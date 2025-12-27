using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using log4net;
using UnConfuserEx.Protections.ControlFlow;
using de4dot.blocks;
using de4dot.blocks.cflow;

namespace UnConfuserEx.Protections
{
    internal class ControlFlowRemover : IProtection
    {
        static ILog Logger = LogManager.GetLogger("ControlFlow");

        public string Name => "ControlFlow";

        private readonly IList<MethodDef> ObfuscatedMethods = new List<MethodDef>();

        public bool IsPresent(ref ModuleDefMD module)
        {
            /*
             * Go through all of the methods in the module
             * if they all contain a switch then it's present
             */
            foreach (var method in module.GetTypes().SelectMany(t => t.Methods))
            {
                if (IsMethodObfuscated(method))
                {
                    ObfuscatedMethods.Add(method);
                }
            }

            return ObfuscatedMethods.Any();
        }

        public bool Remove(ref ModuleDefMD module)
        {
            int numSolved = 0;
            int numFailed = 0;

            Logger.Debug($"Found {ObfuscatedMethods.Count} obfuscated methods");
            foreach (var method in ObfuscatedMethods)
            {
                try
                {
                    Logger.Debug($"Removing obfuscation from method {method.FullName} (Token: {method.MDToken.Raw:X8})");

                    var deobfuscatedBlocks = DeobfuscateMethod(ref module, method);

                    IList<Instruction> instructions;
                    IList<ExceptionHandler> exceptionHandlers;
                    deobfuscatedBlocks.GetCode(out instructions, out exceptionHandlers);
                    DotNetUtils.RestoreBody(method, instructions, exceptionHandlers);
                    FixStackConsistency(method);

                    if (IsMethodStillObfuscated(method))
                    {
                        // Dump the method body if it fails verification
                        try
                        {
                            var ilDump = new List<string>();
                            ilDump.Add($"Method: {method.FullName}");
                            foreach (var i in method.Body.Instructions)
                                ilDump.Add(i.ToString());
                            System.IO.File.AppendAllLines("failed_control_flow.txt", ilDump);
                            System.IO.File.AppendAllText("failed_control_flow.txt", "\n----------------------------\n");
                        }
                        catch { }

                        throw new Exception("Method still obfuscated after deobfuscation");
                    }

                    numSolved++;
                }
                catch (Exception ex)
                {
                    Logger.Error($"Failed to remove obfuscation for method {method.FullName} (Token: {method.MDToken.Raw:X8}) ({ex.Message})");
                    Logger.Error(ex.StackTrace);

                    try
                    {
                        var ilDump = new List<string>();
                        ilDump.Add($"Method: {method.FullName} (Token: {method.MDToken.Raw:X8})");
                        ilDump.Add($"Error: {ex.Message}");
                        if (method.HasBody)
                        {
                            foreach (var i in method.Body.Instructions)
                                ilDump.Add(i.ToString());
                            if (method.Body.HasExceptionHandlers)
                            {
                                ilDump.Add("Exception Handlers:");
                                foreach (var eh in method.Body.ExceptionHandlers)
                                    ilDump.Add($"{eh.HandlerType}: Try({eh.TryStart} - {eh.TryEnd}), Handler({eh.HandlerStart} - {eh.HandlerEnd}), Filter({eh.FilterStart})");
                            }
                        }
                        System.IO.File.AppendAllLines("failed_control_flow.txt", ilDump);
                        System.IO.File.AppendAllText("failed_control_flow.txt", "\n----------------------------\n");
                    }
                    catch { }

                    numFailed++;
                }
            }

            var msg = $"Removed obfuscation from {numSolved} methods. Failed to remove from {numFailed} methods";
            if (numFailed > 0)
            {
                Logger.Error(msg);
            }
            else
            {
                Logger.Debug(msg);
            }

            return numFailed == 0;
        }

        /// <summary>
        /// Stricter check used after deobfuscation - only detects core dispatcher patterns
        /// </summary>
        public static bool IsMethodStillObfuscated(MethodDef method)
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0)
                return false;

            var instrs = method.Body.Instructions;
            
            // Only check for concrete dispatcher patterns:
            // 1. Switch-based dispatcher
            if (IsSwitchObfuscation(instrs.ToList()))
                return true;
            
            // 2. If-chain dispatcher: ldloc; ldc.i4; ceq; brfalse/brtrue (needs > 15 occurrences)
            int ifChainMatch = 0;
            for (int i = 0; i < instrs.Count - 4; i++)
            {
                if (instrs[i].IsLdloc() && instrs[i+1].IsLdcI4() && instrs[i+2].OpCode == OpCodes.Ceq &&
                    (instrs[i+3].OpCode == OpCodes.Brfalse || instrs[i+3].OpCode == OpCodes.Brfalse_S ||
                     instrs[i+3].OpCode == OpCodes.Brtrue || instrs[i+3].OpCode == OpCodes.Brtrue_S))
                {
                    ifChainMatch++;
                }
            }
            // Much higher threshold for post-deobfuscation check
            if (ifChainMatch > 25) return true;
            
            // 3. Bed's Mod dispatcher: ldloc; ldc.i4; mul; ldc.i4; xor; stloc (keep strict check)
            for (int i = 0; i < instrs.Count - 5; i++)
            {
                if (instrs[i].IsLdloc() && instrs[i+1].IsLdcI4() && instrs[i+2].OpCode == OpCodes.Mul &&
                    instrs[i+3].IsLdcI4() && instrs[i+4].OpCode == OpCodes.Xor && instrs[i+5].IsStloc())
                {
                    return true;
                }
            }
            
            return false;
        }

        public static bool IsMethodObfuscated(MethodDef method)
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0)
                return false;


            if (IsSwitchObfuscation(method.Body.Instructions.ToList()))
                return true;

            var instrs = method.Body.Instructions;
            
            // Exclude methods with significant pointer operations (ldind/stind) - these are typically
            // low-level decryption routines (like AntiTamper) that legitimately have many constants
            // and local variable assignments, but are not control-flow obfuscated.
            int pointerOps = 0;
            int arrayOps = 0;
            bool hasNativeInterop = false;
            
            for (int i = 0; i < instrs.Count; i++)
            {
                var opCode = instrs[i].OpCode;
                
                // Check for pointer operations
                if (opCode == OpCodes.Ldind_I || opCode == OpCodes.Ldind_I1 || opCode == OpCodes.Ldind_I2 ||
                    opCode == OpCodes.Ldind_I4 || opCode == OpCodes.Ldind_I8 || opCode == OpCodes.Ldind_U1 ||
                    opCode == OpCodes.Ldind_U2 || opCode == OpCodes.Ldind_U4 || opCode == OpCodes.Ldind_R4 ||
                    opCode == OpCodes.Ldind_R8 || opCode == OpCodes.Ldind_Ref ||
                    opCode == OpCodes.Stind_I || opCode == OpCodes.Stind_I1 || opCode == OpCodes.Stind_I2 ||
                    opCode == OpCodes.Stind_I4 || opCode == OpCodes.Stind_I8 || opCode == OpCodes.Stind_R4 ||
                    opCode == OpCodes.Stind_R8 || opCode == OpCodes.Stind_Ref)
                {
                    pointerOps++;
                }
                
                // Check for array element access (common in crypto/decryption routines)
                if (opCode == OpCodes.Ldelem || opCode == OpCodes.Ldelem_I || opCode == OpCodes.Ldelem_I1 ||
                    opCode == OpCodes.Ldelem_I2 || opCode == OpCodes.Ldelem_I4 || opCode == OpCodes.Ldelem_I8 ||
                    opCode == OpCodes.Ldelem_U1 || opCode == OpCodes.Ldelem_U2 || opCode == OpCodes.Ldelem_U4 ||
                    opCode == OpCodes.Ldelem_R4 || opCode == OpCodes.Ldelem_R8 || opCode == OpCodes.Ldelem_Ref ||
                    opCode == OpCodes.Stelem || opCode == OpCodes.Stelem_I || opCode == OpCodes.Stelem_I1 ||
                    opCode == OpCodes.Stelem_I2 || opCode == OpCodes.Stelem_I4 || opCode == OpCodes.Stelem_I8 ||
                    opCode == OpCodes.Stelem_R4 || opCode == OpCodes.Stelem_R8 || opCode == OpCodes.Stelem_Ref)
                {
                    arrayOps++;
                }
                
                // Check for native interop calls (Marshal, IntPtr)
                if (opCode == OpCodes.Call || opCode == OpCodes.Callvirt)
                {
                    var operand = instrs[i].Operand;
                    if (operand is IMethod calledMethod)
                    {
                        var declType = calledMethod.DeclaringType?.FullName ?? "";
                        if (declType.Contains("System.Runtime.InteropServices.Marshal") ||
                            declType.Contains("System.IntPtr") ||
                            declType.Contains("System.UIntPtr"))
                        {
                            hasNativeInterop = true;
                        }
                    }
                }
            }
            
            // If the method has >= 3 pointer operations, it's likely a low-level routine
            if (pointerOps >= 3)
                return false;
            
            // If the method has >= 5 array operations AND native interop calls, it's a crypto routine
            if (arrayOps >= 5 && hasNativeInterop)
                return false;
            
            // If the method has significant array operations (>= 10), likely crypto/decryption
            if (arrayOps >= 10)
                return false;

            // Heuristic for "opaque predicate" or constant-based dispatcher:
            // Look for a loop where a local variable is compared against a constant 
            // and then modified by additions/subtractions of other constants.
            int constantOps = 0;
            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].IsLdcI4())
                {
                    // If we see many constant additions/subtractions in a loop-like structure
                    if (i + 1 < instrs.Count && (instrs[i+1].OpCode == OpCodes.Add || instrs[i+1].OpCode == OpCodes.Sub))
                    {
                        constantOps++;
                    }
                }
            }

            // If we have many numeric obfuscation artifacts (> 5), consider it obfuscated
            if (constantOps > 5) return true;

            // Detection for if-chain dispatcher:
            // ldloc <v>; ldc.i4 <c>; ceq; brfalse/brtrue
            int ifChainMatch = 0;
            for (int i = 0; i < instrs.Count - 4; i++)
            {
                if (instrs[i].IsLdloc() && instrs[i+1].IsLdcI4() && instrs[i+2].OpCode == OpCodes.Ceq &&
                    (instrs[i+3].OpCode == OpCodes.Brfalse || instrs[i+3].OpCode == OpCodes.Brfalse_S ||
                     instrs[i+3].OpCode == OpCodes.Brtrue || instrs[i+3].OpCode == OpCodes.Brtrue_S))
                {
                    ifChainMatch++;
                }
            }
            if (ifChainMatch > 10) return true;

            // Extra check for Bed's Mod state update pattern:
            // ldc.i4 <c>; stloc <v>;
            int stateUpdates = 0;
            for (int i = 0; i < instrs.Count - 2; i++)
            {
                if (instrs[i].IsLdcI4() && instrs[i+1].IsStloc())
                {
                    stateUpdates++;
                }
            }
            if (stateUpdates > 15) return true;

            // Extra check for Bed's Mod specific pattern: 
            // ldloc <v>; ldc.i4 <c>; mul; ldc.i4 <c2>; xor; stloc <v>;
            for (int i = 0; i < instrs.Count - 5; i++)
            {
                if (instrs[i].IsLdloc() && instrs[i+1].IsLdcI4() && instrs[i+2].OpCode == OpCodes.Mul &&
                    instrs[i+3].IsLdcI4() && instrs[i+4].OpCode == OpCodes.Xor && instrs[i+5].IsStloc())
                {
                    return true;
                }
            }

            return false;
        }

        public static bool IsSwitchObfuscation(List<Instruction> instrs)
        {
            if (instrs.Count < 3)
            {
                return false;
            }

            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Switch
                    && instrs[i - 1].OpCode == OpCodes.Rem_Un
                    && instrs[i - 2].IsLdcI4()
                    && instrs[i].Operand is Instruction[] cases
                    && cases.Length == instrs[i - 2].GetLdcI4Value())
                {
                    return true;
                }
            }
            return false;
        }

        public static Blocks DeobfuscateMethod(ref ModuleDefMD module, MethodDef method)
        {
            var deobfuscator = new BlocksCflowDeobfuscator();
            var blocks = new Blocks(method);
            blocks.RemoveDeadBlocks();
            blocks.RepartitionBlocks();
            blocks.UpdateBlocks();

            // COMMENTED OUT: We don't want to optimize branches BEFORE the deobfuscator runs
            // as it can change the patterns that SwitchDeobfuscator looks for.
            // blocks.Method.Body.SimplifyBranches();
            // blocks.Method.Body.OptimizeBranches();

            deobfuscator.Initialize(blocks);
            deobfuscator.Add(new SwitchDeobfuscator(module));
            deobfuscator.Add(new IfChainDeobfuscator());
            deobfuscator.Deobfuscate();
            blocks.RemoveDeadBlocks();

            blocks.RepartitionBlocks();

            return blocks;
        }

        private static void FixStackConsistency(MethodDef method)
        {
            if (!method.HasBody) return;

            var instructions = method.Body.Instructions;
            if (instructions.Count == 0) return;
            var entry = instructions[0];

            // Identify all branch targets to help find basic block boundaries
            var targets = new HashSet<Instruction>();
            foreach (var instr in instructions)
            {
                if (instr.Operand is Instruction t) targets.Add(t);
                else if (instr.Operand is IList<Instruction> ts)
                {
                    foreach (var t2 in ts) if (t2 != null) targets.Add(t2);
                }
            }

            for (int i = 0; i < instructions.Count; i++)
            {
                var instr = instructions[i];
                if ((instr.OpCode == OpCodes.Br || instr.OpCode == OpCodes.Br_S) && instr.Operand == entry)
                {
                    // Find basic block start for this junk jump
                    int blockStart = i;
                    while (blockStart > 0)
                    {
                        var prev = instructions[blockStart - 1];
                        if (prev.OpCode.FlowControl == FlowControl.Branch ||
                            prev.OpCode.FlowControl == FlowControl.Cond_Branch ||
                            prev.OpCode.FlowControl == FlowControl.Return ||
                            prev.OpCode.FlowControl == FlowControl.Throw ||
                            targets.Contains(instructions[blockStart]))
                        {
                            break;
                        }
                        blockStart--;
                    }

                    // Calculate stack height from blockStart to the jump
                    int height = 0;
                    for (int j = blockStart; j < i; j++)
                    {
                        instructions[j].UpdateStack(ref height);
                        if (height < 0) height = 0;
                    }

                    // Insert enough pops to clear the stack before jumping back to entry
                    if (height > 0)
                    {
                        for (int k = 0; k < height; k++)
                        {
                            instructions.Insert(i, Instruction.Create(OpCodes.Pop));
                        }
                        i += height;
                    }
                }
            }
        }
    }
}
