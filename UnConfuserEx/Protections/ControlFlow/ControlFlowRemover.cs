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

                    if (IsMethodObfuscated(method))
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
            return true;
        }

        public static bool IsMethodObfuscated(MethodDef method)
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0)
                return false;


            if (IsSwitchObfuscation(method.Body.Instructions.ToList()))
                return true;

            // Heuristic for "opaque predicate" or constant-based dispatcher:
            // Look for a loop where a local variable is compared against a constant 
            // and then modified by additions/subtractions of other constants.
            var instrs = method.Body.Instructions;
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
