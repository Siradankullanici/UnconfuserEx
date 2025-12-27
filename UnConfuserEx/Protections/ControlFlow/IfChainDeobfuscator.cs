using de4dot.blocks;
using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using log4net;
using System;
using System.Collections.Generic;
using System.Linq;

namespace UnConfuserEx.Protections.ControlFlow
{
    internal class IfChainDeobfuscator : BlockDeobfuscator, IBranchHandler
    {
        private static readonly ILog Logger = LogManager.GetLogger("IfChainDeobfuscator");
        private InstructionEmulator emulator = new InstructionEmulator();
        private BranchEmulator branchEmulator;
        private bool branchTaken;
        private HashSet<Block> visited = new HashSet<Block>();

        public IfChainDeobfuscator()
        {
            branchEmulator = new BranchEmulator(emulator, this);
        }

        public void HandleNormal(int stackArgs, bool isTaken)
        {
            branchTaken = isTaken;
        }

        public bool HandleSwitch(Int32Value switchIndex)
        {
            return false;
        }

        protected override bool Deobfuscate(Block block)
        {
            // Scan for any ldc; stloc pattern in the block
            for (int i = 0; i < block.Instructions.Count - 1; i++)
            {
                var ldc = block.Instructions[i];
                var stloc = block.Instructions[i + 1];

                if (ldc.IsLdcI4() && stloc.IsStloc())
                {
                    var local = Instr.GetLocalVar(blocks.Locals, stloc);
                    if (local == null) continue;

                    var value = ldc.GetLdcI4Value();
                    
                    // We need a start block for resolution.
                    // If stloc is the last instruction, it's the fallthrough.
                    // If it's followed by ldc; stloc; br; it's the target.
                    // If it's in the middle, we treat the rest of the block as a virtual start.
                    
                    Block startResolve;
                    int numToRemove;

                    if (i + 1 == block.Instructions.Count - 1)
                    {
                        // Last in block
                        startResolve = block.FallThrough;
                        numToRemove = 2;
                    }
                    else if (i + 2 == block.Instructions.Count - 1 && block.Instructions[i + 2].IsBr())
                    {
                        // stloc followed by br
                        startResolve = block.Targets[0];
                        numToRemove = 3;
                    }
                    else
                    {
                        // Middle of block. This is complex. For now, we only resolve if it's the end of a block pattern.
                        continue;
                    }

                    if (startResolve != null)
                    {
                        var target = Resolve(startResolve, local, value);
                        if (target != null && target != startResolve)
                        {
                            Logger.Debug($"Method {blocks.Method.Name}: Resolved state {value} (Local {local}) to target {target}");
                            block.ReplaceLastInstrsWithBranch(numToRemove, target);
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private Block Resolve(Block startBlock, Local local, int value)
        {
            Block current = startBlock;
            visited.Clear();
            
            emulator.Initialize(blocks.Method);
            emulator.SetLocal(local, new Int32Value(value));

            while (current != null && visited.Add(current))
            {
                if (!IsDispatcher(current, local))
                    return current;

                if (current.Instructions.Count == 0)
                {
                    current = current.FallThrough;
                    continue;
                }

                emulator.ClearStack();

                for (int i = 0; i < current.Instructions.Count - 1; i++)
                {
                    emulator.Emulate(current.Instructions[i].Instruction);
                }

                branchTaken = false;
                if (!branchEmulator.Emulate(current.LastInstr.Instruction))
                    return current;

                if (branchTaken)
                {
                    if (current.Targets != null && current.Targets.Count > 0)
                        current = current.Targets[0];
                    else
                        return current;
                }
                else
                {
                    current = current.FallThrough;
                }
                
                var newVal = emulator.GetLocal(local);
                if (newVal is Int32Value i32 && i32.AllBitsValid())
                {
                    value = i32.Value;
                }
            }

            return current;
        }

        private bool IsDispatcher(Block block, Local local)
        {
            if (block.Instructions.Count > 50) return false;
            if (block.Instructions.Count == 0) return true;
            
            bool usesLocal = false;
            foreach (var instr in block.Instructions)
            {
                if (instr.OpCode.FlowControl == FlowControl.Call) return false;
                if (instr.OpCode.FlowControl == FlowControl.Throw) return false;
                
                if (instr.IsLdloc() && Instr.GetLocalVar(blocks.Locals, instr) == local)
                    usesLocal = true;
                
                if (instr.IsStloc() && Instr.GetLocalVar(blocks.Locals, instr) != local)
                    return false;
            }

            return usesLocal || block.Instructions.Count <= 2;
        }
    }
}
