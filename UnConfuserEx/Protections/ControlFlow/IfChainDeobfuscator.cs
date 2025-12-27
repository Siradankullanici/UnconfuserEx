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
            // Scan for any stloc pattern in the block
            for (int i = 0; i < block.Instructions.Count; i++)
            {
                var stloc = block.Instructions[i];
                if (stloc.IsStloc())
                {
                    var local = Instr.GetLocalVar(blocks.Locals, stloc);
                    if (local == null) continue;

                    // Try to resolve from the next block or instruction
                    Block startResolve = null;
                    int numToRemove = 0;

                    if (i == block.Instructions.Count - 1)
                    {
                        // stloc is the last instruction, resolve from fallthrough
                        startResolve = block.FallThrough;
                        numToRemove = 1;
                    }
                    else if (i + 1 == block.Instructions.Count - 1 && block.Instructions[i + 1].IsBr())
                    {
                        // stloc followed by br
                        startResolve = block.Targets[0];
                        numToRemove = 2;
                    }
                    else
                    {
                        // Middle of block. We treat the rest of the block as a virtual start if possible,
                        // but for now let's only handle ends of blocks as it's safer.
                        continue;
                    }

                    if (startResolve != null)
                    {
                        // For stloc, we need the value. If the previous instruction was ldc, we have it.
                        // If not, we can try to use the emulator to find the value at this point.
                        emulator.Initialize(blocks.Method);
                        // We need to emulate up to this point to know the value being stored.
                        foreach (var instr in block.Instructions.Take(i + 1))
                        {
                            emulator.Emulate(instr.Instruction);
                        }

                        var valueV = emulator.GetLocal(local);
                        if (valueV is Int32Value i32 && i32.AllBitsValid())
                        {
                            var target = Resolve(startResolve, local, i32.Value);
                            if (target != null && target != startResolve)
                            {
                                Logger.Debug($"Method {blocks.Method.Name}: Resolved state {i32.Value} (Local {local}) to target {target}");
                                block.ReplaceLastInstrsWithBranch(numToRemove, target);
                                return true;
                            }
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
            if (block.Instructions.Count > 100) return false;
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
