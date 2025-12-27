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
            if (block.Instructions.Count < 2) return false;

            Local local = null;
            Value startValue = null;
            Block startResolve = null;
            int numToRemove = 0;

            var last = block.Instructions.Last();
            var secondLast = block.Instructions[block.Instructions.Count - 2];

            // Standard Pattern: ldc <v>; stloc <local>; (at end of block)
            if (secondLast.IsLdcI4() && last.IsStloc())
            {
                local = Instr.GetLocalVar(blocks.Locals, last);
                if (local != null) {
                    startValue = new Int32Value(secondLast.GetLdcI4Value());
                    startResolve = block.FallThrough;
                    numToRemove = 2;
                }
            }
            // Standard Pattern with Branch: ldc <v>; stloc <local>; br <target>;
            else if (block.Instructions.Count >= 3)
            {
                var thirdLast = block.Instructions[block.Instructions.Count - 3];
                if (thirdLast.IsLdcI4() && secondLast.IsStloc() && last.IsBr())
                {
                    local = Instr.GetLocalVar(blocks.Locals, secondLast);
                    if (local != null) {
                        startValue = new Int32Value(thirdLast.GetLdcI4Value());
                        startResolve = block.Targets[0];
                        numToRemove = 3;
                    }
                }
            }

            // Complex Arithmetic Pattern: ldloc <local>; ldc <v>; mul; ldc <v2>; xor; stloc <local>;
            if (local == null && block.Instructions.Count >= 6) {
                int count = block.Instructions.Count;
                var i5 = block.Instructions[count - 1]; // stloc
                var i4 = block.Instructions[count - 2]; // xor
                var i3 = block.Instructions[count - 3]; // ldc
                var i2 = block.Instructions[count - 4]; // mul
                var i1 = block.Instructions[count - 5]; // ldc
                var i0 = block.Instructions[count - 6]; // ldloc

                if (i5.IsStloc() && i4.OpCode == OpCodes.Xor && i3.IsLdcI4() && i2.OpCode == OpCodes.Mul && i1.IsLdcI4() && i0.IsLdloc()) {
                    var l5 = Instr.GetLocalVar(blocks.Locals, i5);
                    var l0 = Instr.GetLocalVar(blocks.Locals, i0);
                    if (l5 != null && l5 == l0) {
                        local = l5;
                        // For complex patterns, we emulation the initial block once to get the start value
                        emulator.Initialize(blocks.Method);
                        // We need the OLD value of the local to solve the new one.
                        // But wait! If this is a state update, we usually already known the state.
                        // Actually, resolving based on an expression is hard if we don't know the input.
                        // Bed's mod usually uses simple constants for the FIRST state set.
                    }
                }
            }

            if (local != null && startResolve != null && startValue != null)
            {
                var target = Resolve(startResolve, local, (startValue as Int32Value).Value);

                if (target != null && target != startResolve)
                {
                    Logger.Debug($"Method {blocks.Method.Name}: Resolved state {startValue} (Local {local}) to target {target}");
                    block.ReplaceLastInstrsWithBranch(numToRemove, target);
                    return true;
                }
            }

            return false;
        }

        private Block Resolve(Block startBlock, Local local, int value)
        {
            Block current = startBlock;
            visited.Clear();
            
            // Initialize emulator once for the resolution chain
            emulator.Initialize(blocks.Method);
            emulator.SetLocal(local, new Int32Value(value));

            while (current != null && visited.Add(current))
            {
                if (!IsDispatcher(current, local))
                {
                    return current;
                }

                if (current.Instructions.Count == 0)
                {
                    current = current.FallThrough;
                    continue;
                }

                // Clear stack before emulating a dispatcher block
                emulator.ClearStack();

                // Emulate all instructions except the last branch
                for (int i = 0; i < current.Instructions.Count - 1; i++)
                {
                    emulator.Emulate(current.Instructions[i].Instruction);
                }

                // Emulate the branch instruction
                branchTaken = false;
                if (!branchEmulator.Emulate(current.LastInstr.Instruction))
                {
                    return current;
                }

                // Follow the branch taken/not taken
                Block next;
                if (branchTaken)
                {
                    if (current.Targets != null && current.Targets.Count > 0)
                        next = current.Targets[0];
                    else
                        return current;
                }
                else
                {
                    next = current.FallThrough;
                }
                
                current = next;

                // Update the state variable if the block modified it
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
            if (block.Instructions.Count > 40) return false;
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
