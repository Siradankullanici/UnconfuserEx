using dnlib.DotNet.Emit;

namespace MSILEmulator.Instructions.Branch
{
    internal class Bge
    {
        public static int Emulate(Context ctx, Instruction instr)
        {
            dynamic val2 = ctx.Stack.Pop();
            dynamic val1 = ctx.Stack.Pop();

            if (val1 >= val2)
                return ctx.Offsets[((Instruction)instr.Operand).Offset];

            return -2;
        }

        public static int EmulateUn(Context ctx, Instruction instr)
        {
            var val2 = ctx.Stack.Pop();
            var val1 = ctx.Stack.Pop();

            // Simplified unsigned comparison
            if (val1 is uint u1 && val2 is uint u2)
            {
                if (u1 >= u2) return ctx.Offsets[((Instruction)instr.Operand).Offset];
            }
            else if (val1 is ulong ul1 && val2 is ulong ul2)
            {
                if (ul1 >= ul2) return ctx.Offsets[((Instruction)instr.Operand).Offset];
            }
            else
            {
                dynamic d1 = val1;
                dynamic d2 = val2;
                if (d1 >= d2) return ctx.Offsets[((Instruction)instr.Operand).Offset];
            }

            return -2;
        }
    }
}
