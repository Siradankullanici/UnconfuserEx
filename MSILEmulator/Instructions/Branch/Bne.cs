using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSILEmulator.Instructions.Branch
{
    internal class Bne
    {
        public static int Emulate(Context ctx, Instruction instr)
        {
            object val2 = ctx.Stack.Pop();
            object val1 = ctx.Stack.Pop();

            dynamic d2 = val2;
            dynamic d1 = val1;

            if (d1 != d2)
                return ctx.Offsets[((Instruction)instr.Operand).Offset];

            return -2;
        }
    }
}
