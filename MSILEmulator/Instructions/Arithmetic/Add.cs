using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSILEmulator.Instructions.Arithmetic
{
    internal class Add
    {
        public static void Emulate(Context ctx)
        {
            dynamic val2 = ctx.Stack.Pop();
            dynamic val1 = ctx.Stack.Pop();

            ctx.Stack.Push(val1 + val2);
        }
    }
}
