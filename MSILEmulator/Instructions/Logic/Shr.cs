using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSILEmulator.Instructions.Logic
{
    internal class Shr
    {
        public static void Emulate(Context ctx)
        {
            dynamic shift = ctx.Stack.Pop();
            dynamic val = ctx.Stack.Pop();

            ctx.Stack.Push(val >> shift);
        }
    }
}
