using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSILEmulator.Instructions.Logic
{
    internal class Shr_Un
    {
        public static void Emulate(Context ctx)
        {
            int shift = (int)ctx.Stack.Pop();
            uint val = (uint)(int)ctx.Stack.Pop();

            ctx.Stack.Push((int)(val >> shift));
        }
    }
}
