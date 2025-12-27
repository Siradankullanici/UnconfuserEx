using System;

namespace MSILEmulator.Instructions.Logic
{
    internal class Ceq
    {
        public static void Emulate(Context ctx)
        {
            dynamic val2 = ctx.Stack.Pop();
            dynamic val1 = ctx.Stack.Pop();

            ctx.Stack.Push(val1 == val2 ? 1 : 0);
        }
    }
}
