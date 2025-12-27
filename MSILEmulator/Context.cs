using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSILEmulator
{
    public class Context
    {
        public Dictionary<int, object> Args = new();
        public Dictionary<int, object> Locals = new();
        public Dictionary<uint, int> Offsets = new();
        public Stack<object> Stack = new();
        public object? LastStoredValue;

        public Context(IList<Instruction> instructions)
        {
            for (int i = 0; i < instructions.Count; i++)
            {
                Offsets[instructions[i].Offset] = i;
            }
        }
    }
}
