using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MSILEmulator;

namespace UnConfuserEx.Protections.AntiTamper
{
    internal class DynamicDeriver : IKeyDeriver
    {
        private IList<Instruction> derivation;

        public DynamicDeriver(IList<Instruction> derivation)
        {
            this.derivation = derivation;
        }

        public uint[] DeriveKey(uint[] dst, uint[] src)
        {
            SortedSet<int> arrays = new();
            for (int i = 0; i < derivation.Count - 5; i++)
            {
                // Pattern for ldelem: ldloc <arr>; ldc.i4 <idx>; ldelem.u4
                if (derivation[i].IsLdloc()
                    && derivation[i + 2].OpCode == OpCodes.Ldelem_U4)
                {
                    arrays.Add(((Local)derivation[i].Operand).Index);
                }
                // Pattern for ldind (pointer): ldloc <ptr>; ldind.u4
                else if (derivation[i].IsLdloc() && derivation[i+1].OpCode == OpCodes.Ldind_U4)
                {
                    arrays.Add(((Local)derivation[i].Operand).Index);
                }
            }
            int[] arrayIndices = arrays.ToArray();
            
            // In some versions, there might be more locals involved (like initial keys)
            // but we only care about the ones being used as arrays/pointers for dst/src
            if (arrayIndices.Length < 2)
            {
                // If we can't find them, it might be the Normal deriver logic
                // we'll just return and let it fail gracefully or let caller handle it
                return dst; 
            }

            var ilMethod = new ILMethod(derivation);

            ilMethod.SetLocal(arrayIndices[0], dst);
            ilMethod.SetLocal(arrayIndices[1], src);

            ilMethod.Emulate();

            return dst;
        }

    }
}
