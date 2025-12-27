using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using SRE = System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
using UnConfuserEx.Protections;
using System.IO;
using UnConfuserEx.Protections.AntiTamper;
using log4net;
using de4dot.blocks;

namespace UnConfuserEx.Protections
{
    internal class AntiTamperRemover : IProtection
    {
        static ILog Logger = LogManager.GetLogger("AntiTamper");

        private enum DeriverType
        { 
            Normal,
            Dynamic
        }

        MethodDef? decryptMethod;
        IList<Instruction>? decryptInstructions;

        string IProtection.Name => "AntiTamper";

        public bool IsPresent(ref ModuleDefMD module)
        {
            decryptMethod = GetDecryptMethod(module);

            return decryptMethod != null;
        }

        public bool Remove(ref ModuleDefMD module)
        {
            if (decryptMethod == null)
            {
                Logger.Error("decryptMethod is null in Remove!");
                return false;
            }

            if (decryptMethod.Body == null)
            {
                Logger.Error("decryptMethod.Body is null in Remove!");
                return false;
            }

            if (ControlFlowRemover.IsMethodObfuscated(decryptMethod!))
            {
                Logger.Debug("Detected that the decrypt method is obfuscated, attempting to deobfuscate");
                try
                {
                    var deobfuscatedBlocks = ControlFlowRemover.DeobfuscateMethod(ref module, decryptMethod!);

                    IList<ExceptionHandler> exceptionHandlers;
                    deobfuscatedBlocks.GetCode(out decryptInstructions, out exceptionHandlers);
                }
                catch (Exception ex)
                {
                    Logger.Error("Failed to remove obfuscation from the decrypt method");
                    Logger.Error(ex.StackTrace);
                    return false;
                }
            }
            else
            {
                decryptInstructions = decryptMethod!.Body.Instructions;
            }
            Logger.Info($"Decrypt method has {decryptInstructions.Count} instructions");

            ImageSectionHeader? encryptedSection = GetEncryptedSection(module);
            if (encryptedSection == null)
            {
                Logger.Error("Failed to find encrypted section");
                return false;
            }
            Logger.Debug($"Found encrypted data in section {Encoding.UTF8.GetString(encryptedSection.Name)}");

            uint[]? initialKeys = GetInitialKeys();
            if (initialKeys == null)
            {
                Logger.Error("Failed to find initial keys in decrypt method");
                return false;
            }
            Logger.Debug($"Found initial decryption keys");

            (DeriverType? deriverType, List<Instruction>? derivation) = GetDeriverTypeAndDerivation();
            if (deriverType == null || derivation == null)
            {
                Logger.Error("[-] Failed to get the key deriver type and it's derivation");
                return false;
            }
            Logger.Debug($"Detected deriver type is {deriverType}");

            (uint[] dst, uint[] src) = PrepareKeyArrays(module, encryptedSection, initialKeys);

            IKeyDeriver deriver;
            if (deriverType == DeriverType.Normal)
            {
                deriver = new NormalDeriver();
            }
            else
            {
                deriver = new DynamicDeriver(derivation);
            }

            Logger.Debug($"Deriving decryption key");
            uint[] key = deriver.DeriveKey(dst, src);

            Logger.Debug($"Decrypting method bodies");
            return DecryptSection(ref module, key, encryptedSection);
        }

        private ImageSectionHeader? GetEncryptedSection(ModuleDefMD module)
        {
            int name = -1;
            
            var instrs = decryptInstructions!;
            for (int i = 0; i < instrs.Count - 2; i++)
            {
                if (instrs[i].IsLdloc()
                    && instrs[i + 1].IsLdcI4()
                    && instrs[i + 2].OpCode.FlowControl == FlowControl.Cond_Branch)
                {
                    name = instrs[i + 1].GetLdcI4Value();
                    Logger.Info($"Found potential section hash: {name:X8} at instruction {i}");
                    break;
                }
            }
            
            if (name == -1)
            {
                // Try another pattern: maybe ldc.i4 <hash>; ldloc <g>; bxx
                for (int i = 0; i < instrs.Count - 2; i++)
                {
                    if (instrs[i].IsLdcI4()
                        && instrs[i + 1].IsLdloc()
                        && instrs[i + 2].OpCode.FlowControl == FlowControl.Cond_Branch)
                    {
                        name = instrs[i].GetLdcI4Value();
                        Logger.Info($"Found potential section hash (alternative pattern): {name:X8} at instruction {i}");
                        break;
                    }
                }
            }
            
            if (name == -1)
            {
                return null;
            }

            IList<ImageSectionHeader> sections = module.Metadata.PEImage.ImageSectionHeaders;
            int sectionIdx = 0;
            foreach (var section in sections)
            {
                var sectionName = section.Name;
                string hexName = string.Join(" ", sectionName.Select(b => b.ToString("X2")));
                uint n1 = (uint)sectionName[0] | (uint)sectionName[1] << 8 | (uint)sectionName[2] << 16 | (uint)sectionName[3] << 24;
                uint n2 = (uint)sectionName[4] | (uint)sectionName[5] << 8 | (uint)sectionName[6] << 16 | (uint)sectionName[7] << 24;
                uint sectionHash = n1 * n2;

                uint characts = (uint)section.Characteristics;
                Logger.Debug($"Section {sectionIdx}: {hexName} - Hash: {sectionHash:X8} - Characteristics: {characts:X8}");

                if ((uint)name == sectionHash)
                {
                    Logger.Info($"Found encrypted section by hash match: Section {sectionIdx}");
                    return section;
                }

                // Fallback for Bed's Mod
                if (characts == 0xE0000040)
                {
                    Logger.Info($"Found potential encrypted section by characteristics (0xE0000040): Section {sectionIdx}");
                    return section;
                }
                
                sectionIdx++;
            }
            Logger.Error($"Failed to find section with hash {name:X8}");
            return null;
        }

        private uint[]? GetInitialKeys()
        {
            var instrs = decryptInstructions!;
            for (int i = 0; i < instrs.Count - 8; i++)
            {
                if (instrs[i].IsLdcI4() && instrs[i + 2].IsLdcI4() && instrs[i + 4].IsLdcI4() && instrs[i + 6].IsLdcI4())
                {
                    uint[] keys = new uint[4];
                    keys[0] = (uint)instrs[i].GetLdcI4Value();
                    keys[1] = (uint)instrs[i + 2].GetLdcI4Value();
                    keys[2] = (uint)instrs[i + 4].GetLdcI4Value();
                    keys[3] = (uint)instrs[i + 6].GetLdcI4Value();
                    
                    if (keys[0] > 0x1000 && keys[1] > 0x1000 && keys[2] > 0x1000 && keys[3] > 0x1000)
                    {
                        Logger.Info($"Found initial keys: {keys[0]:X8}, {keys[1]:X8}, {keys[2]:X8}, {keys[3]:X8}");
                        return keys;
                    }
                }
            }

            return null;
        }

        private (DeriverType?, List<Instruction>?) GetDeriverTypeAndDerivation()
        {
            var instrs = decryptInstructions!;

            var firstInstr = -1;
            for (int i = 0; i < instrs.Count - 1; i++)
            {
                if (instrs[i].IsLdcI4() && instrs[i].GetLdcI4Value() == 16
                    && (instrs[i + 1].OpCode.Code == Code.Blt_S || instrs[i + 1].OpCode.Code == Code.Blt))
                {
                    firstInstr = i + 2;
                    break;
                }
            }

            if (firstInstr == -1)
            {
                return (null, null);
            }

            var lastInstr = -1;
            for (int i = firstInstr; i < instrs.Count - 2; i++)
            {
                if (instrs[i].OpCode == OpCodes.Stelem_I4
                    && instrs[i + 1].IsLdcI4() && instrs[i + 1].GetLdcI4Value() == 64
                    && instrs[i + 2].IsStloc())
                {
                    lastInstr = i;
                    break;
                }
            }

            if (lastInstr == -1)
            {
                return (null, null);
            }

            List<Instruction> derivation = new();
            for (int i = 0; i <= (lastInstr - firstInstr); i++)
            {
                derivation.Add(instrs[firstInstr + i]);
            }

            // Normal deriver in Bed's Mod or ConfuserEx is often unrolled to 160 instructions
            // but if it matches the derivation pattern, and DynamicDeriver can handle it, 
            // it's safer to use DynamicDeriver to emulate exactly what's in the DLL.
            return (DeriverType.Dynamic, derivation);
        }

        private static MethodDef? GetDecryptMethod(ModuleDefMD module)
        {
            if (module.GlobalType == null)
            {
                Logger.Error("module.GlobalType is null!");
                return null;
            }
            var cctor = module.GlobalType.FindStaticConstructor();

            if (cctor == null)
            {
                Logger.Debug("No static constructor found in global type");
                return null;
            }

            if (!(cctor.HasBody) || cctor.Body == null || cctor.Body.Instructions.Count == 0)
            {
                Logger.Debug("Static constructor has no body or instructions");
                return null;
            }

            foreach (var instr in cctor.Body.Instructions)
            {
                if (instr.OpCode != OpCodes.Call)
                    continue;

                if (instr.Operand is MethodDef method && method.HasBody)
                {
                    Logger.Debug($"Auditing method {method.FullName} as potential decrypt method");
                    var instrs = method.Body.Instructions;
                    if (instrs == null)
                    {
                        Logger.Warn($"Method {method.FullName} has HasBody=true but Body.Instructions is null!");
                        continue;
                    }
                    for (int i = 0; i < instrs.Count - 2; i++)
                    {
                        if (instrs[i].OpCode == OpCodes.Ldtoken &&
                            instrs[i].Operand == module.GlobalType &&
                            instrs[i + 1].OpCode == OpCodes.Call &&
                            instrs[i + 1].Operand is MemberRef m &&
                            m.Name == "GetTypeFromHandle")
                        {
                            return method;
                        }
                    }
                }
            }

            return null;
        }

        private static (uint[], uint[]) PrepareKeyArrays(ModuleDefMD module, ImageSectionHeader encryptedSection, uint[] initialKeys)
        {
            uint z = initialKeys[0], x = initialKeys[1], c = initialKeys[2], v = initialKeys[3];

            var reader = module.Metadata.PEImage.CreateReader();
            IList<ImageSectionHeader> sections = module.Metadata.PEImage.ImageSectionHeaders;
            foreach (var section in sections)
            {
                var sectionName = section.Name;
                var name1 = sectionName[0] | sectionName[1] << 8 | sectionName[2] << 16 | sectionName[3] << 24;
                var name2 = sectionName[4] | sectionName[5] << 8 | sectionName[6] << 16 | sectionName[7] << 24;
                var val = name1 * name2;

                if (section == encryptedSection)
                {
                    continue;
                }
                else if (val != 0)
                {
                    var size = section.SizeOfRawData >> 2;
                    var loc = section.PointerToRawData;
                    reader.Position = loc;
                    for (int i = 0; i < size; i++)
                    {
                        var t = (z ^ reader.ReadUInt32()) + x + c * v;
                        z = x;
                        x = c;
                        x = v;
                        v = t;
                    }
                }
            }

            uint[] dst = new uint[16], src = new uint[16];
            for (int i = 0; i < 16; i++)
            {
                dst[i] = v;
                src[i] = x;
                z = (x >> 5) | (x << 27);
                x = (c >> 3) | (c << 29);
                c = (v >> 7) | (v << 25);
                v = (z >> 11) | (z << 21);
            }

            return (dst, src);
        }

        private bool DecryptSection(ref ModuleDefMD module, uint[] key, ImageSectionHeader encryptedSection)
        {
            var reader = module.Metadata.PEImage.CreateReader();
            byte[] image = reader.ReadRemainingBytes();

            var size = encryptedSection.SizeOfRawData >> 2;
            var pos = encryptedSection.PointerToRawData;
            reader.Position = pos;
            uint[] result = new uint[size];
            for (uint i = 0; i < size; i++)
            {
                uint data = reader.ReadUInt32();
                result[i] = data ^ key[i & 0xf];
                key[i & 0xf] = (key[i & 0xf] ^ result[i]) + 0x3dbb2819;
            }
            byte[] byteResult = new byte[size << 2];
            Buffer.BlockCopy(result, 0, byteResult, 0, byteResult.Length);

            var stream = new MemoryStream(image)
            {
                Position = pos
            };
            stream.Write(byteResult, 0, byteResult.Length);

            ModuleDefMD newModule = ModuleDefMD.Load(stream);
            
            // Re-find the decrypt method in the new module to remove it
            var newDecryptMethod = GetDecryptMethod(newModule);
            if (newDecryptMethod != null)
            {
                newModule.GlobalType.Methods.Remove(newDecryptMethod);
                
                // Also remove the call to it in the cctor
                var cctor = newModule.GlobalType.FindStaticConstructor();
                if (cctor != null && cctor.HasBody)
                {
                    for (int i = 0; i < cctor.Body.Instructions.Count; i++)
                    {
                        if (cctor.Body.Instructions[i].OpCode == OpCodes.Call &&
                            cctor.Body.Instructions[i].Operand == newDecryptMethod)
                        {
                            cctor.Body.Instructions.RemoveAt(i);
                            break;
                        }
                    }
                }
            }

            module = newModule;
            return true;
        }
    }
}
