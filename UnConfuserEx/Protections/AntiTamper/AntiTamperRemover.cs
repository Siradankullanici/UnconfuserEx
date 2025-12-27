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
                Logger.Error("Failed to find encrypted section even with fallback!");
                return false;
            }
            Logger.Debug($"Using encrypted section: {Encoding.UTF8.GetString(encryptedSection.Name)} (Chars: {encryptedSection.Characteristics:X8})");

            uint[]? initialKeys = GetInitialKeys();
            if (initialKeys == null)
            {
                Logger.Error("Failed to find initial keys in decrypt method");
                return false;
            }
            Logger.Debug($"Found initial decryption keys: {initialKeys[0]:X8}, {initialKeys[1]:X8}, {initialKeys[2]:X8}, {initialKeys[3]:X8}");

            (DeriverType? deriverType, List<Instruction>? derivation) = GetDeriverTypeAndDerivation();
            if (deriverType == null)
            {
                // Fallback to Normal if detection failed but logic seems okay
                deriverType = DeriverType.Normal;
            }
            Logger.Debug($"Initial deriver type detected as {deriverType}");
            
            // For RacGuard variants, Normal is usually the correct choice if the math is inlined.
            // We'll stick with Normal for now unless Dynamic is explicitly required and valid.
            if (deriverType == DeriverType.Dynamic && (derivation == null || derivation.Count < 5))
            {
                 deriverType = DeriverType.Normal;
            }

            (uint[] dst, uint[] src) = PrepareKeyArrays(module, encryptedSection, initialKeys);

            IKeyDeriver deriver;
            if (deriverType == DeriverType.Dynamic && derivation != null && derivation.Count > 0)
            {
                deriver = new DynamicDeriver(derivation);
                Logger.Info("Using DynamicDeriver with captured instructions");
            }
            else
            {
                deriver = new NormalDeriver();
                Logger.Info("Using NormalDeriver");
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
                // Pattern 3: ldloc <g>; ldloc <h>; bxx (where one might be the hash)
                // This is risky, but let's log what we see.
                for (int i = 0; i < instrs.Count - 5; i++)
                {
                     if (instrs[i].IsLdcI4() && instrs[i+1].IsStloc()) {
                         Logger.Debug($"Seen constant at {i}: {instrs[i].GetLdcI4Value():X8}");
                     }
                }
            }
            
            IList<ImageSectionHeader> sections = module.Metadata.PEImage.ImageSectionHeaders;
            int sectionIdx = 0;
            
            // Collect all candidate sections
            var candidates = new List<ImageSectionHeader>();
            
            foreach (var section in sections)
            {
                var sectionName = section.Name;
                uint n1 = (uint)sectionName[0] | (uint)sectionName[1] << 8 | (uint)sectionName[2] << 16 | (uint)sectionName[3] << 24;
                uint n2 = (uint)sectionName[4] | (uint)sectionName[5] << 8 | (uint)sectionName[6] << 16 | (uint)sectionName[7] << 24;
                uint sectionHash = n1 * n2;

                uint characts = (uint)section.Characteristics;

                // Normal match logic
                if (name != -1 && (uint)name == sectionHash)
                {
                    Logger.Info($"Found encrypted section by hash match: Section {sectionIdx} ({sectionHash:X8})");
                    return section;
                }

                // Hardcoded fallback for RacGuard variant: section name "16 4D 71 1F 6D 5E 44 68"
                if (n1 == 0x1F714D16 && n2 == 0x68445E6D)
                {
                    Logger.Info($"Found RacGuard-specific encrypted section: Section {sectionIdx}");
                    return section;
                }

                // Potential candidate (high characteristics and typically contains code/data)
                if (characts == 0xE0000040)
                {
                     candidates.Add(section);
                }
                
                sectionIdx++;
            }

            if (candidates.Count > 0)
            {
                 // Usually the first section with 0xE0000040 is the one for AntiTamper
                 var candidate = candidates.First();
                 Logger.Info($"No hash match (TargetHash: {name:X8}). Choosing candidate by characteristics: Section {sections.IndexOf(candidate)} (Chars: {candidate.Characteristics:X8})");
                 return candidate;
            }

            if (name != -1)
                Logger.Error($"Failed to find section with hash {name:X8}");
            else
                Logger.Error("Failed to find any candidate encrypted section.");
                
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
                    
                    // Initial keys are typically large random-looking numbers
                    if (keys[0] > 0x1000 || keys[1] > 0x1000)
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
            // Look for the start of the key derivation loop: 
            // Often starts with a set of stlocs for the keys, then a block of math.
            // We'll look for the math sequence: xor, add, mul (seen in IL)
            for (int i = 0; i < instrs.Count - 10; i++)
            {
                if (instrs[i].OpCode == OpCodes.Xor && instrs[i + 2].OpCode == OpCodes.Add && instrs[i + 5].OpCode == OpCodes.Mul)
                {
                    // Back up to find the start of the block (usually a ldloc before xor)
                    firstInstr = i - 8; 
                    if (firstInstr < 0) firstInstr = 0;
                    break;
                }
            }

            if (firstInstr == -1)
            {
                // Look for common math markers in the loop
                for (int i = 0; i < instrs.Count - 5; i++)
                {
                    if (instrs[i].OpCode == OpCodes.Xor && instrs[i+1].OpCode.Code == Code.Ldloc_S)
                    {
                         // Found a math block, likely Normal deriver variant
                         return (DeriverType.Normal, null);
                    }
                }
                return (null, null);
            }

            var lastInstr = -1;
            for (int i = firstInstr; i < instrs.Count - 1; i++)
            {
                if (instrs[i].OpCode == OpCodes.Blt_S || instrs[i].OpCode == OpCodes.Blt || instrs[i].OpCode == OpCodes.Ret)
                {
                    lastInstr = i - 1;
                    break;
                }
            }

            if (lastInstr == -1 || lastInstr <= firstInstr)
            {
                return (null, null);
            }

            List<Instruction> derivation = new();
            for (int i = firstInstr; i <= lastInstr; i++)
            {
                derivation.Add(instrs[i]);
            }

            Logger.Info($"Detected dynamic deriver with {derivation.Count} instructions");
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

            int callIdx = 0;
            foreach (var instr in cctor.Body.Instructions)
            {
                if (instr.OpCode != OpCodes.Call)
                    continue;

                if (instr.Operand is MethodDef method && method.HasBody)
                {
                    Logger.Info($"Auditing method call {callIdx++}: {method.FullName} ({method.Body.Instructions.Count} instrs)");
                    
                    // Specific AntiTamper heuristic: 
                    // Usually contains many numeric instructions, loops, and bitwise ops.
                    var instrs = method.Body.Instructions;
                    if (instrs.Count > 100)
                    {
                         // Potential candidate!
                         Logger.Info($"Candidate found: {method.FullName} has {instrs.Count} instructions. Assuming this is the decrypt method.");
                         return method;
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
                var val = (uint)name1 * (uint)name2;

                if (section.PointerToRawData == encryptedSection.PointerToRawData && section.VirtualAddress == encryptedSection.VirtualAddress)
                {
                    continue;
                }
                if (val != 0)
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

            try
            {
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
                Logger.Info("AntiTamper protection removed successfully");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to load decrypted module: {ex.Message}");
                return false;
            }
        }
    }
}
