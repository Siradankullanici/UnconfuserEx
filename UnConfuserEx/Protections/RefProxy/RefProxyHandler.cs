using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using MSILEmulator;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using X86Emulator;

namespace UnConfuserEx.Protections.Delegates
{
    internal class RefProxyHandler
    {
        private MethodDef Handler;
        private X86Method? X86Method;
        private MethodDef? EncodingMethod;
        private int[] NameChars = new int[5];
        private int[] Shifts = new int[4];
        
        private ModuleDefMD ModuleDef;
        private Assembly? LoadedAssembly;
        private string? TempAssemblyPath;

        public RefProxyHandler(ModuleDefMD module, MethodDef handler)
        {
            ModuleDef = module;
            Handler = handler;

            var instrs = handler.Body.Instructions;
            var nameCharsFound = 0;
            var shiftsFound = 0;
            File.AppendAllText("refproxy_debug.log", $"[RefProxyHandler] Inspecting Handler Body with {instrs.Count} instructions:{Environment.NewLine}");
            foreach(var ins in instrs)
            {
                File.AppendAllText("refproxy_debug.log", $"  {ins.OpCode} {ins.Operand}{Environment.NewLine}");
            }

            for (int i = 0; i < instrs.Count - 2; i++)
            {
                if (instrs[i].OpCode == OpCodes.Callvirt &&
                    instrs[i].Operand is IMethodDefOrRef md &&
                    md.Name.Contains("get_Name"))
                {
                    if (instrs[i + 1].IsLdcI4() && nameCharsFound < 5)
                        NameChars[nameCharsFound++] = instrs[i + 1].GetLdcI4Value();
                }
                else if (instrs[i].OpCode == OpCodes.Shl)
                {
                    if (i > 0 && instrs[i - 1].IsLdcI4() && shiftsFound < 4)
                        Shifts[shiftsFound++] = instrs[i - 1].GetLdcI4Value();
                }

                if (nameCharsFound == 5 && shiftsFound == 4)
                {
                    break;
                }
            }

            if (nameCharsFound < 5 || shiftsFound < 4)
            {
                System.Console.WriteLine($"[RefProxyHandler] Warning: Incomplete constants found. NameChars: {nameCharsFound}, Shifts: {shiftsFound}");
            }
            else
            {
                 System.Console.WriteLine($"[RefProxyHandler] Constants found. NameChars: [{string.Join(", ", NameChars)}], Shifts: [{string.Join(", ", Shifts)}]");
            }

            foreach (var instr in instrs)
            {
                if (instr.OpCode == OpCodes.Call && instr.Operand is MethodDef md)
                {
                    if (md.IsNative)
                    {
                        System.Console.WriteLine($"[RefProxyHandler] Found Native X86 Method: {md.Name}");
                        X86Method = new X86Method(module, md);
                    }
                    else if (md.DeclaringType.IsGlobalModuleType && md.Parameters.Count == 1 && md.ReturnType.FullName == "System.Int32")
                    {
                        System.Console.WriteLine($"[RefProxyHandler] Found EncodingMethod: {md.Name}");
                        EncodingMethod = md;
                    }
                }
            }
        }

        public static void ValidateTypeSig(TypeSig? sig)
        {
            if (sig == null) throw new Exception("Null TypeSig encountered");
            
            // recursive checks
            if (sig.Next != null) ValidateTypeSig(sig.Next);

            if (sig is GenericInstSig gis)
            {
                ValidateTypeSig(gis.GenericType);
                foreach (var arg in gis.GenericArguments) ValidateTypeSig(arg);
            }
            if (sig is ModifierSig ms) 
            {
                 if (ms.Modifier == null) throw new Exception("ModifierSig.Modifier is null");
                 ValidateTypeSig(ms.Next);
            }
            if (sig is ClassOrValueTypeSig cov)
            {
                if (cov.TypeDefOrRef == null) throw new Exception("ClassOrValueTypeSig.TypeDefOrRef is null");
            }
        }

        private void SanitizeModule()
        {
            // Remove properties, events, fields, and methods with null signatures (corrupted metadata)
            // This allows NativeWrite to succeed.
            
            // First, remove references to orphaned members (which cause "Method not defined" errors)
            RemoveOrphanedReferences();
    
            // Force ILOnly to ensure compatibility and use standard writer
            ModuleDef.Cor20HeaderFlags |= dnlib.DotNet.MD.ComImageFlags.ILOnly;
            ModuleDef.Cor20HeaderFlags &= ~dnlib.DotNet.MD.ComImageFlags.Bit32Required;
            
            // Remove the problematic 'sxQ=' type which contains duplicate nested types
            // This is a known obfuscation pattern that causes dnlib to fail during metadata writing
            var problematicTypes = ModuleDef.Types.Where(t => t.Name == "sxQ=" || t.FullName.Contains("sxQ=")).ToList();
            foreach (var probType in problematicTypes)
            {
                System.Console.WriteLine($"[RefProxyHandler] Removing problematic type {probType.FullName} with duplicate metadata");
                ModuleDef.Types.Remove(probType);
            }
            
            // Remove types with empty or whitespace-only names that cause BadImageFormatException
            var invalidNameTypes = ModuleDef.Types.Where(t => string.IsNullOrWhiteSpace(t.Name)).ToList();
            foreach (var invalidType in invalidNameTypes)
            {
                System.Console.WriteLine($"[RefProxyHandler] Removing top-level type with invalid (empty/whitespace) name");
                ModuleDef.Types.Remove(invalidType);
            }
            
            // Also remove nested types with invalid names
            foreach (var type in ModuleDef.GetTypes().ToList())
            {
                for (int i = type.NestedTypes.Count - 1; i >= 0; i--)
                {
                    var nested = type.NestedTypes[i];
                    if (string.IsNullOrWhiteSpace(nested.Name))
                    {
                        System.Console.WriteLine($"[RefProxyHandler] Removing nested type with invalid name from {type.Name}");
                        type.NestedTypes.RemoveAt(i);
                    }
                }
            }
            
            // Remove orphaned nested types - types marked as nested but with null or missing DeclaringType
            // This can happen when parent types are removed but nested types remain in the metadata
            // Be aggressive: remove ALL nested types to avoid runtime "Enclosing type(s) not found" errors
            foreach (var type in ModuleDef.GetTypes().ToList())
            {
                if (type.NestedTypes.Count > 0)
                {
                    System.Console.WriteLine($"[RefProxyHandler] Removing all {type.NestedTypes.Count} nested types from {type.Name} to avoid orphan issues");
                    type.NestedTypes.Clear();
                }
            }
            
            // Remove duplicate types (same full name) by renaming duplicates
            var typesByName = new Dictionary<string, int>();
            foreach (var type in ModuleDef.GetTypes().ToList())
            {
                string key = type.FullName;
                if (typesByName.TryGetValue(key, out int count))
                {
                    // Rename the duplicate type to make it unique
                    typesByName[key] = count + 1;
                    type.Name = type.Name + "_dup" + count;
                    System.Console.WriteLine($"[RefProxyHandler] Renaming duplicate type to {type.Name}");
                }
                else
                {
                    typesByName[key] = 1;
                }
            }
            
            // Remove duplicate nested types from each type
            foreach (var type in ModuleDef.GetTypes().ToList())
            {
                if (type.NestedTypes.Count <= 1) continue;
                
                var seenNestedNames = new HashSet<string>();
                for (int i = type.NestedTypes.Count - 1; i >= 0; i--)
                {
                    var nested = type.NestedTypes[i];
                    string nestedKey = nested.FullName;
                    if (!seenNestedNames.Add(nestedKey))
                    {
                        System.Console.WriteLine($"[RefProxyHandler] Removing duplicate nested type {nested.Name} from {type.Name}");
                        type.NestedTypes.RemoveAt(i);
                    }
                }
            }

            // Global method deduplication across all types
            var globalMethodSigs = new Dictionary<string, MethodDef>();
            foreach (var type in ModuleDef.GetTypes().Distinct().ToList())
            {
                for (int i = type.Methods.Count - 1; i >= 0; i--)
                {
                    var method = type.Methods[i];
                    string key = method.FullName;
                    if (globalMethodSigs.TryGetValue(key, out var existing))
                    {
                        // If it's the same object, remove reference
                        // If it's a different object with the same signature, remove it
                        System.Console.WriteLine($"[RefProxyHandler] Removing globally duplicate method {method.Name} from {type.Name} (already in {existing.DeclaringType?.Name})");
                        type.Methods.RemoveAt(i);
                    }
                    else
                    {
                        globalMethodSigs[key] = method;
                    }
                }
            }

            // TypeSpecs - Sanitize explicitly to prevent NativeWrite crash (TypeSig is null)
            if (ModuleDef.TablesStream != null)
            {
                uint typeSpecRows = ModuleDef.TablesStream.TypeSpecTable.Rows;
                for (uint rid = 1; rid <= typeSpecRows; rid++)
                {
                    try
                    {
                        var ts = ModuleDef.ResolveTypeSpec(rid);
                        if (ts == null) continue;

                        bool broken = false;
                        try 
                        { 
                            if (ts.TypeSig == null) broken = true;
                            else ValidateTypeSig(ts.TypeSig);
                        } 
                        catch { broken = true; }

                        if (broken)
                        {
                            System.Console.WriteLine($"[RefProxyHandler] Repairing broken TypeSpec {rid:X} (Token: {0x1B000000 | rid:X}).");
                            ts.TypeSig = ModuleDef.CorLibTypes.Object;
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Console.WriteLine($"[RefProxyHandler] Failed to resolve/repair TypeSpec {rid:X}: {ex.Message}");
                    }
                }
            }

            foreach (var type in ModuleDef.GetTypes().Distinct())
            {
                // Properties - Removal is usually safe
                for (int i = type.Properties.Count - 1; i >= 0; i--)
                {
                    try
                    {
                        var prop = type.Properties[i];
                        if (prop.PropertySig == null) throw new Exception("Null PropertySig");
                        
                        ValidateTypeSig(prop.PropertySig.RetType);
                        foreach (var param in prop.PropertySig.Params)
                            ValidateTypeSig(param);
                    }
                    catch
                    {
                        System.Console.WriteLine($"[RefProxyHandler] Removing corrupted property {type.Properties[i].Name} from {type.Name}");
                        type.Properties.RemoveAt(i);
                    }
                }
                
                // Events - Removal is usually safe
                for (int i = type.Events.Count - 1; i >= 0; i--)
                {
                    try
                    {
                        var evt = type.Events[i];
                        if (evt.EventType == null) throw new Exception("Null EventType");
                        
                        if (evt.EventType is TypeSpec ts) ValidateTypeSig(ts.TypeSig);
                        // other checks if needed
                    }
                    catch
                    {
                         System.Console.WriteLine($"[RefProxyHandler] Removing corrupted event from {type.Name}");
                         type.Events.RemoveAt(i); 
                    }
                }

                // Fields - Repair instead of remove to prevent token references from breaking
                for (int i = type.Fields.Count - 1; i >= 0; i--)
                {
                    try
                    {
                        var field = type.Fields[i];
                        if (field.FieldSig == null) throw new Exception("Null FieldSig");
                        ValidateTypeSig(field.FieldType);
                    }
                    catch
                    {
                         // System.Console.WriteLine($"[RefProxyHandler] Repairing corrupted field {type.Fields[i].Name} from {type.Name}");
                         type.Fields[i].FieldSig = new FieldSig(type.Module.CorLibTypes.Double);
                    }
                }


                // Methods - Repair instead of remove
                for (int i = type.Methods.Count - 1; i >= 0; i--)
                {
                    try
                    {
                        var method = type.Methods[i];
                        if (method.HasBody) method.Body.KeepOldMaxStack = true;
                        if (method.MethodSig == null) throw new Exception("Null MethodSig");
                        
                        ValidateTypeSig(method.MethodSig.RetType);
                        foreach (var param in method.MethodSig.Params)
                            ValidateTypeSig(param);
                    }
                    catch
                    {
                         var method = type.Methods[i];
                         System.Console.WriteLine($"[RefProxyHandler] Repairing corrupted method {method.Name} from {type.Name}");
                         
                         var conv = CallingConvention.Default;
                         if (!method.IsStatic) conv |= CallingConvention.HasThis;
                         
                         // Reset signature to void()
                         method.MethodSig = new MethodSig(conv, 0, type.Module.CorLibTypes.Void);
                         
                         // Reset body
                         if (method.HasBody)
                         {
                             method.Body = new CilBody();
                             method.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                         }
                    }
                }
                
                // Remove duplicate methods - first by object identity, then by signature
                var seenMethodObjects = new HashSet<MethodDef>();
                var seenMethodSigs = new HashSet<string>();
                for (int i = type.Methods.Count - 1; i >= 0; i--)
                {
                    var method = type.Methods[i];
                    
                    // Check object identity first (same MethodDef object referenced multiple times)
                    if (!seenMethodObjects.Add(method))
                    {
                        System.Console.WriteLine($"[RefProxyHandler] Removing duplicate method object {method.Name} from {type.Name}");
                        type.Methods.RemoveAt(i);
                        continue;
                    }
                    
                    // Check by signature (different objects with same signature)
                    string key = method.FullName;
                    if (!seenMethodSigs.Add(key))
                    {
                        System.Console.WriteLine($"[RefProxyHandler] Removing duplicate method signature {method.Name} from {type.Name}");
                        type.Methods.RemoveAt(i);
                    }
                }
            }
        }

        private void RemoveOrphanedReferences()
        {
             foreach (var type in ModuleDef.GetTypes())
             {
                 foreach (var method in type.Methods)
                 {
                     if (!method.HasBody) continue;
                     
                     var instructions = method.Body.Instructions;
                     for (int i = 0; i < instructions.Count; i++)
                     {
                         var operand = instructions[i].Operand;
                         
                         if (operand is MethodDef md)
                         {
                             bool isOrphaned = false;
                             if (md.DeclaringType == null) isOrphaned = true;
                             else if (!md.DeclaringType.Methods.Contains(md)) isOrphaned = true;
                             
                             if (isOrphaned)
                             {
                                 System.Console.WriteLine($"[RefProxyHandler] Noping instruction in {method.Name} referencing orphaned method {md.Name} (Token: {md.MDToken})");
                                 instructions[i].OpCode = OpCodes.Nop;
                                 instructions[i].Operand = null;
                             }
                         }
                         else if (operand is FieldDef fd)
                         {
                             bool isOrphaned = false;
                             if (fd.DeclaringType == null) isOrphaned = true;
                             else if (!fd.DeclaringType.Fields.Contains(fd)) isOrphaned = true;
                             
                             if (isOrphaned)
                             {
                                 System.Console.WriteLine($"[RefProxyHandler] Noping instruction in {method.Name} referencing orphaned field {fd.Name} (Token: {fd.MDToken})");
                                 instructions[i].OpCode = OpCodes.Nop;
                                 instructions[i].Operand = null;
                             }
                         }
                     }
                 }
             }
        }

        private void EnsureAssemblyLoaded()
        {
            if (LoadedAssembly != null) return;

            try
            {
                SanitizeModule();

                string tempFile = Path.GetTempFileName();
                string ext = ModuleDef.Kind == ModuleKind.Dll ? ".dll" : ".exe";
                TempAssemblyPath = Path.ChangeExtension(tempFile, ext);
                if (File.Exists(tempFile)) File.Delete(tempFile);

                System.Console.WriteLine($"[RefProxyHandler] Saving temporary assembly to {TempAssemblyPath} for dynamic analysis (Tokens NOT preserved)...");

                // First write to memory stream with non-preserving options
                using (var memStream = new MemoryStream())
                {
                    var writerOptions = new ModuleWriterOptions(ModuleDef);
                    writerOptions.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
                    // Use NoThrowInstance to ignore duplicate key errors from obfuscated metadata
                    writerOptions.Logger = DummyLogger.NoThrowInstance;
                    // Write to memory stream first
                    ModuleDef.Write(memStream, writerOptions);
                    memStream.Position = 0;
                    
                    // Now write from the memory stream to the file
                    using (var fileStream = File.Create(TempAssemblyPath))
                    {
                        memStream.CopyTo(fileStream);
                    }
                }

                System.Console.WriteLine("[RefProxyHandler] Loading assembly...");
                LoadedAssembly = Assembly.LoadFrom(TempAssemblyPath);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to load assembly for dynamic analysis: {ex.Message}", ex);
            }
        }

        private MethodInfo? FindMethodInAssembly(MethodDef methodDef)
        {
            var typeFunc = FindTypeInAssembly(methodDef.DeclaringType);
            if (typeFunc == null) return null;

            var methods = typeFunc.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance)
                .Where(m => m.Name == methodDef.Name).ToList();

            return methods.FirstOrDefault(m => m.GetParameters().Length == methodDef.Parameters.Count);
        }

        private FieldInfo? FindFieldInAssembly(FieldDef fieldDef)
        {
            var type = FindTypeInAssembly(fieldDef.DeclaringType);
            if (type == null) return null;

            return type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance)
                       .FirstOrDefault(f => f.Name == fieldDef.Name);
        }

        private Type? FindTypeInAssembly(TypeDef typeDef)
        {
             if (typeDef.IsGlobalModuleType)
             {
                 return LoadedAssembly!.ManifestModule.GetTypes().FirstOrDefault(t => t.Name == "<Module>" || t.Name == typeDef.Name);
             }

             var type = LoadedAssembly!.GetType(typeDef.FullName);
             if (type != null) return type;

             return LoadedAssembly.GetTypes().FirstOrDefault(t => t.FullName == typeDef.FullName || t.Name == typeDef.Name);
        }

        public MDToken GetMethodMDToken(FieldDef field)
        {
            var fieldSig = field.FieldSig.ExtraData;

            int key;
            if (field.FieldType is CModOptSig optSig)
            {
                key = (int)optSig.Modifier.MDToken.Raw;
            }
            else
            {
                throw new Exception("First field type wasn't an optional modifier - need to iterate");
            }

            int xorPart = (int)((uint)((field.Name.String[NameChars[0]] ^ (char)fieldSig[fieldSig.Length - 1]) << Shifts[0]) +
                   (uint)((field.Name.String[NameChars[1]] ^ (char)fieldSig[fieldSig.Length - 2]) << Shifts[1]) +
                   (uint)((field.Name.String[NameChars[2]] ^ (char)fieldSig[fieldSig.Length - 3]) << Shifts[2]) +
                   (uint)((field.Name.String[NameChars[3]] ^ (char)fieldSig[fieldSig.Length - 4]) << Shifts[3]));
            
            key += xorPart;
            File.AppendAllText("refproxy_debug.log", $"[RefProxyHandler] Key (Initial + XOR): {key:X8} (Init: {optSig.Modifier.MDToken.Raw:X8}, XOR: {xorPart:X8}){Environment.NewLine}");

            if (X86Method != null)
            {
                int oldKey = key;
                key = X86Method.Emulate(new int[] { key });
                File.AppendAllText("refproxy_debug.log", $"[RefProxyHandler] Key after X86 Emulation: {key:X8} (was {oldKey:X8}){Environment.NewLine}");
            }
            
            if (EncodingMethod != null)
            {
                EnsureAssemblyLoaded();
                
                var methodInfo = FindMethodInAssembly(EncodingMethod);
                if (methodInfo == null)
                    throw new Exception($"Could not resolve EncodingMethod '{EncodingMethod.Name}' via Reflection (Name lookup).");
                
                try 
                {
                    key = (int)methodInfo.Invoke(null, new object[] { key })!;
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to invoke EncodingMethod dynamically: {ex.Message}", ex);
                }
            }

            if (X86Method == null && EncodingMethod == null)
            {
                throw new NotImplementedException("No decryption method (native or managed) found in RefProxy handler");
            }

            int hash = GetFieldHash(field);
            int finalKey = key * hash;
            
            File.AppendAllText("refproxy_debug.log", $"[RefProxyHandler] Field: {field.Name} (Len: {field.Name.Length}), SigLen: {fieldSig.Length}, ExtraData: {BitConverter.ToString(fieldSig)}{Environment.NewLine}");
            File.AppendAllText("refproxy_debug.log", $"[RefProxyHandler] NameChars: {string.Join(",", NameChars)}, Shifts: {string.Join(",", Shifts)}{Environment.NewLine}");
            File.AppendAllText("refproxy_debug.log", $"[RefProxyHandler] Key (pre-hash): {key:X8}, Hash: {hash:X8}, Final: {finalKey:X8}{Environment.NewLine}");

            return new MDToken(finalKey);
        }

        public OpCode GetOpCode(FieldDef field, byte opKey)
        {
            var opCode = (Code)(field.Name.String[NameChars[4]] ^ opKey);
            return opCode.ToOpCode();
        }

        private int GetFieldHash(FieldDef field)
        {
            // Fully static implementation - no dynamic loading needed!
            
            if (!field.HasCustomAttributes)
                throw new Exception($"No custom attributes found on field {field.Name} (static check).");

            var attr = field.CustomAttributes[0];
            int? retVal = null;
            
            // RefProxy attributes usually store the hash as the first constructor argument
            if (attr.ConstructorArguments.Count > 0)
            {
                var arg = attr.ConstructorArguments[0];
                if (arg.Value is int intVal)
                    retVal = intVal;
                else if (arg.Value is uint uintVal)
                    retVal = (int)uintVal;
            }
            
            // Or sometimes as a named argument
            if (retVal == null && attr.NamedArguments.Count > 0)
            {
                foreach (var namedArg in attr.NamedArguments)
                {
                    if (namedArg.Argument.Value is int intVal)
                    {
                        retVal = intVal;
                        break;
                    }
                }
            }

            if (retVal.HasValue)
            {
                File.AppendAllText("refproxy_debug.log", $"[RefProxyHandler] GetFieldHash: Found hash {retVal.Value:X8} in attribute {attr.TypeFullName}{Environment.NewLine}");
                
                // Inspect Attribute GetHashCode
                var currentTypeDef = attr.AttributeType.ResolveTypeDef();
                MethodDef getHashCode = null;
                
                while (currentTypeDef != null)
                {
                    getHashCode = currentTypeDef.FindMethod("GetHashCode");
                    if (getHashCode != null && getHashCode.HasBody)
                    {
                        File.AppendAllText("refproxy_debug.log", $"[RefProxyHandler] Found GetHashCode in {currentTypeDef.FullName}. Inspecting IL:{Environment.NewLine}");
                        foreach(var ins in getHashCode.Body.Instructions)
                        {
                            File.AppendAllText("refproxy_debug.log", $"  {ins.OpCode} {ins.Operand}{Environment.NewLine}");
                        }
                        break;
                    }
                    else if (getHashCode != null)
                    {
                         File.AppendAllText("refproxy_debug.log", $"[RefProxyHandler] Found GetHashCode in {currentTypeDef.FullName} but it has no body.{Environment.NewLine}");
                         break;
                    }

                    if (currentTypeDef.BaseType == null) break;
                    currentTypeDef = currentTypeDef.BaseType.ResolveTypeDef();
                }

                if (getHashCode == null)
                {
                    File.AppendAllText("refproxy_debug.log", $"[RefProxyHandler] Attribute GetHashCode not found in hierarchy.{Environment.NewLine}");
                }
                
                return retVal.Value;
            }

            throw new Exception($"Could not extract int hash from attribute {attr.TypeFullName} statically. ConstructorArgs: {attr.ConstructorArguments.Count}");
        }
        
        ~RefProxyHandler()
        {
            if (TempAssemblyPath != null && File.Exists(TempAssemblyPath))
            {
                try { File.Delete(TempAssemblyPath); } catch { }
            }
        }
    }
}
