using System;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System.Collections.Generic;
using UnConfuserEx.Protections;
using log4net;
using log4net.Config;
using UnConfuserEx.Protections.Delegates;
using UnConfuserEx.Protections.AntiDebug;
using UnConfuserEx.Protections.AntiDump;

namespace UnConfuserEx
{
    internal class UnConfuserEx
    {
        static ILog Logger = LogManager.GetLogger("UnConfuserEx");

        static int Main(string[] args)
        {
            XmlConfigurator.Configure(typeof(UnConfuserEx).Assembly.GetManifestResourceStream("UnConfuserEx.log4net.xml"));

            if (args.Length < 1 || args.Length > 2)
            {
                Logger.Error("Usage: unconfuser.exe <module path> <output path>");
                return 1;
            }

            var path = Path.GetFullPath(args[0]);
            if (!File.Exists(path))
            {
                Logger.Error($"File {path} does not exist");
                return 1;
            }

            // Load the module
            ModuleContext context = new();
            context.AssemblyResolver = new AssemblyResolver();
            context.Resolver = new Resolver(context.AssemblyResolver);
            
            ModuleDefMD module = ModuleDefMD.Load(path, context);
            ((AssemblyResolver)context.AssemblyResolver).AddToCache(module);

            var pipeline = new List<IProtection>
            {
                new RefProxyRemover(),
                
                // If this is present, it MUST be removed first (among CF/Tamper)
                new AntiTamperRemover(),
                
                // This must then be removed second
                new ControlFlowRemover(),

                // And these can all be removed in any order
                new ResourcesRemover(),
                new ConstantsRemover(),
                new AntiDumpRemover(),
                new UnicodeRemover(),

                // Except for this, which requires constants to be removed
                new AntiDebugRemover(),
            };

            foreach (var p in pipeline)
            {
                if (p.IsPresent(ref module))
                {
                    Logger.Info($"{p.Name} detected, attempting to remove");
                    try
                    {
                        if (p.Remove(ref module))
                        {
                            Logger.Info($"Successfully removed {p.Name} protection");
                        }
                        else
                        {
                            Logger.Error($"Failed to remove {p.Name} protection");
                            return 1;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Fatal($"Caught exception when trying to remove {p.Name} protection");
                        Logger.Error(ex.ToString());
                        File.AppendAllText("error.log", $"[Protection {p.Name}] {ex}\n");
                        return 1;
                    }
                }
            }

            var newPath = $"{Path.GetDirectoryName(path)}\\{Path.GetFileNameWithoutExtension(path)}-deobfuscated{Path.GetExtension(path)}";
            if (args.Length == 2)
            {
                // Use the user supplied path
                newPath = args[1];
            }

            // Write the module back
            Logger.Info($"All detected protections removed. Writing new module to {newPath}");

            try
            {
                if (module.IsILOnly)
                {
                    ModuleWriterOptions writerOptions = new ModuleWriterOptions(module);
                    module.Write(newPath, writerOptions);
                }
                else
                {
                    NativeModuleWriterOptions writerOptions = new NativeModuleWriterOptions(module, true);
                    //writerOptions.Logger = DummyLogger.NoThrowInstance;
                    try
                    {
                        module.NativeWrite(newPath, writerOptions);
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn($"Standard NativeWrite failed: {ex.Message}. Retrying without token preservation...");
                        writerOptions = new NativeModuleWriterOptions(module, false);
                        writerOptions.Logger = DummyLogger.NoThrowInstance;
                        module.NativeWrite(newPath, writerOptions);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to write module");
                Logger.Error(ex.ToString());
                File.AppendAllText("error.log", $"[ModuleWriter] {ex}\n");
                return 1;
            }
            Logger.Info("Deobfuscated module successfully written");

            Logger.Info("Deobfuscated module successfully written");

            // Diagnostic IL dump for CLIENT.Library::Main (token 06000151)
            try
            {
                foreach (var type in module.GetTypes())
                {
                    foreach (var m in type.Methods)
                    {
                        if (m.MDToken.Raw == 0x06000151)
                        {
                            var il = new List<string>();
                            il.Add($"Method: {m.FullName} (Token: {m.MDToken.Raw:X8})");
                            if (m.HasBody)
                            {
                                foreach (var instr in m.Body.Instructions)
                                    il.Add(instr.ToString());
                            }
                            File.WriteAllLines("main_method_deobfuscated_il_v2.txt", il);
                            Logger.Info("Dumped Main method IL to main_method_deobfuscated_il_v2.txt");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to dump Main method IL: {ex.Message}");
            }

            // Done
            return 0;
        }

    }
}