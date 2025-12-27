using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

public class Program
{
    public static void Main(string[] args)
    {
        var module = ModuleDefMD.Load(@"c:\Users\victim\Documents\GitHub\UnconfuserEx\examples\RacGuard-deobfuscated.dll");
        foreach (var type in module.GetTypes())
        {
            if (type.Name.Contains("Class136") || type.Name.Contains("Class16"))
            {
                Console.WriteLine($"Type found: {type.FullName}");
                foreach (var method in type.Methods)
                {
                    if (method.Name.Contains("Method3") || method.Name.Contains(".ctor") || method.Name.Contains(".cctor"))
                    {
                        Console.WriteLine($"Method: {method.FullName}");
                        if (method.HasBody)
                        {
                            foreach (var instr in method.Body.Instructions)
                                Console.WriteLine(instr.ToString());
                        }
                    }
                }
            }
        }
    }
}
