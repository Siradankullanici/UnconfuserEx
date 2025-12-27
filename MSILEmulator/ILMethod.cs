using dnlib.DotNet;
using dnlib.DotNet.Emit;
using MSILEmulator.Instructions.Arithmetic;
using MSILEmulator.Instructions.Branch;
using MSILEmulator.Instructions.Load;
using MSILEmulator.Instructions.Logic;
using MSILEmulator.Instructions.Store;
using System;
using System.Collections.Generic;
using System.Linq;

namespace MSILEmulator
{
    public class ILMethod
    {
        private MethodDef? Method;
        private List<Instruction> Instructions;
        private Context Ctx;

        public ILMethod(MethodDef method)
        {
            Method = method;
            Instructions = Method.Body.Instructions.ToList();
            Ctx = new(Instructions);
        }

        public ILMethod(MethodDef method, int start, int end)
        {
            Method = method;
            Instructions = Method.Body.Instructions.Skip(start).Take(end - start).ToList();
            Ctx = new(Instructions);
        }

        public ILMethod(IEnumerable<Instruction> instructions)
        {
            Method = null;
            Instructions = instructions.ToList();
            Ctx = new(Instructions);
        }

        public void SetArg(int index, object value)
        {
            Ctx.Args[index] = value;
        }

        public void SetLocal(int index, object value)
        {
            Ctx.Locals[index] = value;
        }

        public Context Emulate()
        {

            for (int i = 0; i < Instructions.Count; )
            {
                var instr = Instructions[i];

                i = EmulateInstruction(Ctx, instr, i);

                if (i == -1)
                {
                    break;
                }
            }

            return Ctx;
        }

        private int EmulateInstruction(Context ctx, Instruction instr, int index)
        {

            switch (instr.OpCode.Code)
            {
                // Load
                case Code.Ldc_I4:
                case Code.Ldc_I4_S:
                    ctx.Stack.Push(instr.GetLdcI4Value());
                    break;
                case Code.Ldc_I4_0:
                case Code.Ldc_I4_1:
                case Code.Ldc_I4_2:
                case Code.Ldc_I4_3:
                case Code.Ldc_I4_4:
                case Code.Ldc_I4_5:
                case Code.Ldc_I4_6:
                case Code.Ldc_I4_7:
                case Code.Ldc_I4_8:
                    ctx.Stack.Push((int)instr.OpCode.Code - (int)Code.Ldc_I4_0);
                    break;
                case Code.Ldc_I4_M1:
                    ctx.Stack.Push((int)-1);
                    break;

                case Code.Ldc_I8:
                    ctx.Stack.Push((long)instr.Operand);
                    break;

                case Code.Ldc_R4:
                    ctx.Stack.Push((float)instr.Operand);
                    break;

                case Code.Ldc_R8:
                    ctx.Stack.Push((double)instr.Operand);
                    break;

                case Code.Ldarg:
                case Code.Ldarg_0:
                case Code.Ldarg_1:
                case Code.Ldarg_2:
                case Code.Ldarg_3:
                case Code.Ldarg_S:
                    Ldarg.Emulate(ctx, instr);
                    break;

                case Code.Ldloc:
                case Code.Ldloc_0:
                case Code.Ldloc_1:
                case Code.Ldloc_2:
                case Code.Ldloc_3:
                case Code.Ldloc_S:
                    Ldloc.Emulate(ctx, instr);
                    break;

                case Code.Ldelem_U4:
                    Ldelem.EmulateU4(ctx, instr);
                    break;

                // Store
                case Code.Stloc:
                case Code.Stloc_0:
                case Code.Stloc_1:
                case Code.Stloc_2:
                case Code.Stloc_3:
                case Code.Stloc_S:
                    Stloc.Emulate(ctx, instr);
                    break;

                case Code.Stelem_I4:
                    Stelem.Emulate(ctx, instr);
                    break;


                // Arithmetic operators
                case Code.Add:
                    Add.Emulate(ctx);
                    break;
                case Code.Mul:
                    Mul.Emulate(ctx);
                    break;
                case Code.Neg:
                    Neg.Emulate(ctx);
                    break;
                case Code.Or:
                    Or.Emulate(ctx);
                    break;
                case Code.Sub:
                    Sub.Emulate(ctx);
                    break;

                // Logic operators
                case Code.And:
                    And.Emulate(ctx);
                    break;
                case Code.Not:
                    Not.Emulate(ctx);
                    break;
                case Code.Shl:
                    Shl.Emulate(ctx);
                    break;
                case Code.Shr:
                    Shr.Emulate(ctx);
                    break;
                case Code.Shr_Un:
                    Shr_Un.Emulate(ctx);
                    break;
                case Code.Xor:
                    Xor.Emulate(ctx);
                    break;
                case Code.Ceq:
                    Ceq.Emulate(ctx);
                    break;
                case Code.Clt:
                    Clt.Emulate(ctx);
                    break;
                case Code.Clt_Un:
                    Clt.Emulate(ctx); // Using same for now
                    break;
                case Code.Cgt:
                    Cgt.Emulate(ctx);
                    break;
                case Code.Cgt_Un:
                    Cgt.Emulate(ctx); // Using same for now
                    break;


                // Branching
                case Code.Br:
                case Code.Br_S:
                    return ctx.Offsets[((Instruction)instr.Operand).Offset];
                case Code.Beq:
                case Code.Beq_S:
                    return Beq.Emulate(ctx, instr);
                case Code.Bne_Un:
                case Code.Bne_Un_S:
                    return Bne.Emulate(ctx, instr);
                case Code.Bge:
                case Code.Bge_S:
                    return Bge.Emulate(ctx, instr);
                case Code.Bge_Un:
                case Code.Bge_Un_S:
                    return Bge.EmulateUn(ctx, instr);
                case Code.Blt:
                case Code.Blt_S:
                    return Blt.Emulate(ctx, instr);
                case Code.Blt_Un:
                case Code.Blt_Un_S:
                    return Blt.EmulateUn(ctx, instr);
                case Code.Bgt:
                case Code.Bgt_S:
                    return Bgt.Emulate(ctx, instr);
                case Code.Bgt_Un:
                case Code.Bgt_Un_S:
                    return Bgt.EmulateUn(ctx, instr);
                case Code.Ble:
                case Code.Ble_S:
                    return Ble.Emulate(ctx, instr);
                case Code.Ble_Un:
                case Code.Ble_Un_S:
                    return Ble.EmulateUn(ctx, instr);

                case Code.Brtrue:
                case Code.Brtrue_S:
                    {
                        var val = ctx.Stack.Pop();
                        bool condition = false;
                        if (val is int i) condition = i != 0;
                        else if (val is bool b) condition = b;
                        else if (val is long l) condition = l != 0;
                        else if (val != null) condition = true;

                        if (condition)
                            return ctx.Offsets[((Instruction)instr.Operand).Offset];
                        else
                            break;
                    }
                case Code.Stfld:
                case Code.Stsfld:
                    ctx.LastStoredValue = ctx.Stack.Pop();
                    if (instr.OpCode.Code == Code.Stfld)
                        ctx.Stack.Pop(); // Instance
                    break;

                case Code.Brfalse:
                case Code.Brfalse_S:
                    {
                        var val = ctx.Stack.Pop();
                        bool condition = false;
                        if (val is int i) condition = i == 0;
                        else if (val is bool b) condition = b == false;
                        else if (val is long l) condition = l == 0;
                        else if (val == null) condition = true;

                        if (condition)
                            return ctx.Offsets[((Instruction)instr.Operand).Offset];
                        else
                            break;
                    }

                // Conversion
                case Code.Conv_I4:
                    ctx.Stack.Push(Convert.ToInt32(ctx.Stack.Pop()));
                    break;
                case Code.Conv_U8:
                    ctx.Stack.Push(Convert.ToUInt64(ctx.Stack.Pop()));
                    break;
                case Code.Conv_U4:
                    ctx.Stack.Push(Convert.ToUInt32(ctx.Stack.Pop()));
                    break;
                case Code.Conv_U:
                    ctx.Stack.Push((UIntPtr)Convert.ToUInt64(ctx.Stack.Pop()));
                    break;
                case Code.Conv_I:
                    ctx.Stack.Push((IntPtr)Convert.ToInt64(ctx.Stack.Pop()));
                    break;

                // Misc
                case Code.Ldlen:
                    ctx.Stack.Push(((Array)ctx.Stack.Pop()).Length);
                    break;
                case Code.Nop:
                    // ...No-op
                    break;

                case Code.Ret:
                    return -1;

                case Code.Pop:
                    ctx.Stack.Pop();
                    break;
                case Code.Dup:
                    ctx.Stack.Push(ctx.Stack.Peek());
                    break;

                case Code.Ldfld:
                case Code.Ldsfld:
                    ctx.Stack.Push(0); // Dummy value
                    break;
                case Code.Ldstr:
                    ctx.Stack.Push((string)instr.Operand);
                    break;

                case Code.Ldind_I1:
                case Code.Ldind_U1:
                case Code.Ldind_I2:
                case Code.Ldind_U2:
                case Code.Ldind_I4:
                case Code.Ldind_U4:
                case Code.Ldind_I8:
                case Code.Ldind_I:
                case Code.Ldind_R4:
                case Code.Ldind_R8:
                case Code.Ldind_Ref:
                    ctx.Stack.Pop(); // Address
                    ctx.Stack.Push(0); // Return dummy value for now
                    break;

                case Code.Stind_I1:
                case Code.Stind_I2:
                case Code.Stind_I4:
                case Code.Stind_I8:
                case Code.Stind_I:
                case Code.Stind_R4:
                case Code.Stind_R8:
                case Code.Stind_Ref:
                    ctx.Stack.Pop(); // Value
                    ctx.Stack.Pop(); // Address
                    break;

                case Code.Newarr:
                    ctx.Stack.Pop(); // Size
                    ctx.Stack.Push(new object[0]);
                    break;

                case Code.Ldelem_I1:
                case Code.Ldelem_U1:
                case Code.Ldelem_I2:
                case Code.Ldelem_U2:
                case Code.Ldelem_I4:
                case Code.Ldelem_I8:
                case Code.Ldelem_I:
                case Code.Ldelem_R4:
                case Code.Ldelem_R8:
                case Code.Ldelem_Ref:
                    ctx.Stack.Pop(); // Index
                    ctx.Stack.Pop(); // Array
                    ctx.Stack.Push(0);
                    break;

                case Code.Stelem_I1:
                case Code.Stelem_I2:
                case Code.Stelem_I8:
                case Code.Stelem_R4:
                case Code.Stelem_R8:
                case Code.Stelem_Ref:
                    ctx.Stack.Pop(); // Value
                    ctx.Stack.Pop(); // Index
                    ctx.Stack.Pop(); // Array
                    break;

                case Code.Ldtoken:
                    ctx.Stack.Push(instr.Operand);
                    break;

                case Code.Box:
                case Code.Unbox_Any:
                    break;

                case Code.Castclass:
                    break;

                case Code.Call:
                case Code.Callvirt:
                    var m = (IMethod)instr.Operand;
                    if (m.FullName.Contains("System.Math::"))
                    {
                        if (m.Name == "Log") ctx.Stack.Push(Math.Log(Convert.ToDouble(ctx.Stack.Pop())));
                        else if (m.Name == "Ceiling") ctx.Stack.Push(Math.Ceiling(Convert.ToDouble(ctx.Stack.Pop())));
                        else if (m.Name == "Abs") ctx.Stack.Push(Math.Abs(Convert.ToDouble(ctx.Stack.Pop())));
                        else if (m.Name == "Cos") ctx.Stack.Push(Math.Cos(Convert.ToDouble(ctx.Stack.Pop())));
                        else if (m.Name == "Tan") ctx.Stack.Push(Math.Tan(Convert.ToDouble(ctx.Stack.Pop())));
                        else if (m.Name == "Sqrt") ctx.Stack.Push(Math.Sqrt(Convert.ToDouble(ctx.Stack.Pop())));
                    }
                    else if (m.FullName.Contains("System.Convert::ToInt32"))
                    {
                        ctx.Stack.Push(Convert.ToInt32(ctx.Stack.Pop()));
                    }
                    else if (m.FullName.Contains("System.String::op_Equality"))
                    {
                        string s2 = (string)ctx.Stack.Pop();
                        string s1 = (string)ctx.Stack.Pop();
                        ctx.Stack.Push(s1 == s2 ? 1 : 0);
                    }
                    else if (m.Name == "GetTypeFromHandle")
                    {
                        ctx.Stack.Push(ctx.Stack.Pop()); // Just return the handle as Type for now
                    }
                    else if (m.Name == "get_Module")
                    {
                        ctx.Stack.Push(ctx.Stack.Pop()); // Return type as module
                    }
                    else if (m.Name == "get_FullyQualifiedName")
                    {
                        ctx.Stack.Push("C:\\bed.dll");
                    }
                    else if (m.Name == "get_Length")
                    {
                        var val = ctx.Stack.Pop();
                        if (val is string s) ctx.Stack.Push(s.Length);
                        else if (val is Array a) ctx.Stack.Push(a.Length);
                        else ctx.Stack.Push(0);
                    }
                    else if (m.Name == "get_Chars")
                    {
                        int index2 = (int)ctx.Stack.Pop();
                        string s = (string)ctx.Stack.Pop();
                        ctx.Stack.Push((int)s[index2]);
                    }
                    else if (m.Name == "GetHINSTANCE")
                    {
                        ctx.Stack.Pop();
                        ctx.Stack.Push((IntPtr)0x400000);
                    }
                    else if (m.Name == "op_Explicit")
                    {
                        ctx.Stack.Push(ctx.Stack.Pop());
                    }
                    else if (m.Name == "ResolveSignature")
                    {
                        ctx.Stack.Pop(); // token
                        ctx.Stack.Pop(); // module
                        ctx.Stack.Push(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 }); // Mock signature
                    }
                    else if (m.Name == "GetFieldFromHandle")
                    {
                        ctx.Stack.Push(ctx.Stack.Pop());
                    }
                    else if (m.Name == "GetOptionalCustomModifiers")
                    {
                        ctx.Stack.Pop();
                        ctx.Stack.Push(new object[] { typeof(int) }); // Mock
                    }
                    else if (m.Name == "get_MetadataToken")
                    {
                        ctx.Stack.Pop();
                        ctx.Stack.Push(0); // Mock
                    }
                    else if (m.Name == "get_Name")
                    {
                        ctx.Stack.Push("MockName");
                    }
                    else if (m.Name == "ResolveMethod")
                    {
                        ctx.Stack.Pop(); // token
                        ctx.Stack.Pop(); // module
                        ctx.Stack.Push(null); // Mock
                    }
                    break;

                default:
                    throw new EmulatorException($"Unhandled OpCode {instr.OpCode}");
            }

            return ++index;
        }

    }
}
