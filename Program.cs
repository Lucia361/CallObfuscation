using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Builder;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using FieldAttributes = AsmResolver.PE.DotNet.Metadata.Tables.Rows.FieldAttributes;

namespace CallObfuscation {
    internal static class Program {
        private static void Main(
            string[] args) {
            
            if (args.Length <= 0) {
                Console.Write("[Path]: ");
                args = new[] { Console.ReadLine() };
            }

            var identifierCache = new Dictionary<IMethodDescriptor, int>();
            int currentIndex = 0;
            var moduleDefinition = ModuleDefinition.FromFile(args[0]);

            // Gets GlobalType (<Module>) static constructor (.cctor).
            var globalConstructor = moduleDefinition.GetOrCreateModuleConstructor();
            // Create field of (IntPtr/Native Int) array type.
            var functionPointerArray = CreateFunctionPointerArray(moduleDefinition);
            // Add the field to the module.
            moduleDefinition.GetOrCreateModuleType().Fields.Add(functionPointerArray);
            // Define Importer targeted to moduleDefinition.
            var importer = new ReferenceImporter(moduleDefinition);

            globalConstructor.CilMethodBody ??= new CilMethodBody(globalConstructor);

            // Remove any exit flow codes used before.
            if (globalConstructor.CilMethodBody!.Instructions.Any(i => i.OpCode.Code is CilCode.Ret))
                foreach (var ret in globalConstructor.CilMethodBody!.Instructions
                    .Where(i => i.OpCode.Code is CilCode.Ret).ToArray())
                    globalConstructor.CilMethodBody!.Instructions.Remove(ret);

            var getTypeFromHandle = GetCorLibMethod(moduleDefinition,
                "System", nameof(Type),
                nameof(Type.GetTypeFromHandle), "System.RuntimeTypeHandle");
            var getModule = GetCorLibMethod(moduleDefinition,
                "System", nameof(Type),
                $"get_{nameof(Type.Module)}", Array.Empty<string>());
            var resolveMethod = GetCorLibMethod(moduleDefinition,
                "System.Reflection", nameof(Module),
                nameof(Module.ResolveMethod), "System.Int32");
            var getMethodHandle = GetCorLibMethod(moduleDefinition,
                "System.Reflection", nameof(MethodBase),
                $"get_{nameof(MethodBase.MethodHandle)}", Array.Empty<string>());
            var getFunctionPointer = GetCorLibMethod(moduleDefinition,
                "System", nameof(RuntimeMethodHandle),
                nameof(RuntimeMethodHandle.GetFunctionPointer), Array.Empty<string>());

            var loadAddress =
                new CilLocalVariable(importer.ImportTypeSignature(getFunctionPointer.DeclaringType!.ToTypeSignature()));
            globalConstructor.CilMethodBody.LocalVariables.Add(loadAddress);

            var methods = moduleDefinition
                .GetAllTypes()
                .SelectMany(t => t.Methods)
                .Where(m => m.CilMethodBody is not null)
                .ToArray();


            foreach (var method in methods) {
                var instructions = method.CilMethodBody!.Instructions;
                instructions.ExpandMacros();
                for (int i = 0; i < instructions.Count; i++) {
                    var instruction = instructions[i];

                    if (!(instruction.OpCode == CilOpCodes.Call ||
                          instruction.OpCode == CilOpCodes.Callvirt)) continue;
                    if (instruction.Operand is not IMethodDescriptor methodDescriptor) continue;

                    switch (methodDescriptor) {
                        case MethodSpecification:
                        case MethodDefinition:
                            continue;
                    }


                    if (methodDescriptor.DeclaringType is TypeSpecification) continue;
                    if (methodDescriptor.Signature!.IsSentinel) continue;
                    if (methodDescriptor.DeclaringType?.Resolve() is not { IsDelegate: false } resolvedType) continue;
                    if (resolvedType.IsValueType && methodDescriptor.Signature!.HasThis) continue;

                    if (!identifierCache.ContainsKey(methodDescriptor)) {
                        identifierCache[methodDescriptor] = currentIndex++;
                        var arrayStoreExpression = new[] {
                            new CilInstruction(CilOpCodes.Ldsfld, functionPointerArray)
                        }.Concat(MutateI4(identifierCache[methodDescriptor])).Concat(new[] {
                            new CilInstruction(CilOpCodes.Ldtoken, moduleDefinition.GetModuleType()),
                            new CilInstruction(CilOpCodes.Call, importer.ImportMethod(getTypeFromHandle)),
                            new CilInstruction(CilOpCodes.Callvirt, importer.ImportMethod(getModule))
                        }.Concat(MutateI4(methodDescriptor.MetadataToken.ToInt32())).Concat(new[] {
                            new CilInstruction(CilOpCodes.Callvirt, importer.ImportMethod(resolveMethod)),
                            new CilInstruction(CilOpCodes.Callvirt, importer.ImportMethod(getMethodHandle)),
                            new CilInstruction(CilOpCodes.Stloc, loadAddress),
                            new CilInstruction(CilOpCodes.Ldloca, loadAddress),
                            new CilInstruction(CilOpCodes.Call, importer.ImportMethod(getFunctionPointer)),
                            new CilInstruction(CilOpCodes.Stelem_I)
                        }));
                        globalConstructor.CilMethodBody!.Instructions.AddRange(arrayStoreExpression);
                    }

                    var calliExpression = new[] { new CilInstruction(CilOpCodes.Ldsfld, functionPointerArray) }
                        .Concat(MutateI4(identifierCache[methodDescriptor]))
                        .Concat(new[] {
                            new CilInstruction(CilOpCodes.Ldelem_I),
                            new CilInstruction(CilOpCodes.Calli, methodDescriptor.Signature.MakeStandAloneSignature())
                        }).ToArray();

                    instruction.OpCode = CilOpCodes.Nop;
                    instruction.Operand = null;

                    instructions.InsertRange(i, calliExpression);
                    i += calliExpression.Length;
                }
                instructions.OptimizeMacros();
            }

            // Initialize Array.
            globalConstructor.CilMethodBody!.Instructions.InsertRange(0,
                MutateI4(currentIndex).ToArray()
                    .Concat(new[] { new CilInstruction(CilOpCodes.Newarr, moduleDefinition.CorLibTypeFactory.IntPtr.Type) })
                    .Concat(new[] { new CilInstruction(CilOpCodes.Stsfld, functionPointerArray) }));
            // Make sure to exit the method flow.
            globalConstructor.CilMethodBody!.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
            globalConstructor.CilMethodBody!.Instructions.OptimizeMacros();
            globalConstructor.CilMethodBody!.InitializeLocals = true;
            moduleDefinition.Write(args[0].Insert(args[0].Length - 4, "-CallObfuscated"),
                // Preserving metadata tokens.
                new ManagedPEImageBuilder(MetadataBuilderFlags.PreserveTableIndices));
        }

        private static FieldDefinition CreateFunctionPointerArray(
            ModuleDefinition moduleDefinition) {
            return new FieldDefinition(((char)new Random().Next('a', 'z')).ToString(),
                FieldAttributes.Assembly | FieldAttributes.Static,
                FieldSignature.CreateStatic(moduleDefinition.CorLibTypeFactory.IntPtr.MakeSzArrayType()));
        }

        private static IMethodDescriptor GetCorLibMethod(
            ModuleDefinition moduleDefinition,
            string ns,
            string typename,
            string methodName,
            params string[] parametersFullName) {
            var importer = new ReferenceImporter(moduleDefinition);
            var typeRef = new TypeReference(moduleDefinition.CorLibTypeFactory.CorLibScope, ns, typename);

            var resolvedReference = importer.ImportType(typeRef).Resolve();

            foreach (var method in resolvedReference!.Methods) {
                if (method.Name != methodName) continue;

                string[] typeNames = method.Parameters.Select(p => p.ParameterType.FullName).ToArray();

                if (!StringEquals(parametersFullName, typeNames)) continue;

                return method;
            }

            return null;

            bool StringEquals(IReadOnlyCollection<string> a, IReadOnlyList<string> b) {
                if (a.Count != b.Count) return false;
                return !a.Where((t, x) => t != b[x]).Any();
            }
        }

        private static IEnumerable<CilInstruction> MutateI4(
            int value) {
            var expression = new List<CilInstruction>();
            var random = new Random();

            expression.AddRange(Mutate(value));

            foreach (var loadI4 in expression.Where(i => i.IsLdcI4()).ToArray()) {
                int insertIndex = expression.IndexOf(loadI4);
                expression.InsertRange(insertIndex, Mutate(loadI4.GetLdcI4Constant()));
                expression.Remove(loadI4);
            }

            return expression;

            IEnumerable<CilInstruction> Mutate(int i32Value) {
                var instructions = new List<CilInstruction>();
                switch (random.Next(3)) {
                    case 0:
                        int subI32 = random.Next();
                        instructions.AddRange(new[] {
                            new CilInstruction(CilOpCodes.Ldc_I4, i32Value - subI32),
                            new CilInstruction(CilOpCodes.Ldc_I4, subI32),
                            new CilInstruction(CilOpCodes.Add)
                        });
                        break;
                    case 1:
                        int addI32 = random.Next();
                        instructions.AddRange(new[] {
                            new CilInstruction(CilOpCodes.Ldc_I4, i32Value + addI32),
                            new CilInstruction(CilOpCodes.Ldc_I4, addI32),
                            new CilInstruction(CilOpCodes.Sub)
                        });
                        break;
                    case 2:
                        int xorI32 = random.Next();
                        instructions.AddRange(new[] {
                            new CilInstruction(CilOpCodes.Ldc_I4, i32Value ^ xorI32),
                            new CilInstruction(CilOpCodes.Ldc_I4, xorI32),
                            new CilInstruction(CilOpCodes.Xor)
                        });
                        break;
                }

                return instructions;
            }
        }
    }
}