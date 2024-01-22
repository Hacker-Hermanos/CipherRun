using System;
using System.Collections.Generic;
using static CipherRun.Data.Enums;
using static CipherRun.Data.Structs;
using static CipherRun.Data.Delegates;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;



namespace CipherRun.Helpers
{
    /// <summary>
    /// This Class Contains Core Helper Methods Will Be Used In Many Techniques, (Nt* Functions Exposed From This Class Are Syscalls)
    /// </summary>
    /// <remarks>Some of Them Look Similar To DInvoke Because They Are From DInvoke XD, Their Definitions is a little Modified to Meet Our Needs</remarks>
    public class Methods
    {
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint MEM_RELEASE = 0x8000;

        const uint PAGE_READONLY = 0x02;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE = 0x10;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint PAGE_EXECUTE_READWRITE = 0x40;



        /* Start External Functions Def */


        public static IntPtr AllocateFileToMemory(string filePath)
        {
            if (!File.Exists(filePath))
                throw new InvalidOperationException("Filepath not found.");

            var bFile = File.ReadAllBytes(filePath);
            return AllocateBytesToMemory(bFile);
        }


        public static IntPtr AllocateBytesToMemory(byte[] fileBytes)
        {
            var pFile = Marshal.AllocHGlobal(fileBytes.Length);
            Marshal.Copy(fileBytes, 0, pFile, fileBytes.Length);
            return pFile;
        }

        public static PE_META_DATA GetPeMetaData(IntPtr pModule)
        {
            var peMetaData = new PE_META_DATA();

            try
            {
                var e_lfanew = (uint)Marshal.ReadInt32((IntPtr)((ulong)pModule + 0x3c));
                peMetaData.Pe = (uint)Marshal.ReadInt32((IntPtr)((ulong)pModule + e_lfanew));

                if (peMetaData.Pe != 0x4550)
                    throw new InvalidOperationException("Invalid PE signature.");
                peMetaData.ImageFileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((ulong)pModule + e_lfanew + 0x4), typeof(IMAGE_FILE_HEADER));
                var optHeader = (IntPtr)((ulong)pModule + e_lfanew + 0x18);
                var peArch = (ushort)Marshal.ReadInt16(optHeader);
                switch (peArch)
                {
                    case 0x010b:
                        peMetaData.Is32Bit = true;
                        peMetaData.OptHeader32 =
                            (IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(optHeader,
                                typeof(IMAGE_OPTIONAL_HEADER32));
                        break;
                    case 0x020b:
                        peMetaData.Is32Bit = false;
                        peMetaData.OptHeader64 =
                            (IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(optHeader,
                                typeof(IMAGE_OPTIONAL_HEADER64));
                        break;
                    default:
                        throw new InvalidOperationException("Invalid magic value (PE32/PE32+).");
                }
                var sectionArray = new IMAGE_SECTION_HEADER[peMetaData.ImageFileHeader.NumberOfSections];
                for (var i = 0; i < peMetaData.ImageFileHeader.NumberOfSections; i++)
                {
                    var sectionPtr = (IntPtr)((ulong)optHeader + peMetaData.ImageFileHeader.SizeOfOptionalHeader + (uint)(i * 0x28));
                    sectionArray[i] = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(sectionPtr);
                }
                peMetaData.Sections = sectionArray;
            }
            catch
            {
                throw new InvalidOperationException("Invalid module base specified.");
            }
            return peMetaData;
        }



        public static object DynamicApiInvoke(string dllName, string functionName, Type functionDelegateType, ref object[] parameters, bool canLoadFromDisk = false, bool resolveForwards = true)
        {
            var pFunction = GetLibraryAddress(dllName, functionName, canLoadFromDisk, resolveForwards);
            return DynamicFunctionInvoke(pFunction, functionDelegateType, ref parameters);
        }

        public static object DynamicFunctionInvoke(IntPtr functionPointer, Type functionDelegateType, ref object[] parameters)
        {
            var funcDelegate = Marshal.GetDelegateForFunctionPointer(functionPointer, functionDelegateType);
            return funcDelegate.DynamicInvoke(parameters);
        }



        public static IntPtr GetLibraryAddress(string dllName, string functionName, bool canLoadFromDisk = false, bool resolveForwards = true)
        {
            var hModule = GetLoadedModuleAddress(dllName);
            if (hModule == IntPtr.Zero && canLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(dllName);

                if (hModule == IntPtr.Zero)
                    throw new FileNotFoundException(dllName + ", unable to find the specified file.");
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(dllName + ", Dll was not found.");
            }
            return GetExportAddress(hModule, functionName, resolveForwards);
        }

        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }
        public static IntPtr GetExportAddress(IntPtr moduleBase, string exportName, bool resolveForwards = true)
        {
            var functionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                var peHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
                var optHeader = moduleBase.ToInt64() + peHeader + 0x18;
                var magic = Marshal.ReadInt16((IntPtr)optHeader);
                long pExport;
                if (magic == 0x010b) pExport = optHeader + 0x60;
                else pExport = optHeader + 0x70;
                var exportRva = Marshal.ReadInt32((IntPtr)pExport);
                var ordinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x10));
                var numberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x18));
                var functionsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x1C));
                var namesRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x20));
                var ordinalsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x24));
                for (var i = 0; i < numberOfNames; i++)
                {
                    var functionName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + namesRva + i * 4))));
                    if (string.IsNullOrWhiteSpace(functionName)) continue;
                    if (!functionName.Equals(exportName, StringComparison.OrdinalIgnoreCase)) continue;
                    var functionOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;
                    var functionRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                    functionPtr = (IntPtr)((long)moduleBase + functionRva);
                    if (resolveForwards)
                        functionPtr = GetForwardAddress(functionPtr);
                    break;
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to parse module exports.");
            }
            if (functionPtr == IntPtr.Zero)
                throw new MissingMethodException(exportName + ", export not found.");
            return functionPtr;
        }
        public static IntPtr GetForwardAddress(IntPtr exportAddress, bool canLoadFromDisk = false)
        {
            var functionPtr = exportAddress;
            try
            {
                var forwardNames = Marshal.PtrToStringAnsi(functionPtr);
                if (string.IsNullOrWhiteSpace(forwardNames)) return functionPtr;
                var values = forwardNames.Split('.');
                if (values.Length > 1)
                {
                    var forwardModuleName = values[0];
                    var forwardExportName = values[1];
                    var apiSet = GetApiSetMapping();
                    var lookupKey = forwardModuleName.Substring(0, forwardModuleName.Length - 2) + ".dll";
                    if (apiSet.ContainsKey(lookupKey))
                        forwardModuleName = apiSet[lookupKey];
                    else
                        forwardModuleName = forwardModuleName + ".dll";
                    var hModule = GetPebLdrModuleEntry(forwardModuleName);
                    if (hModule == IntPtr.Zero && canLoadFromDisk)
                        hModule = LoadModuleFromDisk(forwardModuleName);
                    if (hModule != IntPtr.Zero)
                        functionPtr = GetExportAddress(hModule, forwardExportName);
                }
            }
            catch
            {
                // Do nothing, it was not a forward
            }
            return functionPtr;
        }
        public static IntPtr GetPebAddress()
        {
            byte[] stub;

            if (IntPtr.Size == 8)
            {
                stub = new byte[]
                {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x60,     // mov rax, qword ptr gs:[0x60]
                0x00, 0x00, 0x00,
                0xc3                                    // ret
                };
            }
            else
            {
                stub = new byte[]
                {
                0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,     // mov eax,dword ptr fs:[30]
                0xC3                                    // ret
                };
            }

            var parameters = Array.Empty<object>();

            return (IntPtr)DynamicAsmInvoke(
                stub,
                typeof(ReadGs),
                ref parameters);
        }

        public static object DynamicAsmInvoke(byte[] asmStub, Type functionDelegateType, ref object[] parameters)
        {
            unsafe
            {
                fixed (byte* buffer = asmStub)
                {
                    var ptr = (IntPtr)buffer;
                    var size = new IntPtr(asmStub.Length);
                    var oldProtect = DynamicNtProtectVirtualMemory(new IntPtr(-1), ref ptr,
                        ref size, PAGE_EXECUTE_READWRITE);
                    var result = DynamicFunctionInvoke(ptr, functionDelegateType, ref parameters);
                    DynamicNtProtectVirtualMemory(new IntPtr(-1), ref ptr,
                        ref size, oldProtect);
                    return result;
                }
            }
        }



        public static IntPtr GetPebLdrModuleEntry(string dllName)
        {
            // Set function variables
            uint ldrDataOffset;
            uint inLoadOrderModuleListOffset;

            if (IntPtr.Size == 4)
            {
                ldrDataOffset = 0xc;
                inLoadOrderModuleListOffset = 0xC;
            }
            else
            {
                ldrDataOffset = 0x18;
                inLoadOrderModuleListOffset = 0x10;
            }

            // Get _PEB pointer
            var pPeb = GetPebAddress();

            // Get module InLoadOrderModuleList -> _LIST_ENTRY
            var pebLdrData = Marshal.ReadIntPtr((IntPtr)((ulong)pPeb + ldrDataOffset));
            var pInLoadOrderModuleList = (IntPtr)((ulong)pebLdrData + inLoadOrderModuleListOffset);
            var le = (LIST_ENTRY)Marshal.PtrToStructure(pInLoadOrderModuleList, typeof(LIST_ENTRY));

            // Loop entries
            var flink = le.Flink;
            var hModule = IntPtr.Zero;
            var dte = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(LDR_DATA_TABLE_ENTRY));
            while (dte.InLoadOrderLinks.Flink != le.Blink)
            {
                // Match module name
                var moduleName = Marshal.PtrToStringUni(dte.BaseDllName.Buffer);
                if (!string.IsNullOrWhiteSpace(moduleName) && moduleName.Equals(dllName, StringComparison.OrdinalIgnoreCase))
                {
                    hModule = dte.DllBase;
                    break;
                }

                // Move Ptr
                flink = dte.InLoadOrderLinks.Flink;
                dte = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(LDR_DATA_TABLE_ENTRY));
            }

            return hModule;
        }

        public static Dictionary<string, string> GetApiSetMapping()
        {
            var pbi = NtQueryInformationProcessBasicInformation((IntPtr)(-1));
            var apiSetMapOffset = IntPtr.Size == 4 ? (uint)0x38 : 0x68;
            var apiSetDict = new Dictionary<string, string>();

            var pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((ulong)pbi.PebBaseAddress + apiSetMapOffset));
            var apiSetNamespace = (ApiSetNamespace)Marshal.PtrToStructure(pApiSetNamespace, typeof(ApiSetNamespace));

            for (var i = 0; i < apiSetNamespace.Count; i++)
            {
                var setEntry = new ApiSetNamespaceEntry();

                var pSetEntry = (IntPtr)((ulong)pApiSetNamespace + (ulong)apiSetNamespace.EntryOffset + (ulong)(i * Marshal.SizeOf(setEntry)));
                setEntry = (ApiSetNamespaceEntry)Marshal.PtrToStructure(pSetEntry, typeof(ApiSetNamespaceEntry));

                var apiSetEntryName = Marshal.PtrToStringUni((IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.NameOffset), setEntry.NameLength / 2);
                var apiSetEntryKey = apiSetEntryName.Substring(0, apiSetEntryName.Length - 2) + ".dll"; // Remove the patch number and add .dll

                var valueEntry = new ApiSetValueEntry();
                var pSetValue = IntPtr.Zero;

                switch (setEntry.ValueLength)
                {
                    case 1:
                        pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset);
                        break;

                    case > 1:
                        {
                            for (var j = 0; j < setEntry.ValueLength; j++)
                            {
                                var host = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset + (ulong)Marshal.SizeOf(valueEntry) * (ulong)j);
                                if (Marshal.PtrToStringUni(host) != apiSetEntryName)
                                    pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset + (ulong)Marshal.SizeOf(valueEntry) * (ulong)j);
                            }

                            if (pSetValue == IntPtr.Zero)
                                pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset);

                            break;
                        }
                }

                valueEntry = (ApiSetValueEntry)Marshal.PtrToStructure(pSetValue, typeof(ApiSetValueEntry));

                var apiSetValue = string.Empty;
                if (valueEntry.ValueCount != 0)
                {
                    var pValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)valueEntry.ValueOffset);
                    apiSetValue = Marshal.PtrToStringUni(pValue, valueEntry.ValueCount / 2);
                }

                apiSetDict.Add(apiSetEntryKey, apiSetValue);
            }

            return apiSetDict;
        }


        public static INTERNAL_PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
        {
            var retValue = DynamicNtQueryInformationProcess(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, out var pProcInfo);

            if (retValue != NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            return (INTERNAL_PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(INTERNAL_PROCESS_BASIC_INFORMATION));
        }


        public static NTSTATUS DynamicNtQueryInformationProcess(IntPtr hProcess, PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
        {
            int processInformationLength;
            uint retLen = 0;

            switch (processInfoClass)
            {
                case PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    processInformationLength = IntPtr.Size;
                    break;

                case PROCESSINFOCLASS.ProcessBasicInformation:
                    var pbi = new INTERNAL_PROCESS_BASIC_INFORMATION();
                    pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(pbi));
                    RtlZeroMemory(pProcInfo, Marshal.SizeOf(pbi));
                    Marshal.StructureToPtr(pbi, pProcInfo, true);
                    processInformationLength = Marshal.SizeOf(pbi);
                    break;

                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] funcargs =
            {
            hProcess, processInfoClass, pProcInfo, processInformationLength, retLen
        };

            var retValue = (NTSTATUS)DynamicApiInvoke("ntdll.dll", "NtQueryInformationProcess", typeof(DynamicNtQueryInformationProcess), ref funcargs);

            if (retValue != NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            pProcInfo = (IntPtr)funcargs[2];

            return retValue;
        }


        public static void RtlZeroMemory(IntPtr destination, int length)
        {
            object[] funcargs =
            {
            destination, length
        };

            DynamicApiInvoke("ntdll.dll", "RtlZeroMemory", typeof(DynamicRtlZeroMemory), ref funcargs);
        }

        public static IntPtr LoadModuleFromDisk(string dllPath)
        {
            var uModuleName = new UNICODE_STRING();
            RtlInitUnicodeString(ref uModuleName, dllPath);

            var hModule = IntPtr.Zero;
            var callResult = LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);

            if (callResult != NTSTATUS.Success || hModule == IntPtr.Zero)
                return IntPtr.Zero;

            return hModule;
        }


        public static void RtlInitUnicodeString(ref UNICODE_STRING destinationString, [MarshalAs(UnmanagedType.LPWStr)] string sourceString)
        {
            object[] funcargs =
            {
            destinationString, sourceString
        };
            DynamicApiInvoke("ntdll.dll", "RtlInitUnicodeString", typeof(RtlInitUnicodeString), ref funcargs);
            destinationString = (UNICODE_STRING)funcargs[0];
        }


        public static NTSTATUS LdrLoadDll(IntPtr pathToFile, uint dwFlags, ref UNICODE_STRING moduleFileName, ref IntPtr moduleHandle)
        {
            object[] funcargs =
            {
            pathToFile, dwFlags, moduleFileName, moduleHandle
        };
            var retValue = (NTSTATUS)DynamicApiInvoke("ntdll.dll", "LdrLoadDll", typeof(LdrLoadDll), ref funcargs);
            moduleHandle = (IntPtr)funcargs[3];
            return retValue;
        }


        public static uint DynamicNtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength)
        {
            uint bytesWritten = 0;
            object[] funcargs =
            {
            processHandle, baseAddress, buffer, bufferLength, bytesWritten
        };

            var retValue = (NTSTATUS)DynamicApiInvoke("ntdll.dll", "NtWriteVirtualMemory", typeof(DynamicNtWriteVirtualMemory), ref funcargs);

            if (retValue != NTSTATUS.Success)
                throw new InvalidOperationException("Failed to write memory, " + retValue);

            bytesWritten = (uint)funcargs[4];
            return bytesWritten;
        }


        public static IntPtr DynamicNtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect)
        {
            object[] funcargs =
            {
            processHandle, baseAddress, zeroBits, regionSize, allocationType, protect
        };

            var retValue = (NTSTATUS)DynamicApiInvoke("ntdll.dll", "NtAllocateVirtualMemory", typeof(DynamicNtAllocateVirtualMemory), ref funcargs);

            switch (retValue)
            {
                case NTSTATUS.AccessDenied:
                    throw new UnauthorizedAccessException("Access is denied.");
                case NTSTATUS.AlreadyCommitted:
                    throw new InvalidOperationException("The specified address range is already committed.");
                case NTSTATUS.CommitmentLimit:
                    throw new InvalidOperationException("Your system is low on virtual memory.");
                case NTSTATUS.ConflictingAddresses:
                    throw new InvalidOperationException("The specified address range conflicts with the address space.");
                case NTSTATUS.InsufficientResources:
                    throw new InvalidOperationException("Insufficient system resources exist to complete the API call.");
                case NTSTATUS.InvalidHandle:
                    throw new InvalidOperationException("An invalid HANDLE was specified.");
                case NTSTATUS.InvalidPageProtection:
                    throw new InvalidOperationException("The specified page protection was not valid.");
                case NTSTATUS.NoMemory:
                    throw new InvalidOperationException("Not enough virtual memory or paging file quota is available to complete the specified operation.");
                case NTSTATUS.ObjectTypeMismatch:
                    throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
            }

            if (retValue != NTSTATUS.Success)
                throw new InvalidOperationException("An attempt was made to duplicate an object handle into or out of an exiting process.");

            baseAddress = (IntPtr)funcargs[1];
            return baseAddress;
        }


        public static uint DynamicNtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect)
        {
            uint oldProtect = 0;
            object[] funcargs =
            {
            processHandle, baseAddress, regionSize, newProtect, oldProtect
        };

            var retValue = (NTSTATUS)DynamicApiInvoke("ntdll.dll", "NtProtectVirtualMemory", typeof(DynamicNtProtectVirtualMemory), ref funcargs);

            if (retValue != NTSTATUS.Success)
                throw new InvalidOperationException("Failed to change memory protection, " + retValue);

            oldProtect = (uint)funcargs[4];
            return oldProtect;
        }

        public static void DynamicNtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint freeType)
        {
            object[] funcargs =
            {
            processHandle, baseAddress, regionSize, freeType
        };

            var retValue = (NTSTATUS)DynamicApiInvoke("ntdll.dll", "NtFreeVirtualMemory", typeof(DynamicNtFreeVirtualMemory), ref funcargs);

            switch (retValue)
            {
                case NTSTATUS.AccessDenied:
                    throw new UnauthorizedAccessException("Access is denied.");
                case NTSTATUS.InvalidHandle:
                    throw new InvalidOperationException("An invalid HANDLE was specified.");
            }

            if (retValue != NTSTATUS.Success)
                throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
        }

        /// <summary>
        /// Gets The Syscall if the provided Function by parsing Ntdll 
        /// </summary>
        /// <remarks>Will Not Work With SysWOW/32Bit</remarks>
        /// <param name="FunctionName"></param>
        /// <returns>Pointer to the Syscall, Treat as Function pointer</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static IntPtr GetSyscallStub(string FunctionName)
        {
            // Find the path for ntdll by looking at the currently loaded module
            string NtdllPath = string.Empty;
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                {
                    NtdllPath = Mod.FileName;
                }
            }

            // Alloc module into memory for parsing
            IntPtr pModule = AllocateFileToMemory(NtdllPath);

            // Fetch PE meta data
            PE_META_DATA PEINFO = GetPeMetaData(pModule);

            // Alloc PE image memory -> RW
            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
            UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;

            IntPtr pImage = DynamicNtAllocateVirtualMemory(
                (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            // Write PE header to memory
            UInt32 BytesWritten = DynamicNtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);

            // Write sections to memory
            foreach (IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                // Calculate offsets
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + ish.PointerToRawData);

                // Write data
                BytesWritten = DynamicNtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                if (BytesWritten != ish.SizeOfRawData)
                {
                    throw new InvalidOperationException("Failed to write to memory.");
                }
            }

            // Get Ptr to function
            IntPtr pFunc = GetExportAddress(pImage, FunctionName);
            if (pFunc == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to resolve ntdll export.");
            }

            // Alloc memory for call stub
            BaseAddress = IntPtr.Zero;
            RegionSize = (IntPtr)0x50;
            IntPtr pCallStub = DynamicNtAllocateVirtualMemory(
                (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            // Write call stub
            BytesWritten = DynamicNtWriteVirtualMemory((IntPtr)(-1), pCallStub, pFunc, 0x50);
            if (BytesWritten != 0x50)
            {
                throw new InvalidOperationException("Failed to write to memory.");
            }

            // Change call stub permissions
            DynamicNtProtectVirtualMemory((IntPtr)(-1), ref pCallStub, ref RegionSize, PAGE_EXECUTE_READ);

            // Free temporary allocations
            Marshal.FreeHGlobal(pModule);
            RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;

            DynamicNtFreeVirtualMemory((IntPtr)(-1), ref pImage, ref RegionSize, MEM_RELEASE);

            return pCallStub;
        }





        /* This Section is To Provide an Easy Interface For Development In Which We Have The Functions At Our Disposal */

        public static IntPtr NtProtectVirtualMemory_ptr = GetSyscallStub("NtProtectVirtualMemory");
        /// <summary>
        /// Perform Memory Protections
        /// </summary>
        /// <param name="pHandle"></param>
        /// <param name="Address"></param>
        /// <param name="NtSize"></param>
        /// <param name="AccessMask"></param>
        /// <param name="OldProtection"></param>
        /// <returns></returns>
        public static object NtProtectVirtualMemory(IntPtr pHandle, IntPtr Address, IntPtr NtSize, uint AccessMask, uint OldProtection)
        {
            object[] NtVPArgs = { pHandle, Address, NtSize, AccessMask, OldProtection };
            return DynamicFunctionInvoke(NtProtectVirtualMemory_ptr, typeof(NtProtectVirtualMemory), ref NtVPArgs);
        }

        public static IntPtr NtFreeVirtualMemory_ptr = GetSyscallStub("NtFreeVirtualMemory");
        public static NtFreeVirtualMemory NtFreeVirtualMemory = Marshal.GetDelegateForFunctionPointer<NtFreeVirtualMemory>(NtFreeVirtualMemory_ptr);

        public static IntPtr NtAllocateVirtualMemory_ptr = GetSyscallStub("NtAllocateVirtualMemory");
        public static NtAllocateVirtualMemory NtAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemory>(NtAllocateVirtualMemory_ptr);

        public static IntPtr NtWriteVirtualMemory_ptr = GetSyscallStub("NtWriteVirtualMemory");
        public static NtWriteVirtualMemory NtWriteVirtualMemory = Marshal.GetDelegateForFunctionPointer<NtWriteVirtualMemory>(NtWriteVirtualMemory_ptr);

        public static IntPtr NtReadVirtualMemory_ptr = GetSyscallStub("NtReadVirtualMemory");
        public static NtReadVirtualMemory NtReadVirtualMemory = Marshal.GetDelegateForFunctionPointer<NtReadVirtualMemory>(NtReadVirtualMemory_ptr);

        public static IntPtr NtCreateThreadEx_ptr = GetSyscallStub("NtCreateThreadEx");
        public static NtCreateThreadEx NtCreateThreadEx = Marshal.GetDelegateForFunctionPointer<NtCreateThreadEx>(NtCreateThreadEx_ptr);

        public static IntPtr NtClose_ptr = GetSyscallStub("NtClose");
        public static NtClose NtClose = Marshal.GetDelegateForFunctionPointer<NtClose>(NtClose_ptr);
        
        public static IntPtr NtWaitForSingleObject_ptr = GetSyscallStub("NtWaitForSingleObject");
        public static NtWaitForSingleObject NtWaitForSingleObject = Marshal.GetDelegateForFunctionPointer<NtWaitForSingleObject>(NtWaitForSingleObject_ptr);

        public static IntPtr NtOpenThread_ptr = GetSyscallStub("NtOpenThread");
        public static NtOpenThread NtOpenThread = Marshal.GetDelegateForFunctionPointer<NtOpenThread>(NtOpenThread_ptr);

        public static IntPtr NtCreateSec_ptr = GetSyscallStub("NtCreateSection");
        public static NtCreateSection NtCreateSection = Marshal.GetDelegateForFunctionPointer<NtCreateSection>(NtCreateSec_ptr);

        public static IntPtr NtMapSec_ptr = GetSyscallStub("NtMapViewOfSection");
        public static NtMapViewOfSection NtMapViewOfSection = Marshal.GetDelegateForFunctionPointer<NtMapViewOfSection>(NtMapSec_ptr);

        public static IntPtr NtResumeThread_ptr = GetSyscallStub("NtResumeThread");
        public static NtResumeThread NtResumeThread = Marshal.GetDelegateForFunctionPointer<NtResumeThread>(NtResumeThread_ptr);

        public static IntPtr NtQueryInfoP = GetSyscallStub("NtQueryInformationProcess");
        NtQueryInformationProcess NtQueryInformationProcess = Marshal.GetDelegateForFunctionPointer<NtQueryInformationProcess>(NtQueryInfoP);

        public static IntPtr QueueApc_ptr = GetLibraryAddress("kernel32.dll", "QueueUserAPC");
        public static QueueUserAPC QueueUserAPC = Marshal.GetDelegateForFunctionPointer<QueueUserAPC>(QueueApc_ptr);

        public static IntPtr GetThreadCtx = GetLibraryAddress("kernel32.dll", "GetThreadContext");
        public static GetThreadContext GetThreadContext = Marshal.GetDelegateForFunctionPointer<GetThreadContext>(GetThreadCtx);

        public static IntPtr SetThreadCtx = GetLibraryAddress("kernel32.dll", "SetThreadContext");
        public static SetThreadContext SetThreadContext = Marshal.GetDelegateForFunctionPointer<SetThreadContext>(SetThreadCtx);

        public static IntPtr CreateP = GetLibraryAddress("kernel32.dll", "CreateProcessA");
        public static CreateProcessA CreateProcessA = Marshal.GetDelegateForFunctionPointer<CreateProcessA>(CreateP);

        public static IntPtr WNetUseConnectionA_ptr = GetLibraryAddress("mpr.dll", "WNetUseConnectionA");
        public static WNetUseConnectionA WNetUseConnectionA = Marshal.GetDelegateForFunctionPointer<WNetUseConnectionA>(WNetUseConnectionA_ptr);

    }
}
