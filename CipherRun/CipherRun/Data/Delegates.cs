using System;
using System.Runtime.InteropServices;
using static CipherRun.Data.Enums;
using static CipherRun.Data.Structs;


namespace CipherRun.Data
{
    /// <summary>
    /// This Class Contains Function Delegates For Use With Dynamic Importations
    /// </summary>
    public class Delegates
    {
        public delegate bool CreateProcessA(
        IntPtr lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcAttribs,
        IntPtr lpThreadAttribs,
        bool bInheritHandles,
        uint dwCreateFlags,
        IntPtr lpEnvironment,
        IntPtr lpCurrentDir,
        [In] ref STARTUPINFO lpStartinfo,
        out PROCESSINFORMATION lpProcInformation
        );

        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            out PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen,
            ref uint retlen
            );


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWriteVirtualMemory(
            IntPtr ProcessHandle, 
            IntPtr BaseAddress, IntPtr Buffer, 
            uint NumberOfBytesToWrite, 
            ref uint NumberOfBytesWritten
            );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            uint NumberOfBytesToRead,
            ref uint NumberOfBytesRead);


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtOpenThread(
            IntPtr ThreadHandle,
            uint DesiredAccess, /*Example: THREAD_ALL_ACCESS = 0x1F03FF*/
            OBJECT_ATTRIBUTES ObjectAttributes,
            CLIENT_ID ClientId
            );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtResumeThread(
            IntPtr ThreadHandle,
            ref int PreviousSuspendCount);


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int AmsiInitialize(
            string name,
            out Int64 context
        );

        /// <summary>
        /// DO NOT Use This Delegate Directly, It Won't Work, Use Only with DynamicApiInvoke, Or use The Predefined Function
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtProtectVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            MEMORY_PROTECTION newProtect,
            ref MEMORY_PROTECTION oldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void NtMapViewOfSection(
        IntPtr SectionHandle,
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,// OPTIONAL
        ulong ZeroBits, // OPTIONAL
        ulong CommitSize,
        IntPtr SectionOffset, //OPTIONAL,
        ref ulong ViewSize,
        int InheritDisposition, // 
        ulong AllocationType,//OPTIONAL,
        ulong Protect
        );


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void NtCreateSection(
            ref IntPtr section, 
            uint desiredAccess, 
            IntPtr pAttrs, 
            ref long pMaxSize, 
            uint pageProt, 
            uint allocationAttribs, 
            IntPtr hFile
            );


        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Auto)]
        public unsafe delegate bool GlobalMemoryStatusEx(
        [In, Out] MEMORYSTATUSEX* lpbuffer
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr VitualAllocExNuma(
            IntPtr ptr,
            IntPtr ptr1,
            uint int1,
            uint int2,
            uint int3,
            uint int4
        );


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtFreeVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint freeType
        );


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateThreadEx(
            ref IntPtr threadHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr NtWaitForSingleObject(IntPtr HANDLE, bool BOOL, IntPtr Handle);


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
        IntPtr processHandle, 
        ref IntPtr allocatedAddress, 
        IntPtr zeroBits, 
        ref IntPtr regionSize, 
        uint allocationType,
        uint memoryProtection
        );


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr NtClose(IntPtr HANDLE);


        
        public delegate uint QueueUserAPC(
            IntPtr pfnAPC, 
            IntPtr hThread, 
            ulong dwData /* ulong NULL pointer, in C#: (ulong)IntPtr.Zero.ToInt64();*/ 
            );


        public delegate bool GetThreadContext(IntPtr hThread, ref CONTEXT64 context);

        public delegate bool SetThreadContext(IntPtr hThread, ref CONTEXT64 context);


       public delegate int WNetUseConnectionA(
            IntPtr hwndOwner,
            NETRESOURCE lpNetResource,
            string lpPassword,
            string lpUserID,
            int dwFlags,
            string lpAccessName,
            string lpBufferSize,
            string lpResult
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint LdrLoadDll(
            IntPtr pathToFile,
            uint dwFlags,
            ref UNICODE_STRING moduleFileName,
            ref IntPtr moduleHandle);



        /* Delegates Defined Here are Using in CypherRun.Helpers.Methods only */
        /* 
         Sometimes We Need To call the Same Function With Entirely Different Data Types While The Function is Ok with It
         C# Is Not and We Need To Specifically Tell it That its ok

        the funtion pointer is the same, different Delegate --__("")__-- im not crazy, they made me....
         */


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DynamicNtFreeVirtualMemory(
        IntPtr processHandle,
        ref IntPtr baseAddress,
        ref IntPtr regionSize,
        uint freeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DynamicNtProtectVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint newProtect,
            ref uint oldProtect);


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DynamicNtAllocateVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            IntPtr zeroBits,
            ref IntPtr regionSize,
            uint allocationType,
            uint protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DynamicNtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref uint bytesWritten);


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(
            ref UNICODE_STRING destinationString,
            [MarshalAs(UnmanagedType.LPWStr)]
            string sourceString);



        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void DynamicRtlZeroMemory(
                    IntPtr destination,
                    int length);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint DynamicNtQueryInformationProcess(
            IntPtr processHandle,
            PROCESSINFOCLASS processInformationClass,
            IntPtr processInformation,
            int processInformationLength,
            ref uint returnLength);

        /// <summary>
        /// ReadGs is actually a Macro thats used to execute in-line assembly instruction to return a pointer to PEB
        /// </summary>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr ReadGs();

    }
}
