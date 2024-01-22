using System;
using System.Runtime.InteropServices;
using static CipherRun.Helpers.Methods;

namespace CipherRun.Heuristics
{
    /// <summary>
    /// This Class Contains Anti Debuggers That Might "Deceit" an Automated Debugger
    /// </summary>
    public class AntiDebug
    {

        /// <summary>
        /// This Function Reads The Second Field From The PEB Structure, if the Field is 1 We Are Debugged, if 0 We Are "safe"
        /// </summary>
        /// <remarks>Leaving the Action To Be Takan if Being Debugged Flexible, Just Returns an Indicator</remarks>
        /// <returns>True If a Debugger Is Attached, False If a Debuuger is Not Attached</returns>
        public static bool IsBeingDebugged() {
            IntPtr peb = GetPebAddress(); // retrives the base of the PEB structure with an in-line assembly call

            byte Dattached = Marshal.ReadByte(peb, 2);

            if (Dattached != 0)
            {
                return true; // Being Debugged
            }
            return false;

        }

    }
}
