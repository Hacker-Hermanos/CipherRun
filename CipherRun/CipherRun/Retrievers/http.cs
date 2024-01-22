using System;
using System.Net;

namespace CipherRun.Retrievers
{
    /// <summary>
    /// this is a simple class that contains a http downloader function
    /// </summary>
    public class Http
    {

        /// <summary>
        /// Downloads from a given url, The Return Type is a byte[] to be Flexible with any sort of data being downloaded
        /// </summary>
        /// <param name="url"></param>
        /// <returns>byte array containing the data</returns>
        public static byte[] GetPayload(string url) {
            using (WebClient cl = new()) {
                byte[] data = new byte[]{ };
                try
                {
                    data = cl.DownloadData(url);

                }catch (Exception ex) { Console.WriteLine($"[-] Error occured during downloading: {ex.Message}"); }

                return data;
            }
        }
    }
}
