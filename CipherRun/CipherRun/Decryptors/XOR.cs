using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CipherRun.Decryptors
{
    public class XOR
    {
        /// <summary>
        /// Takes In The XOR Encrypted Data and a Key and returns the decrypted data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <remarks>XOR is always and will always be unstable</remarks>
        /// <returns>byte array containing the decrypted data</returns>
        public static byte[] Decrypt(byte[] data, byte[] key) {
            int dataLength = data.Length;
            int keyLength = key.Length;

            byte[] decryptedData = new byte[dataLength];

            for (int i = 0; i < dataLength; i++)
            {
                decryptedData[i] = (byte)(data[i] ^ key[i % keyLength]);
            }

            return decryptedData;
        }
    }
}
