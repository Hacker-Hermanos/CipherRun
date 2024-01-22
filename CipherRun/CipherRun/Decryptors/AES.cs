using System;
using System.Security.Cryptography;
using System.IO;

namespace CipherRun.Decryptors
{
    /// <summary>
    /// AES Decryption
    /// </summary>
    public class AES
    {
        /// <summary>
        /// This Function Takes in an AES Encrypted Buffer and The Key/IV Used in Encryption and Returns The Decrypted Buffer
        /// </summary>
        /// <param name="EncryptedBuffer"></param>
        /// <param name="AesKey"></param>
        /// <param name="AesIV"></param>
        /// <returns>The Decrypted Data</returns>
        public static byte[] Decrypt(byte[] EncryptedBuffer, string AesKey, string AesIV) {

            using (AesManaged aes = new AesManaged())
            {
                aes.Key = System.Text.Encoding.UTF8.GetBytes(AesKey);
                aes.IV = System.Text.Encoding.UTF8.GetBytes(AesIV);
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.Zeros;

                ICryptoTransform aes_decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream Encryptedms = new MemoryStream(EncryptedBuffer))
                {
                    using (MemoryStream Decryptedms = new MemoryStream())
                    {

                        using (CryptoStream cs = new CryptoStream(Encryptedms, aes_decryptor, CryptoStreamMode.Read))
                        {
                            cs.CopyTo(Decryptedms);
                        }

                        byte[] decrypted_buff = Decryptedms.ToArray();
                        return decrypted_buff;
                    }

                }
            }
        }

    }
}
