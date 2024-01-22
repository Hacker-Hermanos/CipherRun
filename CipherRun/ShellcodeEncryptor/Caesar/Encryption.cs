using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Caesar
{
    public static class Encryption
    {
        // random substitution key
        static Random rnd = new Random();
        public static int substitutionKey = rnd.Next(5, 101);

        public static StringBuilder Encrypt(byte[] buf)
        {
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i<buf.Length; i++)
            {
                encoded[i] = (byte) (((uint) buf[i] + substitutionKey) & 0xFF);
            }

            uint counter = 0;

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("{0:D}, ", b);
                counter++;
                if (counter % 50 == 0)
                {
                    hex.AppendFormat("_{0}", Environment.NewLine);
                }
            }
            return hex;
        }
    }
}
