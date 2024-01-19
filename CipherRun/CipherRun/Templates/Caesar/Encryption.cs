using System;

namespace Caesar
{
	public class Encryption
	{
		// VARS
		// substitution key -> TO-DO: randomize key!
		static Random rnd = new Random();
		public static int substitutionKey = rnd.Next(5, 101);

		// METHODS
		public static byte[] Encrypt(byte[] buf)
		{
			// Caesar Encryption Routine
			byte[] encoded = new byte[buf.Length];

			for (int i = 0; i < buf.Length; i++)
			{

				encoded[i] = (byte)(((uint)buf[i] + substitutionKey) & 0xFF);
			}
			return encoded;
			/*
				DEBUGGING STUFF

				StringBuilder hex = new StringBuilder(encoded.Length * 2);
				foreach (byte b in encoded)
				{
					hex.AppendFormat("0x{0:x2}, ", b);
				}
				Console.WriteLine($"The payload size is {encoded.Length} bytes: " + hex.ToString());
				// Console.WriteLine(hex.ToString());
			*/
		}
		public static byte[] Decrypt(byte[] buf)
		{
			// Caesar Decryption Routine
			for (int i = 0; i < buf.Length; i++)
			{

				buf[i] = (byte)(((uint)buf[i] - substitutionKey) & 0xFF);
			}
			return buf;
			/*
				DEBUGGING STUFF

				StringBuilder hex = new StringBuilder(encoded.Length * 2);
				foreach (byte b in encoded)
				{
					hex.AppendFormat("0x{0:x2}, ", b);
				}
				Console.WriteLine($"The payload size is {encoded.Length} bytes: " + hex.ToString());
				// Console.WriteLine(hex.ToString());
			*/
		}

	}
}
