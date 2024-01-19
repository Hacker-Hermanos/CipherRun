# CipherRun

CipherRun is a tool designed to automate common hacking techniques for ethical hacking and penetration testing purposes. This toolkit focuses on evading antivirus solutions through the use of heuristics bypasses, encryption, and different shellcode running techniques.

## Contents

- **CipherRun.cs**: Contains the main program logic.
  - Calls `heuristic.Sleep` to bypass behavioral detection.
  - Encrypts the payload located in `Shellcode.cs` using `Caesar.Encryption.Encrypt`.
  - Passes the encrypted payload to `Caesar.Injection.Inject` or `Caesar.ProcessHollow.Hollow` (these are the shellcode runner files).
  - The runner file decrypts the payload using `Caesar.Encryption.Decrypt` and executes the instructions.

- **Shellcode.cs**: Contains the payload to be utilized. Paste your payload here.

- **Heuristics Folder (Heuristics Namespace)**:
  - **Sleep.cs**: Implements a heuristic sleep function to bypass behavioral detections.

- **Caesar Folder (Caesar Namespace)**:
  - **Encryption.cs**: Contains Caesar encryption and decryption routines.
  - **Injection.cs**: Contains a shellcode running function which injects into `explorer.exe`.
  - **ProcessHollow.cs**: Contains a shellcode running function which performs process hollowing.

## Usage

1. Clone the repository: `git clone https://github.com/Hacker-Hermanos/CipherRun.git`

2. Add your shellcode into `Shellcode.cs`. Select your preferred shellcode runner in `CipherRun.cs`

3. Compile the project using Visual Studio.

4. Start your listener

5. Run the compiled executable on the victim machine.

**Note**: This tool is intended for educational and ethical hacking purposes only. Ensure that you have appropriate authorization before using it in any environment.

## Contribution

Contributions to enhance and expand the functionality of this toolkit are highly encouraged. If you have ideas for additional features, improvements, or bug fixes, please submit a pull request.

## Disclaimer

This toolkit is provided for educational and ethical hacking purposes only. The author is not responsible for any misuse or damage caused by the use of this software. Use it responsibly and with proper authorization.

## Credits

This project was inspired by [Apophis](https://github.com/tasox/Apophis). We would like to extend our gratitude to the creators of Apophis for their innovative work, which served as a foundation and inspiration for this tool.
