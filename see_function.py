import sys
from capstone import *
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)

WINDOWS_API_LIST = [
    # Process Creation and Manipulation
    "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW", "CreateProcessWithTokenW", 
    "NtCreateProcess", "NtCreateProcessEx", "RtlCreateUserThread", "OpenProcess", "TerminateProcess", 
    "SuspendThread", "ResumeThread",

    # Process Injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory", 
    "ReadProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "SetThreadContext", 
    "QueueUserAPC", "GetThreadContext",

    # DLL Injection and Loading
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", 
    "LdrLoadDll", "LdrGetProcedureAddress",

    # Memory Manipulation
    "VirtualQuery", "VirtualQueryEx", "NtAllocateVirtualMemory", "NtFreeVirtualMemory", 
    "NtProtectVirtualMemory", "MapViewOfFile", "UnmapViewOfFile",

    # File Operations
    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "DeleteFileA", "DeleteFileW", 
    "SetFileAttributesA", "SetFileAttributesW", "CopyFileA", "CopyFileW",

    # ... (remaining API functions)
]

def load_binary(file_path):
    """Load the binary file into memory."""
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except IOError as e:
        print(f"Error reading binary file: {e}")
        sys.exit(1)

def disassemble_binary(binary_code):
    """Disassemble the binary code using Capstone."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)  # Change to CS_MODE_64 for 64-bit binaries
    md.detail = True
    instructions = []
    
    for instruction in md.disasm(binary_code, 0x1000):
        instructions.append(instruction)
    
    return instructions

def extract_api_calls(instructions):
    """Extract API calls from disassembled instructions."""
    api_calls = []
    
    for instruction in instructions:
        if instruction.mnemonic == "call":
            # Extract the function name, if it's a recognized API call
            api_func_name = instruction.op_str.split(' ')[-1]
            if api_func_name in WINDOWS_API_LIST:
                api_calls.append(api_func_name)
    
    return api_calls

def main(binary_file):
    # Load the binary file into memory
    binary_code = load_binary(binary_file)
    
    # Disassemble the binary code
    instructions = disassemble_binary(binary_code)
    
    # Extract API calls
    api_calls = extract_api_calls(instructions)
    
    # Output the API calls in a cool, user-friendly way
    if api_calls:
        print(Fore.CYAN + Style.BRIGHT + "\n🎯  Detected API Calls:")
        print(Fore.YELLOW + "-" * 40)
        for api_call in api_calls:
            print(Fore.GREEN + f" - {api_call}")
        print(Fore.YELLOW + "-" * 40 + "\n")
        print(Fore.CYAN + Style.BRIGHT + "✔️ Analysis complete. Suspicious API calls detected.")
    else:
        print(Fore.RED + Style.BRIGHT + "\n🔍 No known suspicious API calls detected.")
        print(Fore.CYAN + Style.BRIGHT + "✔️ Analysis complete. Your binary looks clean (at least from our API list perspective).")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_binary>")
        sys.exit(1)
    
    binary_file = sys.argv[1]
    main(binary_file)
