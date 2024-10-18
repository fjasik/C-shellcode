# Shellcode in C experiments

## About

This project serves the purpose of demonstrating the creation of position independent shellcode in C. To achieve that, the specifically written C code is compiled down to assembly, which is then edited and manually linked in to an exe. After extracting the executable section, it is ready to be injected into any process. At least that's the theory.

## Solution structure

This is a standard VS2019 solution, however not all projects are compilable. The structure is as follows:
- `C-Shellcode`: This is the main shellcode-writing playground. It heavily uses the shamelessly stolen `peb_lookup.h` to import Win32 functions without the use of LoadLibrary (since in a shellcode, we don't have access to it, nor the CRT). The following shellcodes exist:
    - `test_debug.c`: Demonstrates the shellcode debug printing. Retrieves the necessary functions by name.
    - `test_string.c`: Demonstrates how to use shellcode debug printing, fetch handles and function pointers with stack based strings, and call MessageBoxA correctly. Needs to be running inside of a process that has `user32.dll` loaded.
    - `test_hash.c`: Similar to `test_string.c`, but uses precalculated hash values to fetch handles and function pointers.
    - `websocket.c`: When injected, it opens a socket to a remote IP address, fetches a size number, allocates memory of given size, fetches the payload of given size into memory and finally simply executes it. Note, it has to be injected into a process that has `Ws2_32.dll` loaded.
    - `reflective_loader.c`: This shellcode, when concatenated with a DLL, loads it in-memory and invokes its DllMain.
    - `spawn.c`: Spawns `cmd.exe` with redirected IO to custom named pipes
    - `inject.c`: Injects shellcode that is concatenated to its end into another hardcoded process
- `DummyDLL`: Just a dummy test DLL to verify that the loading process was a success. It spawns a thread that prints to console and shows a message box.
- `DummyWinsock2App`: A dummy test application that loads `Ws2_32.dll`, opens a socket and does nothing. Useful to inject into.
- `ShellcodeInjector`: A classic shellcode injector app that uses `WriteProcessMemory` and `CreateRemoteThread` to inject shellcode into a remote process.
- `SelfInjector`: An even more simpler app that loads the shellcode into itself, useful for debugging.

There is also the `Auxilary` folder which contains a couple of important helper scripts:
- `amend_asm_x86.py` and `amend_asm_x64.py`: Python scripts that amend the  assembly generated by the MSVC compiler. It removes all external links and makes sure the executable section of the fully linked exe can simply be extracted and ran. The x64 version also injects a stack aligning procedure to be ran before main.
- `compile_c_shellcode.ps1`: A Powershell script that compiles the `.c` file into an executable, from which the shellcode is extracted. Choose the correct architecture, whether to add debug printing and use optimization. Note, you need to run this from the `Developer PowerShell for VS 2019` and the architecture must match: you will not be able to compile x86 shellcodes from the x64 powershell.
- `concat_binaries.py`: A small Python script to concatenate 2 binary files, useful to create the reflective DLL as one needs to concatenate the reflective loader with the DLL.
- `extract_text_section.py`: A small Python script that parses the executable and extracts its text section, then saves it to a file.
- `hash_string.py`: A Python script to generate hash values for dll and function names, used to import dlls and functions by hash, rather than name. Note that dll names should use the lowercase hash.
- `inject_shellcode.ps1`: A Powershell script to inject shellcode into a process (can be caught by defender).
- `server.py`: A very simple Python server that opens a socket, waits for something to bind to it (like, what `websocket.c` does), then sends 2 messages: first the size of the payload, and then the payload itself. It then exits.

## Compilation

### 32-bit

To compile an example shellcode:
- Open the `x86 Native Tools Command Prompt for VS 2019`, or the powershell equivalent
- Navigate to the root of the repository
- Invoke the compilation script
    - `.\Auxilary\compile_c_shellcode.ps1 .\C-Shellcode\test_string.c -Architecture Win32`
        - Use `-DebugPrint` to allow the shellcode to print debug messages
        - Use `-Optimize` to let the compiler optimize the code (might not work, be careful)
- Profit

### 64-bit

To compile an example shellcode, very similarly to the 32 bit example:
- Open the `Developer PowerShell for VS 2019`, or the powershell equivalent
- Navigate to the root of the repository
- Invoke the compilation script
    - `.\Auxilary\compile_c_shellcode.ps1 .\C-Shellcode\test_string.c -Architecture x64`
        - Use `-DebugPrint` and `-Optimize` if you want to
- Profit

## Example usage (32 bit)

### Preparation

Prepare the malicious code:
- Build the solution
    - Right click `Build Solution` in Visual Studio in `Win32` mode
- Compile and build the shellcodes
    - Open the `x86 Native Tools Command Prompt for VS2019`, or the powershell equivalent
        - `.\Auxilary\compile_c_shellcode.ps1 .\C-Shellcode\websocket.c -Architecture Win32 -DebugPrint`
        - `.\Auxilary\compile_c_shellcode.ps1 .\C-Shellcode\reflective_loader.c -Architecture Win32 -DebugPrint`
            - Note, when compiling `reflective_loader.c`, make sure to check that the size of the generated shellcode matches the constant `kShellcodeLength` in the code.
- Concatenate the `reflective_loader` shellcode with a dummy DLL
    - `python3 .\Auxilary\concat_binaries.py .\out\shellcode\bin\reflective_loader_dbg_x86.bin .\out\bin\Win32\Debug\DummyDLL.dll`

### Execution

Run it:
- Start the websocket server and make it serves the `reflective_loader` shellcode concatenated with the DLL
    - `python3 .\Auxilary\server.py .\concat.bin`
- Start the dummy Winsock2 application
    - `.\out\bin\Win32\Debug\DummyWinsock2App.exe`
- Inject the `websocket` shellcode into the dummy Winsock2 application
    - `.\out\bin\Win32\Debug\ShellcodeInjector.exe .\out\shellcode\bin\websocket_dbg_x86.bin DummyWinsock2App.exe`

### What happens ?

The attack chain is therefore as follows:
- The `websocket` shellcode is executed in the `DummyWinsock2App.exe`
- A socket is immidiately opened connecting to the python server
- `concat.bin` is downloaded, which is the `DummyDLL.dll` glued with the `reflective_loader` shellcode
- The `reflective_loader` shellcode is executed, which loads `DummyDLL.dll`
- `DllMain` is called and the main thread is initialised
- A message box is spawned, from the DLL

## Compilaition status

### Table

| Shellcode status  | **x86**   |             |               | **x64**   |             |               |
|-------------------|-----------|-------------|---------------|-----------|-------------|---------------|
|                   | **Debug** | **Vanilla** | **Optimized** | **Debug** | **Vanilla** | **Optimized** |
| test_debug        | ok        | ok          | ok            | ok        | ok          | ok            |
| test_string       | ok        | ok          | ok            | ok        | ok          | ok            |
| test_hash         | ok        | ok          | ok            | ok        | ok          | ok            |
| websocket         | ok        | ok          | interactv req | ok        | ok          | ok            |
| reflective_loader | ok        | ok          | ok | compiles but crashes |             |               |
| spawn             |           |             |               |           |             |               |
| inject            |           |             |               |           |             |               |

### Notes

- websocket x86 optimized shellcode needs to be compiled with -Interactive flag, manual edit of the generated assembly is required. MSVC seems to add 2 `voltbl ` code segments that are never referenced, and fail the compilation. Need to remove them.

## To do

- Fix x64 `reflective_loader` shellcode compilation and running
- Fix `

## Disclaimer

I don't know enough about shellcodes to tell you whether the shellcode is good, bad or whatever. This project greatly facilitates the writing of a shellcode, without touching assembly. You still have to adhere to certain rules, for example, all strings have to be stack based, can't have external dependencies... Read the references to know what you can and can't do.

This project is a proof of concept, not designed for anything in particular, be careful when using it.

## References

- https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c
- https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf