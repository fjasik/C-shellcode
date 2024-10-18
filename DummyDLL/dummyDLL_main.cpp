#include <Windows.h>

#include <iostream>
#include <thread>

void MainFunction() {
    std::cout << "Hi" << std::endl;

    MessageBoxA(NULL, "Dummy DLL", "Main function got loaded", MB_ICONINFORMATION);

    std::cout << "Bye" << std::endl;
}

// I know you're not meant to start threads in a dll main but, I don't care
// The official Microsoft documentation says:
// > You should never perform the following tasks from within DllMain: [...]
// > Call CreateThread. Creating a thread can work if you do not 
// > synchronize with other threads, but it is risky.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    std::cout << "DllMain called with reason: " << reason << std::endl;

    switch (reason) {
        case DLL_PROCESS_ATTACH:
        {
            auto thread = std::thread(&MainFunction);
            thread.detach();

            break;
        }
    }

    return TRUE;
}