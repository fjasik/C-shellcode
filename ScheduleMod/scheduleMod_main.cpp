#include <Windows.h>
#include <thread>
#include "detours.h"

namespace Pingwin::Schedule1 {

    static constexpr auto kOffset_Update = 0x8EE340;
    static constexpr auto kOffset_BackgroundImage = 0x88;
    static constexpr auto kOffset_LabelGroup = 0x90;
    static constexpr auto kOffset_SetActive = 0x29ACC20;
    static constexpr auto kOffset_GameObject = 0x10;

    using Update_t = void(__fastcall*)(void* thisPtr);
    Update_t oUpdate = nullptr;

    using SetActive_t = void(__fastcall*)(void* gameObject, bool active);
    SetActive_t SetGameObjectActive = nullptr;

    void* mapAppInstance = nullptr;
    bool mapDisplayed = false;

    uintptr_t GameAssemblyBase() {
        static const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA("GameAssembly.dll"));
        return base;
    }

    void TryForceMapVisible() {
        if (mapDisplayed || mapAppInstance == nullptr || SetGameObjectActive == nullptr) {
            return;
        }

        const auto backgroundImagePtr = *reinterpret_cast<void**>(
            reinterpret_cast<uintptr_t>(mapAppInstance) + kOffset_BackgroundImage
            );

        if (backgroundImagePtr != nullptr) {
            const auto gameObject = *reinterpret_cast<void**>(
                reinterpret_cast<uintptr_t>(backgroundImagePtr) + kOffset_GameObject
                );

            if (gameObject != nullptr) {
                SetGameObjectActive(gameObject, true);
            }
        }

        const auto labelGroupPtr = *reinterpret_cast<void**>(
            reinterpret_cast<uintptr_t>(mapAppInstance) + kOffset_LabelGroup
            );

        if (labelGroupPtr != nullptr) {
            const auto gameObject = *reinterpret_cast<void**>(
                reinterpret_cast<uintptr_t>(labelGroupPtr) + kOffset_GameObject
                );

            if (gameObject != nullptr) {
                SetGameObjectActive(gameObject, true);
            }
        }

        mapDisplayed = true;
    }

    void __fastcall hkUpdate(void* thisPtr) {
        if (mapAppInstance == nullptr) {
            mapAppInstance = thisPtr;
        }

        TryForceMapVisible();

        oUpdate(thisPtr);
    }

    void HookMapAppUpdate() {
        const uintptr_t updateAddr = GameAssemblyBase() + kOffset_Update;
        oUpdate = reinterpret_cast<Update_t>(updateAddr);

        SetGameObjectActive = reinterpret_cast<SetActive_t>(GameAssemblyBase() + kOffset_SetActive);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(reinterpret_cast<PVOID*>(&oUpdate), hkUpdate);
        DetourTransactionCommit();
    }

    void MainFunction() {
        HookMapAppUpdate();
    }

} // namespace Pingwin::Schedule1

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        std::thread(Pingwin::Schedule1::MainFunction).detach();
    }
    return TRUE;
}
