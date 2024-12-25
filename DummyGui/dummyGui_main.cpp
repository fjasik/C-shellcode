#include <windows.h>

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CLOSE:
        {
            PostQuitMessage(0); // Signal the application to exit
            return 0;
        }
        case WM_DESTROY:
        {
            PostQuitMessage(0); // Ensure cleanup
            return 0;
        }
        default:
        {
            return DefWindowProc(hwnd, msg, wParam, lParam);
        }
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"DummyGuiClass";

    if (!RegisterClass(&wc)) {
        return GetLastError();
    }

    HWND hwnd = CreateWindowEx(
        0,
        wc.lpszClassName,
        L"Minimal Window",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 300,
        nullptr,
        nullptr,
        hInstance,
        nullptr);

    if (!hwnd) {
        return GetLastError();
    }

    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
    UpdateWindow(hwnd);

    MSG msg = { 0 };
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}