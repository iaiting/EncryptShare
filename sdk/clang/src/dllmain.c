
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // printf("\nprocess attach of dll");
            break;
        case DLL_THREAD_ATTACH:
            // printf("\nthread attach of dll");
            break;
        case DLL_THREAD_DETACH:
            // printf("\nthread detach of dll");
            break;
        case DLL_PROCESS_DETACH:
            // printf("\nprocess detach of dll");
            break;
    }
    return TRUE;
}