#pragma once

#define MAVI_EXPORT extern "C" __declspec(dllexport)

MAVI_EXPORT void __cdecl StartServiceWorker();
MAVI_EXPORT void __cdecl StopServiceWorker();
