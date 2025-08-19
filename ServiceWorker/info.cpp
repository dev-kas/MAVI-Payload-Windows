#include "pch.h"

#include <Windows.h>
#include <VersionHelpers.h>
#include <string>
#include <iostream>
#include <memory>

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#include "info.h"

std::string getOS() {
    std::string osVersion;

    if (IsWindows10OrGreater()) {
        osVersion = "Windows 10 or later";
    }
    else if (IsWindows8Point1OrGreater()) {
        osVersion = "Windows 8.1 or later";
    }
    else if (IsWindows8OrGreater()) {
        osVersion = "Windows 8 or later";
    }
    else if (IsWindows7OrGreater()) {
        osVersion = "Windows 7 or later";
    }
    else if (IsWindowsVistaOrGreater()) {
        osVersion = "Windows Vista or later";
    }
    else {
        osVersion = "Windows XP or earlier";
    }

    return osVersion;
}

std::string getArch() {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x86-64 (AMD64)" : "x86 (32-bit)";
}

std::string getDeviceName() {
    char name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(name);
    GetComputerNameA(name, &size);
    return std::string(name);
}

uint64_t getRAM() {
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    GlobalMemoryStatusEx(&status);
    return status.ullTotalPhys;
}

std::string getScreenRes() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    return std::to_string(width) + "x" + std::to_string(height);
}

bool isRunningInVM() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    char buffer[128];
    DWORD size = sizeof(buffer);
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "SystemManufacturer", nullptr, nullptr, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            std::string manufacturer(buffer);
            if (manufacturer.find("VMware") != std::string::npos ||
                manufacturer.find("VirtualBox") != std::string::npos ||
                manufacturer.find("QEMU") != std::string::npos) {
                RegCloseKey(hKey);
                return true;
            }
		}
		RegCloseKey(hKey);
    }
	return false;
}

std::string getDeviceUUID() {
    char uuid[128] = {};
    DWORD size = sizeof(uuid);
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, (LPBYTE)uuid, &size);
        RegCloseKey(hKey);
    }
    return std::string(uuid);
}

std::string getDeviceType() {
    // this is simplified, because due to heuristics,
    // windows can only run on desktop/laptops, so this has been hardcoded.
    return "desktop";
}

rapidjson::Document to_json(const DeviceInfo& device) {
    rapidjson::Document doc;
    doc.SetObject();
	rapidjson::Document::AllocatorType& allocator = doc.GetAllocator();

	doc.AddMember("os", rapidjson::Value().SetString(device.os.c_str(), allocator), allocator);
	doc.AddMember("arch", rapidjson::Value().SetString(device.arch.c_str(), allocator), allocator);
	doc.AddMember("name", rapidjson::Value().SetString(device.name.c_str(), allocator), allocator);
	doc.AddMember("scrRes", rapidjson::Value().SetString(device.scrRes.c_str(), allocator), allocator);
	doc.AddMember("deviceType", rapidjson::Value().SetString(device.deviceType.c_str(), allocator), allocator);
	doc.AddMember("deviceUUID", rapidjson::Value().SetString(device.deviceUUID.c_str(), allocator), allocator);
	doc.AddMember("ram", device.ram, allocator);
	doc.AddMember("isVM", device.inVM, allocator);

	return doc;
}

std::string json_to_string(rapidjson::Document& doc) {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);
    return buffer.GetString();
}

std::shared_ptr<DeviceInfo> get_info() {
	auto info = std::make_shared<DeviceInfo>();

	info->os = getOS();
	info->arch = getArch();
	info->name = getDeviceName();
	info->scrRes = getScreenRes();
	info->deviceType = getDeviceType();
	info->deviceUUID = getDeviceUUID();
	info->ram = getRAM();
	info->inVM = isRunningInVM();

	return info;
}
