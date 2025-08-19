#pragma once

#include <string>
#include <Windows.h>
#include <memory>

// Base Functionality from the original code

struct DeviceInfo {
	std::string os;
	std::string arch;
	std::string name;
	std::string scrRes;
	std::string deviceType;
	std::string deviceUUID;
	uint64_t ram;
	bool inVM;
};

std::shared_ptr<DeviceInfo> get_info();
rapidjson::Document to_json(const DeviceInfo& device);
std::string json_to_string(rapidjson::Document& doc);

// utilities

std::string getOS();
std::string getArch();
std::string getDeviceName();
uint64_t getRAM();
std::string getScreenRes();
bool isRunningInVM();
std::string getDeviceUUID();
std::string getDeviceType();
