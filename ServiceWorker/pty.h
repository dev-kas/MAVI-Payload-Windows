#pragma once

#include <iostream>
#include <string>
#include <functional>
#include <Windows.h>
#include <vector>
#include <thread>
#include <atomic>

class PTY {
public:
	using DataCallback = std::function<void(const std::string&)>;

	PTY();
	~PTY();

	bool spawn(const std::string& cmd, const std::string& args);
	void write(const std::string& data);
	void on(const std::string& event, DataCallback callback);
	void close();
	bool isRunning() const;

private:
	HANDLE hChildStdinRd, hChildStdinWr, hChildStdoutRd, hChildStdoutWr, hChildStderrRd, hChildStderrWr;
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	DataCallback dataCallback;
	DataCallback errorCallback;
	std::atomic<bool> running;
	std::thread stdoutReadThread;
	std::thread stderrReadThread;

	// helpers
	bool createPipes();
	void closePipes();
	void readFromPipe();
	void readFromStderrPipe();
};
