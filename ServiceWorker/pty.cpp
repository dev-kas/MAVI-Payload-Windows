#include "pch.h"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <future>

#include "pty.h"

PTY::PTY() : hChildStdinRd(INVALID_HANDLE_VALUE), hChildStdinWr(INVALID_HANDLE_VALUE),
	hChildStdoutRd(INVALID_HANDLE_VALUE), hChildStdoutWr(INVALID_HANDLE_VALUE),
	hChildStderrRd(INVALID_HANDLE_VALUE), hChildStderrWr(INVALID_HANDLE_VALUE),
	running(false)
{
	ZeroMemory(&si, sizeof(STARTUPINFOA));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOA);
}

PTY::~PTY() {
	close(); // ensure shutdown is signaled

	// wait for threads to finish before object is destroyed
	if (stdoutReadThread.joinable()) stdoutReadThread.join();
	if (stderrReadThread.joinable()) stderrReadThread.join();
}

bool PTY::createPipes() {
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// stdin
	if (!CreatePipe(&hChildStdinRd, &hChildStdinWr, &saAttr, 0)) {
		std::cerr << "Stdin CreatePipe failed." << std::endl;
		return false;
	}
	if (!SetHandleInformation(hChildStdinWr, HANDLE_FLAG_INHERIT, 0)) {
		std::cerr << "Stdin SetHandleInformation failed." << std::endl;
		return false;
	}
	// stdout
	if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0)) {
		std::cerr << "Stdout CreatePipe failed." << std::endl;
		return false;
	}
	if (!SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0)) {
		std::cerr << "Stdout SetHandleInformation failed." << std::endl;
		return false;
	}
	// stderr
	if (!CreatePipe(&hChildStderrRd, &hChildStderrWr, &saAttr, 0)) {
		std::cerr << "Stderr CreatePipe failed." << std::endl;
		return false;
	}
	if (!SetHandleInformation(hChildStderrRd, HANDLE_FLAG_INHERIT, 0)) {
		std::cerr << "Stderr SetHandleInformation failed." << std::endl;
		return false;
	}
	return true;
}

void PTY::closePipes() {
	// stdin
	if (hChildStdinRd != INVALID_HANDLE_VALUE) CloseHandle(hChildStdinRd);
	if (hChildStdinWr != INVALID_HANDLE_VALUE) CloseHandle(hChildStdinWr);

	// stdout
	if (hChildStdoutRd != INVALID_HANDLE_VALUE) CloseHandle(hChildStdoutRd);
	if (hChildStdoutWr != INVALID_HANDLE_VALUE) CloseHandle(hChildStdoutWr);

	// stderr
	if (hChildStderrRd != INVALID_HANDLE_VALUE) CloseHandle(hChildStderrRd);
	if (hChildStderrWr != INVALID_HANDLE_VALUE) CloseHandle(hChildStderrWr);

	hChildStdinRd = hChildStdinWr = hChildStdoutRd = hChildStdoutWr = hChildStderrRd = hChildStderrWr = INVALID_HANDLE_VALUE;
}

bool PTY::spawn(const std::string& cmd, const std::string& args) {
	if (running) {
		std::cerr << "PTY is already running." << std::endl;
		return false;
	}

	if (!createPipes()) {
		return false;
	}

	std::stringstream cmdLineStream;
	cmdLineStream << cmd << " " << args;
	std::string cmdLine = cmdLineStream.str();

	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = hChildStdinRd;
	si.hStdError = hChildStderrWr;
	si.hStdOutput = hChildStdoutWr;

	bool success = CreateProcessA(
		NULL, // application name
		(LPSTR)cmdLine.c_str(), // command line
		NULL, // process attributes
		NULL, // thread attributes
		TRUE, // inherit handles
		CREATE_NO_WINDOW, // creation flags
		NULL, // environment
		NULL, // current directory
		&si, // startup info
		&pi // process information
	);

	if (!success) {
		std::cerr << "CreateProcess failed (" << GetLastError() << ")" << std::endl;
		closePipes();
		return false;
	}

	CloseHandle(hChildStdinRd);
	CloseHandle(hChildStdoutWr);
	CloseHandle(hChildStderrWr);
	hChildStdinRd = INVALID_HANDLE_VALUE;
	hChildStdoutWr = hChildStderrWr = INVALID_HANDLE_VALUE;
	running = true;

	stdoutReadThread = std::thread(&PTY::readFromPipe, this);
	stderrReadThread = std::thread(&PTY::readFromStderrPipe, this);
	return true;
}

void PTY::write(const std::string& data) {
	if (!running) {
		std::cerr << "PTY is not running." << std::endl;
		return;
	}

	DWORD dwWritten;
	if (!WriteFile(hChildStdinWr, data.c_str(), data.length(), &dwWritten, NULL)) {
		std::cerr << "WriteFile failed (" << GetLastError() << ")" << std::endl;
		return;
	}
}

void PTY::on(const std::string& event, DataCallback callback) {
	if (event == "data") {
		dataCallback = callback;
		return;
	} else if (event == "error") {
		errorCallback = callback;
		return;
	}

	std::cerr << "Event '" << event << "' is not supported." << std::endl;
}

void PTY::readFromPipe() {
	const int BUFFER_SIZE = 4096;
	char buffer[BUFFER_SIZE];
	DWORD dwRead;
	BOOL bSuccess = FALSE;

	while (running) {
		bSuccess = ReadFile(hChildStdoutRd, buffer, BUFFER_SIZE - 1, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) {
			if (GetLastError() == ERROR_BROKEN_PIPE) {
				std::cout << "Child process terminated." << std::endl;
			}
			else {
				std::cerr << "ReadFile failed (" << GetLastError() << ")" << std::endl;
			}
			break;
		}

		buffer[dwRead] = '\0';
		if (dataCallback) dataCallback(std::string(buffer, dwRead));
	}
}

void PTY::readFromStderrPipe() {
	const int BUFFER_SIZE = 4096;
	char buffer[BUFFER_SIZE];
	DWORD dwRead;
	BOOL bSuccess = FALSE;

	while (running) {
		bSuccess = ReadFile(hChildStderrRd, buffer, BUFFER_SIZE - 1, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) {
			if (GetLastError() == ERROR_BROKEN_PIPE) {
				std::cout << "Child process terminated." << std::endl;
			}
			else {
				std::cerr << "ReadFile failed (" << GetLastError() << ")" << std::endl;
			}
			break;
		}

		buffer[dwRead] = '\0';
		if (errorCallback) errorCallback(std::string(buffer, dwRead));
	}
}

void PTY::close() {
	bool expected = true;
	if (running.compare_exchange_strong(expected, false)) { // compare_exchange sets running to false
		if (pi.hProcess != NULL) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			pi.hProcess = NULL;
			pi.hThread = NULL;
		}

		closePipes(); // close all pipes
	}
}

bool PTY::isRunning() const {
	return running;
}
