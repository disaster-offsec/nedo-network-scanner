#include "args_handler.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <thread>

ArgsHandler::ArgsHandler(int argc, char* argv[]) 
    : argc_(argc), argv_(argv) {}

ScanOptions ArgsHandler::parse() {
    ScanOptions opts;
    const char* progname = argv_[0];

    for (int i = 1; i < argc_; ++i) {
        std::string arg = argv_[i];

        if (arg == "-h" || arg == "--help") {
            opts.show_help = true;
            print_help(progname);
            return opts;
        }
        else if (arg == "-t" || arg == "--target") {
            opts.target = get_value(i, "target");
            if (opts.target.empty()) {
                opts.has_error = true;
                opts.error_message = "Missing value for " + arg;
                return opts;
            }
        }
        else if (arg == "-p" || arg == "--ports") {
            std::string port_spec = get_value(i, "ports");
            if (port_spec.empty()) {
                opts.has_error = true;
                opts.error_message = "Missing value for " + arg;
                return opts;
            }
            opts.ports = parse_port_list(port_spec);
        }
        else if (arg == "-to" || arg == "--timeout") {
            std::string val = get_value(i, "timeout");
            if (val.empty()) {
                opts.has_error = true;
                opts.error_message = "Missing value for " + arg;
                return opts;
            }
            opts.timeout_sec = std::stoi(val);
            if (opts.timeout_sec <= 0) {
                opts.has_error = true;
                opts.error_message = "Timeout must be positive";
                return opts;
            }
        }
        else if (arg == "-th" || arg == "--threads") {
            std::string val = get_value(i, "threads");
            if (val.empty()) {
                opts.has_error = true;
                opts.error_message = "Missing value for " + arg;
                return opts;
            }
            opts.threads = std::stoi(val);
            if (opts.threads <= 0) {
                opts.has_error = true;
                opts.error_message = "Threads must be positive";
                return opts;
            }
        }
        else if (is_option(arg)) {
            opts.has_error = true;
            opts.error_message = "Unknown option: " + arg;
            return opts;
        }
        else {
            // позиционный аргумент – считаем его target
            if (opts.target == "127.0.0.1")
                opts.target = arg;
            else {
                opts.has_error = true;
                opts.error_message = "Unexpected argument: " + arg;
                return opts;
            }
        }
    }

    if (opts.threads == 0)
        opts.threads = auto_threads();

    if (opts.ports.empty()) {
        opts.has_error = true;
        opts.error_message = "No valid ports specified";
    }
    return opts;
}

void ArgsHandler::print_help(const char* progname) const {
    std::cout << "Usage: " << progname << " [options]\n"
              << "Options:\n"
              << "  -t, --target IP       Target IP address (default 127.0.0.1)\n"
              << "  -p, --ports LIST      Port list: 22,80,443 or 1-1000 (default 22,80,443,8000)\n"
              << "  -to, --timeout SEC    Connection timeout in seconds (default 2)\n"
              << "  -th, --threads NUM    Number of threads (default auto = CPU cores)\n"
              << "  -h, --help            Show this help\n"
              << "\nExamples:\n"
              << "  " << progname << " -t 192.168.1.1 -p 22,80,443\n"
              << "  " << progname << " --target scanme.nmap.org --ports 1-1000 --threads 50\n";
}

bool ArgsHandler::is_option(const std::string& arg) const {
    return arg.size() >= 2 && arg[0] == '-';
}

std::string ArgsHandler::get_value(int& i, const std::string& opt_name) {
    if (i + 1 >= argc_) return "";
    std::string val = argv_[i+1];
    if (is_option(val)) return "";
    ++i;
    return val;
}

std::vector<int> ArgsHandler::parse_port_list(const std::string& spec) {
    std::vector<int> ports;
    std::stringstream ss(spec);
    std::string token;

    while (std::getline(ss, token, ',')) {
        token.erase(std::remove_if(token.begin(), token.end(), ::isspace), token.end());
        if (token.empty()) continue;

        size_t dash = token.find('-');
        if (dash != std::string::npos) {
            try {
                int start = std::stoi(token.substr(0, dash));
                int end = std::stoi(token.substr(dash + 1));
                if (start >= 1 && end <= 65535 && start <= end) {
                    for (int p = start; p <= end; ++p)
                        ports.push_back(p);
                } else {
                    std::cerr << "Warning: invalid port range: " << token << "\n";
                }
            } catch (...) {
                std::cerr << "Warning: malformed port range: " << token << "\n";
            }
        } else {
            try {
                int port = std::stoi(token);
                if (port >= 1 && port <= 65535)
                    ports.push_back(port);
                else
                    std::cerr << "Warning: port out of range: " << port << "\n";
            } catch (...) {
                std::cerr << "Warning: invalid port number: " << token << "\n";
            }
        }
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

int ArgsHandler::auto_threads() const {
    unsigned int n = std::thread::hardware_concurrency();
    return n > 0 ? n : 4;
}
