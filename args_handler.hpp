#ifndef ARGS_HANDLER_HPP
#define ARGS_HANDLER_HPP

#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <thread>


struct ScanOptions {
    std::string target = "127.0.0.1";
    std::vector<int> ports = {22, 80, 443, 8000};
    int timeout_sec = 2;
    int threads = 0;       // 0 = автоматическое определение
    bool show_help = false;
    bool has_error = false;
    std::string error_message;
};

class ArgsHandler {
public:
    ArgsHandler(int argc, char* argv[]);
    ScanOptions parse();
    void print_help(const char* progname) const;

private:
    int argc_;
    char** argv_;

    bool is_option(const std::string& arg) const;
    std::string get_value(int& i, const std::string& opt_name);
    std::vector<int> parse_port_list(const std::string& spec);
    int auto_threads() const;
};

#endif // ARGS_HANDLER_HPP
