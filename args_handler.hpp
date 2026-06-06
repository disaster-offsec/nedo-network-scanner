#pragma once

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>

struct ScanOptions {
    std::string target = "127.0.0.1";
    std::vector<int> ports = {22, 80, 443, 8000};
    int timeout_sec = 2;
    int threads = 0;   // 0 означает "авто"
    bool show_help = false;
    bool has_error = false;
    std::string error_message;
};

class ArgsHandler {
public:
    ArgsHandler(int argc, char* argv[]) 
        : argc_(argc), argv_(argv) {}
    
    ScanOptions parse();

private:
    int argc_;
    char** argv_;
    
    void print_help(const char* progname);
    bool is_option(const std::string& arg);
    std::string get_value(int& i, const std::string& opt_name);
    std::vector<int> parse_port_list(const std::string& spec);
    int auto_threads();
};
