#ifndef SCANNER_HPP_
#define SCANNER_HPP_

// basic libs
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>

// network-libs
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/select.h>
#include <errno.h>

struct ScanResult {
  bool is_open;
  std::string banner;
};


ScanResult is_port_open(const std::string& ip, int port, int timeout_sec = 2);

#endif // SCANNER_H_
