#include "scanner.hpp"
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>

ScanResult is_port_open(const std::string& ip, int port, int timeout_sec) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(ip.c_str(), port_str, &hints, &res) != 0) {
        return {false, ""};
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == -1) {
        freeaddrinfo(res);
        return {false, ""};
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(sock, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (ret == -1 && errno != EINPROGRESS) {
        close(sock);
        return {false, ""};
    }

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    struct timeval tv = {timeout_sec, 0};
    ret = select(sock + 1, nullptr, &fdset, nullptr, &tv);
    if (ret <= 0) {
        close(sock);
        return {false, ""};
    }

    int error = 0;
    socklen_t len = sizeof(error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);

    std::string banner = "";
    if (error == 0) {
        // ШАГ 1: Пытаемся прочитать то, что сервер отправил сразу (SSH, FTP, SMTP)
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        struct timeval read_tv = {0, 200000}; // 200 мс
        int ready = select(sock + 1, &readfds, nullptr, nullptr, &read_tv);
        
        if (ready > 0 && FD_ISSET(sock, &readfds)) {
            char buffer[512];
            int n = recv(sock, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
            if (n > 0) {
                buffer[n] = '\0';
                banner = buffer;
            }
        }
        
        // ШАГ 2: Если ничего не прочиталось — пробуем отправить HTTP-запрос
        // (некоторые серверы ждут запроса, например HTTP)
        if (banner.empty()) {
            const char* request = "HEAD / HTTP/1.0\r\n\r\n";
            send(sock, request, strlen(request), 0);
            
            // Ждём ответ (немного дольше, так как серверу нужно обработать запрос)
            FD_ZERO(&readfds);
            FD_SET(sock, &readfds);
            struct timeval http_tv = {0, 500000}; // 500 мс для HTTP
            ready = select(sock + 1, &readfds, nullptr, nullptr, &http_tv);
            
            if (ready > 0 && FD_ISSET(sock, &readfds)) {
                char buffer[512];
                int n = recv(sock, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
                if (n > 0) {
                    buffer[n] = '\0';
                    banner = buffer;
                }
            }
        }
    }

    close(sock);
    return {error == 0, banner};
}
