#include "scanner.hpp"

ScanResult is_port_open(const std::string& ip, int port, int timeout_sec) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;         // IPv4
    hints.ai_socktype = SOCK_STREAM;   // TCP

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(ip.c_str(), port_str, &hints, &res) != 0)
        return {false, ""};

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == -1) {
        freeaddrinfo(res);
        return {false, ""};
    }

    // Неблокирующий режим
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Асинхронный connect
    int ret = connect(sock, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (ret == -1 && errno != EINPROGRESS) {
        close(sock);
        return {false, ""};
    }

    // Ожидание через select
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    ret = select(sock + 1, nullptr, &fdset, nullptr, &tv);
    if (ret <= 0) {
        close(sock);
        return {false, ""};
    }

    // Проверка ошибки сокета
    int error = 0;
    socklen_t len = sizeof(error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);

    std::string banner = "";

    // Чтение баннера
    if (error == 0) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        struct timeval read_tv;
        read_tv.tv_sec = 0;          // 0 секунд
        read_tv.tv_usec = 200000;    // 200 000 микросекунд = 200 мс

        int ready = select(sock + 1, &readfds, nullptr, nullptr, &read_tv);
        if (ready > 0 && FD_ISSET(sock, &readfds)) {
            char buffer[256];
            int n = recv(sock, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
            if (n > 0) {
                buffer[n] = '\0';
                banner = buffer;
            }
        }
    }

    close(sock);

    return {error == 0, banner};
}
