#include "scanner.hpp"

bool is_port_open(const std::string& ip, int port, int timeout_sec) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;         // IPv4
    hints.ai_socktype = SOCK_STREAM;   // TCP

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(ip.c_str(), port_str, &hints, &res) != 0)
        return false;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == -1) {
        freeaddrinfo(res);
        return false;
    }

    // неблокирующий режим
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // асинхронный connect
    int ret = connect(sock, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (ret == -1 && errno != EINPROGRESS) {
        close(sock);
        return false;
    }

    // ожидание через select
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    ret = select(sock+1, nullptr, &fdset, nullptr, &tv);
    if (ret <= 0) {
        close(sock);
        return false;
    }

    // проверка на ошибку сокета
    int error = 0;
    socklen_t len = sizeof(error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
    close(sock);

    return (error == 0);
}


int main() {
    std::string target = "127.0.0.1";
    std::vector<int> ports = {22, 80, 443, 8000};

    for (int port : ports) {
        std::cout << "Port " << port << ": ";
        if (is_port_open(target, port, 1))
            std::cout << "open\n";
        else std::cout << "closed\n";
    }

    return EXIT_SUCCESS;
}
