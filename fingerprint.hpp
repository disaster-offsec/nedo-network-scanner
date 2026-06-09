#ifndef FINGERPRINT_HPP
#define FINGERPRINT_HPP

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>


// Структура для хранения параметров TCP-стека удалённого хоста
struct TcpFingerprint {
    int ttl;           // Time To Live из IP-заголовка (обычно 64, 128, 255)
    int window;        // TCP Window Size (размер окна)
    int mss;           // Maximum Segment Size (максимальный размер сегмента)
    bool wscale;       // Window Scaling (поддержка масштабирования окна)
    bool sack;         // Selective ACK (выборочное подтверждение)
    bool timestamps;   // Timestamps (метки времени)
    bool ecn;          // Explicit Congestion Notification
};

// Определить ОС по уже установленному сокету (соединение должно быть активно)
// Возвращает строку с названием ОС или "Unknown"
std::string detect_os_from_socket(int sock);

// Превратить fingerprint в читаемую строку (для отладки)
std::string fingerprint_to_string(const TcpFingerprint& fp);

// Получить fingerprint из активного сокета
TcpFingerprint get_fingerprint_from_socket(int sock);

#endif
