#include "fingerprint.hpp"
// Включаем расширения Linux для TCP_INFO
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

TcpFingerprint get_fingerprint_from_socket(int sock) {
    TcpFingerprint fp;
    memset(&fp, 0, sizeof(fp));
    
    fp.ttl = 0;
    fp.window = 0;
    fp.mss = 0;
    fp.wscale = false;
    fp.sack = false;
    fp.timestamps = false;
    fp.ecn = false;
    
    // 1. Получаем TTL (Time To Live)
    socklen_t len = sizeof(fp.ttl);
    if (getsockopt(sock, IPPROTO_IP, IP_TTL, &fp.ttl, &len) != 0) {
        // Если не получилось, пробуем IPV6 (но нам нужен IPv4)
        // В большинстве случаев работает
    }
    
    // 2. Получаем TCP_INFO (структура с кучей полезной информации)
    struct tcp_info info;
    len = sizeof(info);
    memset(&info, 0, len);
    
    if (getsockopt(sock, IPPROTO_TCP, TCP_INFO, &info, &len) == 0) {
        fp.window = info.tcpi_snd_wnd;
        
        // tcpi_options содержит битовые флаги
        // TCPI_OPT_WSCALE = 1 << 1
        // TCPI_OPT_SACK   = 1 << 2
        // TCPI_OPT_ECN    = 1 << 4
        // TCPI_OPT_TIMESTAMPS = 1 << 3 (не везде)
        fp.wscale = (info.tcpi_options & 0x02) != 0;  // TCPI_OPT_WSCALE
        fp.sack   = (info.tcpi_options & 0x04) != 0;  // TCPI_OPT_SACK
        fp.ecn    = (info.tcpi_options & 0x10) != 0;  // TCPI_OPT_ECN
        fp.timestamps = (info.tcpi_options & 0x08) != 0; // TCPI_OPT_TIMESTAMPS
    }
    
    // 3. Получаем MSS (Maximum Segment Size)
    len = sizeof(fp.mss);
    if (getsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &fp.mss, &len) != 0) {
        fp.mss = 0;  // Не удалось получить
    }
    
    return fp;
}

std::string detect_os_from_socket(int sock) {
    // Получаем параметры
    TcpFingerprint fp = get_fingerprint_from_socket(sock);
    
    // База сигнатур (реальные данные из nmap и практики)
    // Формат: {min_ttl, max_ttl, min_win, max_win, mss, wscale, sack, ts, ecn, os_name}
    struct OsSignature {
        int ttl_min, ttl_max;
        int win_min, win_max;
        int mss;
        bool wscale;
        bool sack;
        bool timestamps;
        bool ecn;
        std::string name;
        int confidence;  // 0-100
    };
    
    std::vector<OsSignature> signatures = {
        // Linux ядро 2.4-2.6
        {60, 68, 5800, 5900, 1460, false, true, false, false, "Linux 2.4-2.6", 70},
        // Linux ядро 2.6-3.x
        {60, 68, 40000, 43000, 1460, false, true, false, false, "Linux 2.6-3.x", 80},
        // Linux ядро 4.x-5.x (современные)
        {60, 68, 42000, 43000, 1460, true, true, true, false, "Linux 4.x-5.x", 90},
        // Linux Ubuntu (специфичный window)
        {60, 68, 42540, 42540, 1460, true, true, true, false, "Linux (Ubuntu)", 85},
        
        // Windows 7/8/10
        {120, 128, 8192, 8192, 1460, true, true, false, false, "Windows 7/8/10", 85},
        // Windows 10 с обновлениями (большое окно)
        {120, 128, 65535, 65535, 1460, true, true, false, false, "Windows 10 (latest)", 80},
        // Windows Server 2008/2012
        {120, 128, 8192, 16384, 1460, true, true, false, false, "Windows Server", 75},
        // Windows XP (устаревшая)
        {120, 128, 65535, 65535, 1460, false, false, false, false, "Windows XP", 60},
        
        // FreeBSD
        {60, 68, 65535, 65535, 1460, false, false, false, false, "FreeBSD", 75},
        // FreeBSD с опциями
        {60, 68, 65535, 65535, 1460, true, true, true, false, "FreeBSD (modern)", 80},
        
        // macOS (Darwin)
        {60, 68, 65535, 65535, 1460, true, true, true, false, "macOS", 80},
        
        // Solaris
        {240, 255, 65535, 65535, 1460, false, false, false, false, "Solaris", 70},
        
        // OpenBSD
        {60, 68, 16384, 16384, 1460, false, false, false, false, "OpenBSD", 75},
        
        // Cisco IOS (маршрутизаторы)
        {240, 255, 4128, 4128, 1460, false, false, false, false, "Cisco IOS", 65},
    };
    
    // Поиск наилучшего совпадения
    int best_score = 0;
    std::string best_match = "Unknown";
    
    for (const auto& sig : signatures) {
        int score = 0;
        
        // TTL (самый важный параметр, даёт много очков)
        if (fp.ttl >= sig.ttl_min && fp.ttl <= sig.ttl_max) {
            score += 40;
        } else if (abs(fp.ttl - (sig.ttl_min + sig.ttl_max)/2) <= 10) {
            score += 10;  // близко, но не точно
        }
        
        // Window Size (тоже важен)
        if (fp.window >= sig.win_min && fp.window <= sig.win_max) {
            score += 30;
        } else if (abs(fp.window - (sig.win_min + sig.win_max)/2) <= 5000) {
            score += 10;
        }
        
        // MSS
        if (fp.mss == sig.mss && sig.mss > 0) {
            score += 15;
        }
        
        // TCP опции
        if (fp.wscale == sig.wscale) score += 5;
        if (fp.sack == sig.sack) score += 5;
        if (fp.timestamps == sig.timestamps) score += 5;
        if (fp.ecn == sig.ecn) score += 5;
        
        // Учитываем уверенность из базы
        score = score * sig.confidence / 100;
        
        if (score > best_score) {
            best_score = score;
            best_match = sig.name;
        }
    }
    
    // Если уверенность низкая, возвращаем Unknown
    if (best_score < 25) {
        return "Unknown";
    }
    
    // Для отладки можно вывести fingerprint
    // std::cerr << "[DEBUG] TTL=" << fp.ttl << " WIN=" << fp.window 
    //           << " MSS=" << fp.mss << " score=" << best_score << "\n";
    
    return best_match;
}

std::string fingerprint_to_string(const TcpFingerprint& fp) {
    std::string result = "TTL=" + std::to_string(fp.ttl) + 
                         " WIN=" + std::to_string(fp.window) + 
                         " MSS=" + std::to_string(fp.mss);
    
    result += " FLAGS:";
    if (fp.wscale) result += " WSCALE";
    if (fp.sack) result += " SACK";
    if (fp.timestamps) result += " TS";
    if (fp.ecn) result += " ECN";
    
    return result;
}
