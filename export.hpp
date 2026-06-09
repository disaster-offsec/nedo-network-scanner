#ifndef EXPORT_HPP
#define EXPORT_HPP

#include <string>
#include <vector>
#include <ctime>
#include <algorithm>

// Структура PortResult (должна совпадать с той, что в main.cpp)
struct PortResult {
    int port;
    bool is_open;
    std::string banner;
    std::string os;
};

// Экспорт в JSON
bool export_to_json(const std::vector<PortResult>& results, 
                    const std::string& filename,
                    const std::string& target,
                    size_t total_ports);

// Экспорт в CSV
bool export_to_csv(const std::vector<PortResult>& results,
                   const std::string& filename,
                   const std::string& target);

// Экспорт в текстовый файл
bool export_to_text(const std::vector<PortResult>& results,
                    const std::string& filename,
                    const std::string& target,
                    size_t total_ports);

#endif
