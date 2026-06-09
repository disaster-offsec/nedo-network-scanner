#include "export.hpp"
#include <fstream>
#include <iostream>

bool export_to_json(const std::vector<PortResult>& results, 
                    const std::string& filename,
                    const std::string& target,
                    size_t total_ports) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    file << "{\n";
    file << "  \"scan_info\": {\n";
    file << "    \"target\": \"" << target << "\",\n";
    file << "    \"total_ports_scanned\": " << total_ports << ",\n";
    file << "    \"open_ports_count\": " << results.size() << ",\n";
    file << "    \"timestamp\": " << std::time(nullptr) << "\n";
    file << "  },\n";
    file << "  \"open_ports\": [\n";
    
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        file << "    {\n";
        file << "      \"port\": " << r.port << ",\n";
        file << "      \"is_open\": " << (r.is_open ? "true" : "false") << ",\n";
        
        // Экранирование кавычек в баннере
        std::string escaped_banner = r.banner;
        size_t pos = 0;
        while ((pos = escaped_banner.find('"', pos)) != std::string::npos) {
            escaped_banner.replace(pos, 1, "\\\"");
            pos += 2;
        }
        
        file << "      \"banner\": \"" << escaped_banner << "\",\n";
        file << "      \"os\": \"" << r.os << "\"\n";
        file << "    }";
        if (i != results.size() - 1) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    return true;
}

bool export_to_csv(const std::vector<PortResult>& results,
                   const std::string& filename,
                   const std::string& target) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    // Заголовок
    file << "# Target: " << target << "\n";
    file << "# Scan time: " << std::time(nullptr) << "\n";
    file << "Port,Banner,OS\n";
    
    for (const auto& r : results) {
        if (!r.is_open) continue;
        
        // Убираем запятые и кавычки из баннера для CSV
        std::string clean_banner = r.banner;
        std::replace(clean_banner.begin(), clean_banner.end(), ',', ';');
        std::replace(clean_banner.begin(), clean_banner.end(), '"', '\'');
        // Оставляем только первую строку
        size_t newline = clean_banner.find('\n');
        if (newline != std::string::npos) {
            clean_banner = clean_banner.substr(0, newline);
        }
        
        file << r.port << ","
             << "\"" << clean_banner << "\","
             << r.os << "\n";
    }
    
    return true;
}

bool export_to_text(const std::vector<PortResult>& results,
                    const std::string& filename,
                    const std::string& target,
                    size_t total_ports) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    file << "=== Scan Configuration ===\n";
    file << "Target: " << target << "\n";
    file << "Total ports scanned: " << total_ports << "\n";
    file << "Timestamp: " << std::time(nullptr) << "\n\n";
    
    file << "=== Open Ports ===\n";
    if (results.empty()) {
        file << "No open ports found.\n";
    } else {
        for (const auto& r : results) {
            file << "Port " << r.port << " is OPEN";
            if (!r.banner.empty()) {
                std::string banner = r.banner;
                banner.erase(std::remove(banner.begin(), banner.end(), '\n'), banner.end());
                banner.erase(std::remove(banner.begin(), banner.end(), '\r'), banner.end());
                if (banner.length() > 100) banner = banner.substr(0, 100) + "...";
                file << " (banner: " << banner << ")";
            }
            if (!r.os.empty() && r.os != "Unknown") {
                file << " [OS: " << r.os << "]";
            }
            file << "\n";
        }
    }
    
    file << "\nScan completed. " << results.size() << "/" << total_ports << " ports open.\n";
    
    return true;
}
