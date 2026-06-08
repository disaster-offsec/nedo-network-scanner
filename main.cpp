#include "scanner.hpp"
#include "args_handler.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <chrono>
#include <algorithm>

struct PortResult {
    int port;
    bool is_open;
    std::string banner;
};

void worker(const std::string& target, const std::vector<int>& ports,
            int timeout_sec, std::vector<PortResult>& results,
            std::mutex& mtx, std::atomic<size_t>& next_index) {
    while (true) {
        size_t idx = next_index.fetch_add(1);
        if (idx >= ports.size()) break;
        ScanResult scan = is_port_open(target, ports[idx], timeout_sec);
        {
            std::lock_guard<std::mutex> lock(mtx);
            results[idx] = {ports[idx], scan.is_open, scan.banner};
        }
    }
}

int main(int argc, char* argv[]) {
    ArgsHandler handler(argc, argv);
    ScanOptions opts = handler.parse();

    if (opts.show_help) {
        return 0;
    }
    if (opts.has_error) {
        std::cerr << "Error: " << opts.error_message << "\n\n";
        handler.print_help(argv[0]);
        return 1;
    }

    // Ограничение потоков
    const int MAX_THREADS = 200;
    if (opts.threads > MAX_THREADS) {
        std::cerr << "Warning: " << opts.threads << " threads requested, limiting to " << MAX_THREADS << "\n";
        opts.threads = MAX_THREADS;
    }

    std::cout << "\n=== Scan Configuration ===\n";
    std::cout << "Target:   " << opts.target << "\n";
    std::cout << "Ports:    " << opts.ports.size() << " ports (";
    for (size_t i = 0; i < std::min(opts.ports.size(), size_t(10)); ++i)
        std::cout << opts.ports[i] << (i+1 < std::min(opts.ports.size(), size_t(10)) ? "," : "");
    if (opts.ports.size() > 10) std::cout << "...";
    std::cout << ")\n";
    std::cout << "Timeout:  " << opts.timeout_sec << " sec\n";
    std::cout << "Threads:  " << opts.threads << "\n\n";

    std::vector<PortResult> results(opts.ports.size());
    std::mutex results_mutex;
    std::atomic<size_t> next_index(0);

    std::vector<std::thread> threads;
    for (int i = 0; i < opts.threads; ++i) {
        threads.emplace_back(worker, std::ref(opts.target), std::ref(opts.ports),
                             opts.timeout_sec, std::ref(results),
                             std::ref(results_mutex), std::ref(next_index));
    }

    std::atomic<bool> done{false};
    std::thread progress([&]() {
        const size_t total = opts.ports.size();
        while (!done) {
            size_t scanned = next_index.load();
            if (scanned > total) scanned = total;
            float percent = 100.0f * scanned / total;
            std::cout << "\rProgress: " << std::fixed << std::setprecision(1) << percent
                      << "% (" << scanned << "/" << total << ")" << std::flush;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        std::cout << "\n";
    });

    for (auto& th : threads) th.join();
    done = true;
    progress.join();

    std::cout << "\n=== Open Ports ===\n";
    int open_count = 0;
    for (const auto& res : results) {
        if (res.is_open) {
            std::cout << "Port " << res.port << " is OPEN";
            if (!res.banner.empty()) {
                std::string banner = res.banner;
                banner.erase(std::remove(banner.begin(), banner.end(), '\n'), banner.end());
                banner.erase(std::remove(banner.begin(), banner.end(), '\r'), banner.end());
                if (banner.length() > 100) banner = banner.substr(0, 100) + "...";
                std::cout << " (banner: " << banner << ")";
            }
            std::cout << "\n";
            ++open_count;
        }
    }
    if (open_count == 0) std::cout << "No open ports found.\n";

    std::cout << "\nScan completed. " << open_count << "/" << opts.ports.size() << " ports open.\n";
    return 0;
}
