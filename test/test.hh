#pragma once
#include <algorithm>
#include <iostream>
#include <format>
#include <vector>
#include <chrono>
#include <numeric>

using byte = uint8_t;

// clang-format off
namespace test {
    inline void print_diff_hex(
        const byte *data1, const byte *data2,
        size_t len1, size_t len2,
        size_t hex_per_line,
        bool indent
    ) noexcept
    {
        auto print_diff_hex_line = [](
            const byte *data, size_t len, size_t start, size_t hex_per_line
        ) {
            for (size_t j = 0; j < hex_per_line; ++j) {
                if ((start + j) < len) {
                    if (data[start + j] == 0) {
                        std::cout << std::format("\x1b[91m" "{:02x}" "\x1b[0m", data[start + j]);
                    } else if (data[start + j] == 255) {
                        std::cout << std::format("\x1b[93m" "{:02x}" "\x1b[0m", data[start + j]);
                    } else {
                        std::cout << std::format("{:02x}", data[start + j]);
                    }
                    std::cout << " ";
                } else {
                    std::cout << "   ";  // 三个空格对齐
                }
            }
        };

        size_t max_len = std::max(len1, len2);

        for (size_t i = 0; i < max_len; i += hex_per_line) {
            if (indent) {
                std::cout << "\t";
            }

            print_diff_hex_line(data1, len1, i, hex_per_line);
            std::cout << "\t\t";
            print_diff_hex_line(data2, len2, i, hex_per_line);

            std::cout << "\n";
        }
    }

    inline void print_hex(const byte *data, size_t len, size_t num, bool newline, bool indent) noexcept
    {
        for (size_t i = 0; i < len; ++i) {
            if (indent && ((i) % num == 0)) {
                std::cout << "\t";
            }

            if (data[i] == 0) {
                std::cout << std::format("\x1b[91m" "{:02x}" "\x1b[0m", data[i]);
            } else if (data[i] == 255) {
                std::cout << std::format("\x1b[93m" "{:02x}" "\x1b[0m", data[i]);
            } else {
                std::cout << std::format("{:02x}", data[i]);
            }

            std::cout << (((i + 1) % num) ? " " : "\n");
        }
        if (newline) {
            std::cout << "\n";
        }
    }

    inline void print_box(const byte *box, size_t size, size_t num, bool newline) noexcept
    {
        for (size_t i = 0; i < size; ++i) {
            std::cout << std::format("0x{:02x}", box[i]);

            std::cout << (((i + 1) != size) ? (((i + 1) % num == 0) ? (",\n") : (", ")) : ("\n"));
        }
        if (newline) {
            std::cout << "\n";
        }
    }
}