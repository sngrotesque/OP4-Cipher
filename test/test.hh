// test/test.hh
#pragma once
#include <algorithm>
#include <iostream>
#include <format>
#include <vector>
#include <chrono>
#include <numeric>
#include <random>
#include <set>

using byte = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

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

// clang-format on
namespace test {
    class PRNG {
    private:
        std::mt19937_64 m_rng;

    public:
        explicit PRNG(u64 seed) noexcept
            : m_rng(seed)
        {
        }

        u64 next_u64() noexcept
        {
            return m_rng();
        }

        u32 next_u32() noexcept
        {
            return m_rng() & UINT32_MAX;
        }

        byte next_byte() noexcept
        {
            return m_rng() & UINT8_MAX;
        }

        // [0, bound) 均匀取值（测试用途，取模偏差可忽略）
        u32 below(u32 bound) noexcept
        {
            return next_u32() % bound;
        }

        void fill_bytes(byte *p, size_t n) noexcept
        {
            while (n > 0) {
                *p++ = next_byte();
                n--;
            }
        }

        template <typename T> T randint(T min, T max)
        {
            return std::uniform_int_distribution<T>(min, max)(m_rng);
        }
    };

    inline bool mem_eq(const byte *a, const byte *b, size_t n) noexcept
    {
        return (n == 0) || (std::memcmp(a, b, n) == 0);
    }

    inline std::string bytes_to_hex(const byte *p, size_t n)
    {
        static constexpr char digits[] = "0123456789abcdef";
        std::string s;
        s.reserve(n * 2);
        for (size_t i = 0; i < n; ++i) {
            s.push_back(digits[p[i] >> 4]);
            s.push_back(digits[p[i] & 0x0f]);
        }
        return s;
    }

    // 十六进制字符串 -> 字节串；长度不符或含非法字符返回 false
    inline bool hex_to_bytes(const char *hex, byte *out, size_t n) noexcept
    {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };

        for (size_t i = 0; i < n; ++i) {
            const int hi = nib(hex[2 * i]);
            const int lo = nib(hex[2 * i + 1]);
            if (hi < 0 || lo < 0) {
                return false;
            }
            out[i] = static_cast<byte>((hi << 4) | lo);
        }
        return hex[2 * n] == '\0';
    }

    inline void report(const std::string_view &message, bool pass, bool indent = false) noexcept
    {
        constexpr std::string_view str_pass("\x1b[92mPASS\x1b[0m");
        constexpr std::string_view str_fail("\x1b[91mFAIL\x1b[0m");

        std::cout << std::format(
            "{}[{}] {}\n", indent ? "\t" : "", pass ? str_pass : str_fail, message);
    }
}
