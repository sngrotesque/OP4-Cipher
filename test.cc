#include "op4.hh"

#include <algorithm>
#include <iostream>
#include <format>
#include <vector>
#include <chrono>
#include <numeric>

#define COLOR_RED  "\x1b[91m"
#define COLOR_GOLD "\x1b[93m"
#define COLOR_RST  "\x1b[0m"

using byte = uint8_t;

// clang-format off
namespace test {
    void print_diff_hex(
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
                        std::cout << std::format(COLOR_RED "{:02x}" COLOR_RST, data[start + j]);
                    } else if (data[start + j] == 255) {
                        std::cout << std::format(COLOR_GOLD "{:02x}" COLOR_RST, data[start + j]);
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

    void print_hex(const byte *data, size_t len, size_t num, bool newline, bool indent) noexcept
    {
        for (size_t i = 0; i < len; ++i) {
            if (indent && ((i) % num == 0)) {
                std::cout << "\t";
            }

            if (data[i] == 0) {
                std::cout << std::format(COLOR_RED "{:02x}" COLOR_RST, data[i]);
            } else if (data[i] == 255) {
                std::cout << std::format(COLOR_GOLD "{:02x}" COLOR_RST, data[i]);
            } else {
                std::cout << std::format("{:02x}", data[i]);
            }

            std::cout << (((i + 1) % num) ? " " : "\n");
        }
        if (newline) {
            std::cout << "\n";
        }
    }

    void print_box(const byte *box, size_t size, size_t num, bool newline) noexcept
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
void op4_test()
{
    auto encryption_test = []() {
        constexpr size_t length = OP4_BL * 3;
        constexpr size_t ks = OP4_KS;

        // 初始化
        const char *buffer = {
            "GET / HTTP/1.1\r\n"
            "Host: www.google.com\r\n"
            "\r\n"};

        byte plaintext[length] = {};
        byte ciphertext[length] = {};
        byte decrypted[length] = {};

        memcpy(plaintext, buffer, strlen(buffer));

        // 初始化加密上下文
        byte key[ks] = {0xd6, 0xc4, 0x15, 0x30, 0xbe, 0xc2, 0xfa, 0x65, 0x50, 0x54, 0xd0,
                        0xb1, 0xa6, 0xa2, 0x8e, 0x34, 0x99, 0xb2, 0x1e, 0xf4, 0x91, 0x1e,
                        0x2d, 0x5c, 0x45, 0x5d, 0xb9, 0xbb, 0x69, 0xc1, 0x41, 0xb6};
        byte nonce[OP4_NL] = {0xed, 0xc4, 0x2b, 0x60, 0x9f, 0xb4,
                              0xa8, 0x11, 0x55, 0x60, 0xb1, 0x8e};
        u32 counter = 0U;
        printf("key:\t\t\t\t\t\t\t\tnonce:\n");
        test::print_diff_hex(key, nonce, sizeof(key), sizeof(nonce), 16, true);

        OP4 op4(key);

        // 加密和解密
        printf("ciphertext:\t\t\t\t\t\t\tplaintext:\n");
        op4.ctr_crypt(ciphertext, plaintext, length, nonce, counter);
        test::print_diff_hex(ciphertext, plaintext, length, length, 16, true);

        printf("decrypted:\t\t\t\t\t\t\tciphertext:\n");
        op4.ctr_crypt(decrypted, ciphertext, length, nonce, counter);
        test::print_diff_hex(decrypted, ciphertext, length, length, 16, true);
    };
    auto speed_test = []() {
        auto timer = []() {
            auto now = std::chrono::high_resolution_clock::now();
            auto duration = now.time_since_epoch();
            return std::chrono::duration<double>(duration).count();
        };
        byte key[32] = {};
        byte nonce[12] = {};

        constexpr size_t length = 256ULL * 1024 * 1024;
        constexpr u32 count = 10;

        std::vector<double> total_timer(count);
        byte *out = new byte[length];
        byte *in = new byte[length];
        OP4 op4(key);

        for (u32 r = 0; r < count; ++r) {
            auto start = timer();
            op4.ctr_crypt(out, in, length, nonce);
            auto stop = timer();
            total_timer[r] = (stop - start);
        }

        auto min_timer = std::min_element(total_timer.begin(), total_timer.end())[0];
        auto max_timer = std::max_element(total_timer.begin(), total_timer.end())[0];
        auto avg_timer = std::accumulate(total_timer.begin(), total_timer.end(), 0.0) / count;

        std::cout << std::format(
            "Encrypting {:.2f} MB of data, time consumption:\n"
            "\tMin time taken: {:.4f}.\n"
            "\tMax time taken: {:.4f}.\n"
            "\tAvg time taken: {:.4f}.\n",
            (static_cast<double>(length) / 1024 / 1024), min_timer, max_timer, avg_timer);
        std::cout << std::format(
            "Average performance: {:.4f} MB/s.",
            (static_cast<double>(length) / avg_timer) / 1024 / 1024);

        delete[] out;
        delete[] in;
    };

    encryption_test();
    speed_test();
}

int main()
{
    op4_test();

    return 0;
}
