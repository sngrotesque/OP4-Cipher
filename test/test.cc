/**
 * 这个代码提供了常规的示例代码，比如加解密数据/文件，加密结果对比等。
 * 
 */
#include <op4.hh>
#include "test.hh"

using namespace cipher;

// 通用测试时使用的 key 和 Nonce
alignas(16) constexpr byte key[op4::ks] = {
    0xd6, 0xc4, 0x15, 0x30, 0xbe, 0xc2, 0xfa, 0x65,
    0x50, 0x54, 0xd0, 0xb1, 0xa6, 0xa2, 0x8e, 0x34,
    0x99, 0xb2, 0x1e, 0xf4, 0x91, 0x1e, 0x2d, 0x5c,
    0x45, 0x5d, 0xb9, 0xbb, 0x69, 0xc1, 0x41, 0xb6
};
alignas(16) constexpr byte nonce[op4::ns] = {
    0xed, 0xc4, 0x2b, 0x60, 0x9f, 0xb4, 0xa8, 0x11,
    0x55, 0x60, 0xb1, 0x8e
};
constexpr u32 counter = 0U;

namespace {
    // 一个简单场景加解密测试
    void encryption_test()
    {
        const char *_content = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
        size_t length = strlen(_content);

        std::vector<byte> plaintext(length, 0);
        std::vector<byte> ciphertext(length, 0);
        std::vector<byte> decrypted(length, 0);
        memcpy(plaintext.data(), _content, strlen(_content));

        OP4 op4(key);

        printf("key:\t\t\t\t\t\t\t\tnonce:\n");
        test::print_diff_hex(key, nonce, sizeof(key), sizeof(nonce), 16, true);

        printf("ciphertext:\t\t\t\t\t\t\tplaintext:\n");
        op4.ctr_crypt(ciphertext.data(), plaintext.data(), length, nonce, counter);
        test::print_diff_hex(ciphertext.data(), plaintext.data(), length, length, 16, true);

        printf("decrypted:\t\t\t\t\t\t\tciphertext:\n");
        op4.ctr_crypt(decrypted.data(), ciphertext.data(), length, nonce, counter);
        test::print_diff_hex(decrypted.data(), ciphertext.data(), length, length, 16, true);
    }

    // 一个简易的性能测试
    void speed_test()
    {
        auto timer = []() {
            auto now = std::chrono::high_resolution_clock::now();
            auto duration = now.time_since_epoch();
            return std::chrono::duration<double>(duration).count();
        };
        auto calculation_time = [](size_t length, std::vector<double> total_timer, size_t count) {
            auto min_timer = std::min_element(total_timer.begin(), total_timer.end())[0];
            auto max_timer = std::max_element(total_timer.begin(), total_timer.end())[0];
            auto avg_timer = std::accumulate(total_timer.begin(), total_timer.end(), 0.0) / count;

            std::cout << std::format(
                "\tEncrypting {:.2f} MB of data, time consumption:\n"
                "\t\tMin time taken: {:.4f}.\n"
                "\t\tMax time taken: {:.4f}.\n"
                "\t\tAvg time taken: {:.4f}.\n",
                (static_cast<double>(length) / 1024 / 1024), min_timer, max_timer, avg_timer);
            std::cout << std::format(
                "\tAverage performance: {:.4f} MB/s.\n",
                (static_cast<double>(length) / avg_timer) / 1024 / 1024);
        };
        constexpr size_t length = 16ULL * 1024 * 1024;
        constexpr u32 count = 10;

        std::vector<double> total_timer(count);
        std::vector<byte> out(length);
        std::vector<byte> in(length);

        {
            cipher::op4::avx2::OP4 op4(key);

            for (u32 r = 0; r < count; ++r) {
                auto start = timer();
                op4.ctr_crypt(out.data(), in.data(), length, nonce);
                auto stop = timer();
                total_timer[r] = (stop - start);
            }

            std::cout << "AVX2 implementation:\n";
            calculation_time(length, total_timer, count);
        }

        {
            cipher::op4::soft::OP4 op4(key);

            for (u32 r = 0; r < count; ++r) {
                auto start = timer();
                op4.ctr_crypt(out.data(), in.data(), length, nonce);
                auto stop = timer();
                total_timer[r] = (stop - start);
            }

            std::cout << "Software implementation:\n";
            calculation_time(length, total_timer, count);
        }
    };
}

void op4_test()
{
    try {
        encryption_test();
        speed_test();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
    }
}

int main()
{
    op4_test();

    return 0;
}
