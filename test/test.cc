// test/test.cc
/**
 * 这个代码提供了常规的示例代码，比如加解密数据/文件，加密结果对比等。
 *
 * 测试内容：
 *   1. 差分测试：AVX2 与软件实现对同一随机输入的输出一致性
 *   2. 往返测试：CTR / ECB 加解密往返 + 跨实现往返，PRNG 种子化可复现
 *   3. 首块密钥流：固定向量下的首块密钥流已知答案测试
 *   4. 雪崩效应：分别测试不同的明文输入，密钥输入，Nonce输入，和测试轮密钥的雪崩效应
 *   5. 加解密：加密和解密一份 HTTP 请求
 *   6. 性能测试：分别使用 AVX2 和 软件 实现测试此算法性能
 */
#define _CRT_SECURE_NO_WARNINGS

#include <op4.hh>
#include "test.hh"

#ifdef _WIN32
#    define NOMINMAX
#    include <Windows.h>
#endif

using namespace cipher;

// clang-format off

// 通用测试时使用的 key 和 nonce 和 counter
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
    // 默认固定种子：保证测试可复现；可用环境变量 OP4_TEST_SEED 覆盖，
    constexpr u64 k_default_seed = 0x4f5034c0ffee2026ULL;
    // 首块密钥流 = E(key, nonce ‖ counter)，即对 16 字节全零明文做 CTR 加密的结果。
    constexpr const char *kat_expected_hex = "ba5117ad51842aa91ac0393309dcc423";
    // 雪崩效应测试类型
    enum class AVALANCHE_EFFECT_TYPE {
        PLAINTEXT_DIFF, // 明文
        KEY_DIFF,       // 密钥
        NONCE_DIFF,     // Nonce
        ROUNDKEY_DIFF,  // 轮密钥
    };

    u64 get_test_seed()
    {
        if (const char *s = std::getenv("OP4_TEST_SEED")) {
            try {
                return std::stoull(s, nullptr, 0);
            } catch (...) {
                std::cerr << "invalid OP4_TEST_SEED, using default.\n";
            }
        }
        return k_default_seed;
    }

    // ==================== 差分测试 ====================
    // 长度集合覆盖 AVX2 ctr_crypt 的全部分支：
    //   0            空输入提前返回
    //   1   ... 15   纯字节尾部
    //   16  ... 127  尾部整块路径
    //   128 ... 255  8 块循环
    //       >=  256  16 块主循环
    // 以及各边界的 ±1
    void differential_test(u64 seed)
    {
        std::cout << "======== 差分测试（AVX2 vs 软件实现）========\n";
        std::cout << std::format("PRNG seed: 0x{:016x}\n", seed);
        std::cout << std::format("key:       {}\n", test::bytes_to_hex(key, op4::ks));
        std::cout << std::format("nonce:     {}\n", test::bytes_to_hex(nonce, op4::ns));

        constexpr size_t k_fixed_lengths[] = {
            0,   1,   8,   15,  16,  17,  31,  32,  63,  64,
            111, 112, 113, 127, 128, 129, 143, 144, 255, 256,
            257, 271, 272, 383, 384, 511, 512, 513, 1000
        };
        constexpr size_t k_max_length = 1024;
        constexpr u32 k_rounds = 32;

        size_t cases  = 0;  // 调用次数
        size_t failed = 0;  // 失败次数

        std::vector<byte> in(k_max_length);
        std::vector<byte> outa(k_max_length);
        std::vector<byte> outs(k_max_length);
        test::PRNG prng(seed);

        for (u32 r = 0; r < k_rounds; ++r) {
            byte k[op4::ks] = {};
            byte n[op4::ns] = {};

            prng.fill_bytes(k, sizeof k);
            prng.fill_bytes(n, sizeof n);

            // 限制计数器范围，避免触发 counter == UINT32_MAX 检查
            const u32 ctr = prng.below(0x40000000u);

            const cipher::op4::avx2::OP4 impla(k);
            cipher::op4::soft::OP4 impls(k);

            for (const size_t len : k_fixed_lengths) {
                prng.fill_bytes(in.data(), len);

                // 用 AVX2 实现加密
                impla.ctr_crypt(outa.data(), in.data(), len, n, ctr);
                // 用 软件 实现加密
                impls.ctr_crypt(outs.data(), in.data(), len, n, ctr);

                cases++; // 调用次数 +1

                // 如果加解密结果不一致
                if (!test::mem_eq(outa.data(), outs.data(), len)) {
                    failed++; // 失败次数 +1

                    std::cout << std::format(
                        "MISMATCH: round={} len={} ctr=0x{:08x}\n", r, len, ctr
                    );
                }
            }

            // 8 次随机长度补充测试
            for (u32 i = 0; i < 8; ++i) {
                const size_t len = prng.below(static_cast<u32>(k_max_length) + 1);

                prng.fill_bytes(in.data(), len);
                // 用 AVX2 实现加密
                impla.ctr_crypt(outa.data(), in.data(), len, n, ctr);
                // 用 软件 实现加密
                impls.ctr_crypt(outs.data(), in.data(), len, n, ctr);

                cases++; // 调用次数 +1

                if (!test::mem_eq(outa.data(), outs.data(), len)) {
                    failed++; // 失败次数 +1

                    std::cout << std::format(
                        "MISMATCH: round={} len={} ctr=0x{:08x}\n", r, len, ctr
                    );
                }
            }
        }

        std::cout << std::format("共 {} 组用例，失败 {} 组\n", cases, failed);
        test::report("差分测试：AVX2 与软件实现输出一致", failed == 0);
    }

    // ==================== 往返测试 ====================
    void roundtrip_test(u64 seed)
    {
        std::cout << "======== 往返测试 ========\n";
        std::cout << std::format("PRNG seed: 0x{:016x}\n", seed);

        test::PRNG prng(seed ^ 0x5eed5eed5eed5eedULL);

        constexpr size_t k_max_length = 1024;
        constexpr u32 k_rounds = 64;

        std::vector<byte> plaintext(k_max_length);
        std::vector<byte> ciphertext(k_max_length);
        std::vector<byte> decrypted(k_max_length);

        size_t failed = 0; // 失败次数

        // ---- CTR 往返（含跨实现组合）----
        for (u32 r = 0; r < k_rounds; ++r) {
            byte k[op4::ks];
            byte n[op4::ns];

            const u32    ctr = prng.below(0x40000000u);
            const size_t len = prng.below(static_cast<u32>(k_max_length) + 1); // 含 0

            prng.fill_bytes(k, sizeof k);
            prng.fill_bytes(n, sizeof n);

            prng.fill_bytes(plaintext.data(), len);

            const cipher::op4::avx2::OP4 impla(k);
            cipher::op4::soft::OP4 impls(k);

            // AVX2 加密 -> AVX2 解密
            impla.ctr_crypt(ciphertext.data(), plaintext.data(), len, n, ctr);
            impla.ctr_crypt(decrypted.data(), ciphertext.data(), len, n, ctr);
            if (!test::mem_eq(decrypted.data(), plaintext.data(), len)) {
                failed++;
                std::cout << std::format("CTR(avx2->avx2) MISMATCH: round={} len={}\n", r, len);
            }

            // AVX2 加密 -> 软件解密（跨实现往返）
            impla.ctr_crypt(ciphertext.data(), plaintext.data(), len, n, ctr);
            impls.ctr_crypt(decrypted.data(), ciphertext.data(), len, n, ctr);
            if (!test::mem_eq(decrypted.data(), plaintext.data(), len)) {
                failed++;
                std::cout << std::format("CTR(avx2->soft) MISMATCH: round={} len={}\n", r, len);
            }

            // 软件加密 -> AVX2 解密（跨实现往返）
            impls.ctr_crypt(ciphertext.data(), plaintext.data(), len, n, ctr);
            impla.ctr_crypt(decrypted.data(), ciphertext.data(), len, n, ctr);
            if (!test::mem_eq(decrypted.data(), plaintext.data(), len)) {
                failed++;
                std::cout << std::format("CTR(soft->avx2) MISMATCH: round={} len={}\n", r, len);
            }
        }
        test::report("CTR 往返：密文可还原为明文（含跨实现）", failed == 0);

        // ---- ECB 往返（仅软件实现提供 ECB）----
        failed = 0;
        constexpr size_t k_max_blocks = 16;
        for (u32 r = 0; r < k_rounds; ++r) {
            byte k[op4::ks];
            prng.fill_bytes(k, sizeof k);
            const size_t blocks = prng.below(k_max_blocks) + 1;  // 1..16 块
            const size_t len = blocks * op4::bl;
            prng.fill_bytes(plaintext.data(), len);

            cipher::op4::soft::OP4 impls(k);
            impls.ecb_encrypt(ciphertext.data(), plaintext.data(), len);
            impls.ecb_decrypt(decrypted.data(), ciphertext.data(), len);
            if (!test::mem_eq(decrypted.data(), plaintext.data(), len)) {
                failed++;
                std::cout << std::format("ECB MISMATCH: round={} blocks={}\n", r, blocks);
            }
        }
        test::report("ECB 往返：密文可还原为明文", failed == 0);
    }

    // ==================== 首块密钥流 KAT ====================
    void kat_test()
    {
        std::cout << "======== 首块密钥流 KAT ========\n";
        std::cout << std::format("key:      {}\n", test::bytes_to_hex(key, op4::ks));
        std::cout << std::format("nonce:    {}\n", test::bytes_to_hex(nonce, op4::ns));
        std::cout << std::format("counter:  0x{:08x}\n", counter);

        // 路径 A：软件实现直接对 nonce ‖ counter 块做 ECB 加密
        byte block[op4::bl] = {};
        memcpy(block, nonce, op4::ns);
        pack32le(block + op4::ns, counter);

        byte ks_soft[op4::bl] = {};
        {
            cipher::op4::soft::OP4 impl(key);
            impl.ecb_encrypt(ks_soft, block, op4::bl);
        }

        // 路径 B：AVX2 实现对全零明文做 CTR 加密，密文即首块密钥流
        byte ks_avx[op4::bl] = {};
        {
            constexpr byte zero[op4::bl] = {};
            const cipher::op4::avx2::OP4 impl(key);
            impl.ctr_crypt(ks_avx, zero, op4::bl, nonce, counter);
        }

        std::cout << std::format("keystream: {}\n", test::bytes_to_hex(ks_avx, op4::bl));

        // 两条独立计算路径必须一致（始终强制执行）
        test::report("KAT: 软件实现与 AVX2 首块密钥流一致", test::mem_eq(ks_soft, ks_avx, op4::bl));

        // 与 golden 向量比对
        byte expected[op4::bl] = {};
        if (!test::hex_to_bytes(kat_expected_hex, expected, op4::bl)) {
            std::cout << "kat_expected_hex 格式非法（应为 32 个十六进制字符）\n";
            test::report("KAT: golden 向量格式", false);
        } else if (std::all_of(expected, expected + op4::bl, [](byte b) { return b == 0; })) {
            std::cout << "golden 值尚未设置（当前为全 0）："
                         "请将上方 keystream 的十六进制粘贴到 kat_expected_hex 后重跑。\n";
        } else {
            test::report("KAT: golden 向量匹配", test::mem_eq(expected, ks_avx, op4::bl));
        }
    }

    // ==================== 雪崩效应 ====================
    // 各类型名称（输出时区分）
    constexpr const char *avalanche_type_name(AVALANCHE_EFFECT_TYPE t) noexcept
    {
        switch (t) {
            case AVALANCHE_EFFECT_TYPE::PLAINTEXT_DIFF: return "明文";
            case AVALANCHE_EFFECT_TYPE::KEY_DIFF:       return "密钥";
            case AVALANCHE_EFFECT_TYPE::NONCE_DIFF:     return "Nonce";
            case AVALANCHE_EFFECT_TYPE::ROUNDKEY_DIFF:  return "轮密钥（密钥扩展）";
        }
        return "unknown";
    }

    // 汉明距离（比特数）
    inline u32 hamming_distance(const byte *a, const byte *b, size_t n) noexcept
    {
        u32 diff = 0;
        for (size_t i = 0; i < n; ++i) {
            diff += static_cast<u32>(std::popcount(static_cast<unsigned>(a[i] ^ b[i])));
        }
        return diff;
    }

    // 各类型的比较输出长度：轮密钥比较整个扩展密钥（128B），其余比较单个密文块（16B）
    template <AVALANCHE_EFFECT_TYPE type>
    constexpr size_t avalanche_out_len() noexcept
    {
        if constexpr (type == AVALANCHE_EFFECT_TYPE::ROUNDKEY_DIFF) {
            return op4::rks;
        } else {
            return op4::bl;
        }
    }

    // 四种类型：
    //   PLAINTEXT_DIFF : 随机密钥 + 随机明文，翻转明文 1 bit，比较 ECB 密文块
    //   KEY_DIFF       : 随机明文 + 随机密钥，翻转密钥 1 bit，比较 ECB 密文块
    //   NONCE_DIFF     : 随机密钥 + 随机 Nonce，翻转 Nonce 1 bit，
    //                    固定全零明文与计数器，比较 CTR 首块密文（= 首块密钥流）
    //   ROUNDKEY_DIFF  : 随机密钥，翻转密钥 1 bit，比较整个扩展轮密钥
    template <AVALANCHE_EFFECT_TYPE type>
    void avalanche_effect(u64 seed, u32 sample_count = 1'000'000)
    {
        constexpr size_t out_len  = avalanche_out_len<type>();
        constexpr size_t out_bits = out_len * 8;
        constexpr double ideal_diff_bits = out_bits / 2.0;

        std::cout << std::format("======== 雪崩效应（{}）========\n", avalanche_type_name(type));
        std::cout << std::format("随机数种子：0x{:016x}\n", seed);
        std::cout << std::format("样本数量：{}\n", sample_count);
        std::cout << std::format("比较输出长度：{} 字节（{} 比特）\n", out_len, out_bits);

        if (sample_count == 0) {
            test::report("雪崩效应：sample_count 为 0", false);
            return;
        }

        test::PRNG prng(seed);

        byte out1[out_len] = {};
        byte out2[out_len] = {};

        double total_bit_diff = 0.0;
        // Welford 在线算法：边跑边算均值/方差，
        // 不再保存全部历史（原来 10M 样本要 40 MB）
        u64    n_seen = 0;
        double mean = 0.0;
        double m2 = 0.0;
        std::vector<u32> bit_change_count(out_bits, 0);

        for (u32 i = 0; i < sample_count; ++i) {
            if constexpr (type == AVALANCHE_EFFECT_TYPE::PLAINTEXT_DIFF) {
                byte plaintext1[op4::bl] = {};
                byte plaintext2[op4::bl] = {};
                byte key[op4::ks] = {};

                prng.fill_bytes(plaintext1, op4::bl);
                prng.fill_bytes(key, op4::ks);

                memcpy(plaintext2, plaintext1, op4::bl);
                const u32 byte_index = prng.randint(0U, op4::bl - 1);
                const u32 bit_index  = prng.randint(0, 7);
                plaintext2[byte_index] ^= static_cast<byte>(1u << bit_index);

                cipher::op4::soft::OP4 cipher(key);
                cipher.ecb_encrypt(out1, plaintext1, op4::bl);
                cipher.ecb_encrypt(out2, plaintext2, op4::bl);
            } else if constexpr (type == AVALANCHE_EFFECT_TYPE::KEY_DIFF) {
                byte plaintext[op4::bl] = {};
                byte key1[op4::ks] = {};
                byte key2[op4::ks] = {};

                prng.fill_bytes(plaintext, op4::bl);
                prng.fill_bytes(key1, op4::ks);

                memcpy(key2, key1, op4::ks);
                const u32 byte_index = prng.randint(0U, op4::ks - 1);
                const u32 bit_index  = prng.randint(0, 7);
                key2[byte_index] ^= static_cast<byte>(1u << bit_index);

                cipher::op4::soft::OP4 cipher1(key1);
                cipher1.ecb_encrypt(out1, plaintext, op4::bl);
                cipher::op4::soft::OP4 cipher2(key2);
                cipher2.ecb_encrypt(out2, plaintext, op4::bl);
            } else if constexpr (type == AVALANCHE_EFFECT_TYPE::NONCE_DIFF) {
                // 固定全零明文 + 同一计数器，翻转 Nonce 1 bit，比较 CTR 首块密文
                constexpr byte zero[op4::bl] = {};
                byte nonce1[op4::ns] = {};
                byte nonce2[op4::ns] = {};
                byte key[op4::ks] = {};

                prng.fill_bytes(key, op4::ks);
                prng.fill_bytes(nonce1, op4::ns);

                memcpy(nonce2, nonce1, op4::ns);
                const u32 byte_index = prng.randint(0U, op4::ns - 1);
                const u32 bit_index  = prng.randint(0, 7);
                nonce2[byte_index] ^= static_cast<byte>(1u << bit_index);

                const u32 ctr = prng.below(0x40000000u);  // 避开 UINT32_MAX 检查
                cipher::op4::soft::OP4 cipher(key);
                cipher.ctr_crypt(out1, zero, op4::bl, nonce1, ctr);
                cipher.ctr_crypt(out2, zero, op4::bl, nonce2, ctr);
            } else if constexpr (type == AVALANCHE_EFFECT_TYPE::ROUNDKEY_DIFF) {
                // 翻转密钥 1 bit，比较密钥扩展输出的整个轮密钥
                byte key1[op4::ks] = {};
                byte key2[op4::ks] = {};

                prng.fill_bytes(key1, op4::ks);
                memcpy(key2, key1, op4::ks);
                const u32 byte_index = prng.randint(0U, op4::ks - 1);
                const u32 bit_index  = prng.randint(0, 7);
                key2[byte_index] ^= static_cast<byte>(1u << bit_index);

                cipher::op4::soft::OP4 cipher1(key1);
                cipher::op4::soft::OP4 cipher2(key2);
                const auto rk1 = cipher1.round_key();
                const auto rk2 = cipher2.round_key();
                memcpy(out1, rk1.data(), out_len);
                memcpy(out2, rk2.data(), out_len);
            }

            const u32 diff_bits = hamming_distance(out1, out2, out_len);
            total_bit_diff += diff_bits;

            ++n_seen;
            const double x     = static_cast<double>(diff_bits);
            const double delta = x - mean;
            mean += delta / static_cast<double>(n_seen);
            m2   += delta * (x - mean);

            for (size_t byte_idx = 0; byte_idx < out_len; ++byte_idx) {
                const byte diff_byte = out1[byte_idx] ^ out2[byte_idx];
                for (u32 bit_idx = 0; bit_idx < 8; ++bit_idx) {
                    if (diff_byte & (1u << bit_idx)) {
                        bit_change_count[byte_idx * 8 + bit_idx]++;
                    }
                }
            }
        }

        // ---- 统计 ----
        const double average_diff_bits = total_bit_diff / sample_count;
        const double variance  = m2 / static_cast<double>(sample_count);
        const double std_dev   = std::sqrt(variance);
        const double avg_ratio = average_diff_bits / static_cast<double>(out_bits) * 100.0;

        double sac_min = 100.0, sac_max = 0.0, sac_sum = 0.0;
        for (const auto cnt : bit_change_count) {
            const double ratio = static_cast<double>(cnt) / sample_count * 100.0;
            sac_sum += ratio;
            sac_min = std::min(sac_min, ratio);
            sac_max = std::max(sac_max, ratio);
        }
        const double sac_avg = sac_sum / static_cast<double>(bit_change_count.size());

        std::cout << std::format("平均变化比特数：{:.4f}（理想值：{:.1f}）\n",
            average_diff_bits, ideal_diff_bits);
        std::cout << std::format("平均比例：{:.4f} %\n", avg_ratio);
        std::cout << std::format("标准偏差：{:.4f}\n", std_dev);
        std::cout << std::format(
            "SAC 统计：最小比率 {:.4f} % / 最大比率 {:.4f} % / 平均比率 {:.4f} %\n",
            sac_min, sac_max, sac_avg);

        std::cout << "SAC 逐位比率（前 10 位）：\n";
        for (size_t b = 0; (b < 10) && (b < bit_change_count.size()); ++b) {
            const double ratio =
                static_cast<double>(bit_change_count[b]) / sample_count * 100.0;
            std::cout << std::format("第 {} 位：{:.4f} %\n", b, ratio);
        }

        const double margin_error = 1.96 * std_dev / std::sqrt(static_cast<double>(sample_count));
        std::cout << std::format("95% 置信区间：[{:.4f}, {:.4f}]\n",
            average_diff_bits - margin_error, average_diff_bits + margin_error);

        // 启发式回归护栏（阈值刻意宽松）：正常应落在 ~50%；
        // 一旦出现"分支漏写 → 静默全 0"或粘滞位（某位恒 0%/100%），这里会显式 FAIL。
        // 跑出基线后可按需收紧。
        constexpr double k_avg_lo = 45.0, k_avg_hi = 55.0;
        const bool pass =
            (avg_ratio >= k_avg_lo) && (avg_ratio <= k_avg_hi) &&
            (sac_min > 1.0) && (sac_max < 99.0);
        test::report(
            std::format("雪崩效应（{}）：平均比例接近 50%，无粘滞位",
                avalanche_type_name(type)).c_str(),
            pass);
    }

    // 一个简单场景加解密测试
    void encryption_test()
    {
        std::cout << "======== 加/解密测试 ========\n";
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
        std::cout << "======== 性能测试 ========\n";
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
                "\t加密 {:.2f} MB 数据的用时统计：\n"
                "\t\t最小用时: {:.4f}.\n"
                "\t\t最大用时: {:.4f}.\n"
                "\t\t平均用时: {:.4f}.\n",
                (static_cast<double>(length) / 1024 / 1024), min_timer, max_timer, avg_timer);
            std::cout << std::format(
                "\t平均性能表现: {:.4f} MB/s.\n",
                (static_cast<double>(length) / avg_timer) / 1024 / 1024);

            return avg_timer;
        };
        constexpr size_t length = 16ULL * 1024 * 1024;
        constexpr u32 count = 10;

        std::vector<double> total_timer(count);
        std::vector<byte> out(length);
        std::vector<byte> in(length);

        double avx2_timer = 0.0;
        double soft_timer = 0.0;
        {
            cipher::op4::avx2::OP4 op4(key);

            for (u32 r = 0; r < count; ++r) {
                auto start = timer();
                op4.ctr_crypt(out.data(), in.data(), length, nonce);
                auto stop = timer();
                total_timer[r] = (stop - start);
            }

            std::cout << "AVX2 实现\n";
            avx2_timer = calculation_time(length, total_timer, count);
        }

        {
            cipher::op4::soft::OP4 op4(key);

            for (u32 r = 0; r < count; ++r) {
                auto start = timer();
                op4.ctr_crypt(out.data(), in.data(), length, nonce);
                auto stop = timer();
                total_timer[r] = (stop - start);
            }

            std::cout << "软件 实现\n";
            soft_timer = calculation_time(length, total_timer, count);
        }

        std::cout << std::format("");
    };

    // ==================== 安全性测试 ====================
    void security_test()
    {
        std::cout << "======== 安全性测试 ========\n";

        {
            std::cout << "1. 密钥碰撞测试\n";
            byte ka[op4::ks] = {0x01};
            byte kb[op4::ks] = {0xcc};

            cipher::op4::soft::OP4 a(ka);
            cipher::op4::soft::OP4 b(kb);

            std::cout << "Key A:\t\t\t\t\t\t\t\tKey B:\n";
            test::print_diff_hex(ka, kb, op4::ks, op4::ks, 16, true);

            std::cout << "Round key A:\t\t\t\t\t\t\tRound key B:\n";
            test::print_diff_hex(
                a.round_key().data(),
                b.round_key().data(),
                op4::rks,
                op4::rks,
                16,
                true
            );

            test::report("密钥碰撞回归测试（不同密钥不得共享轮密钥）", a.round_key() != b.round_key(), true);
        }

        {
            std::cout << "2. 结构化密钥塌缩统计\n";
            std::set<std::array<byte, op4::rks>> distinct;
            for (u32 x = 0; x < 256; ++x) {
                byte k[op4::ks] = {};
                k[0] = static_cast<byte>(x);
                cipher::op4::soft::OP4 c(k);
                distinct.insert(c.round_key());
            }
            // 修复前预期 ~151；修复后必须是 256
            test::report(
                std::format("单字节前缀密钥族：256 个密钥应产生 256 套轮密钥（实际 {}）", distinct.size()),
                distinct.size() == 256,
                true
            );
        }

        {
            std::cout << "3. 碰撞后果演示\n";
            byte ka[op4::ks] = {}; ka[0] = 0x01;
            byte kb[op4::ks] = {}; kb[0] = 0xCC;
            constexpr byte pt[op4::bl] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
            byte ct[op4::bl], rt[op4::bl];

            cipher::op4::soft::OP4 a(ka);
            cipher::op4::soft::OP4 b(kb);
            a.ecb_encrypt(ct, pt, op4::bl);   // 用密钥 A 加密
            b.ecb_decrypt(rt, ct, op4::bl);   // 用密钥 B 解密
            test::report("碰撞后果：密钥 A 加密的数据可用密钥 B 解密", !test::mem_eq(rt, pt, op4::bl), true);
        }

        // ---- 1. g_s 全普查：256 个 s × 256 个 x，毫秒级 ----
        {
            std::cout << "4. g_s 单射性普查\n";
            auto rotl8m = [](u32 x) { x &= 0xFF; return ((x << 5) | (x >> 3)) & 0xFF; };
            u32 s_collide = 0, total_pairs = 0, min_img = 256, max_img = 0;
            for (u32 s = 0; s < 256; ++s) {
                u32 pairs = 0;
                for (u32 a = 0; a < 256; ++a)
                    for (u32 b = a + 1; b < 256; ++b) {
                        const u32 ya = (a + rotl8m(a ^ s)) & 0xFF;
                        const u32 yb = (b + rotl8m(b ^ s)) & 0xFF;
                        if (ya == yb) ++pairs;
                    }
                if (pairs) ++s_collide;
                total_pairs += pairs;
            }
            std::cout << std::format(
                "\t非单射的 s：{}/256，ΣC(s)={}，最坏像 {}（s=0 时为 151）\n",
                s_collide, total_pairs, min_img);
            // 若 s_collide == 256：byte-0 孪生覆盖 ~74% 密钥，碰撞对总数 ≈ 2^240·ΣC(s)
        }

        // ---- 2. 字节 0 孪生密度（在真实 OP4 上测，区分“仅 s=0”与“全部 s”）----
        {
            std::cout << "5. 字节 0 孪生密度\n";
            test::PRNG prng(0xA17A0000ULL);
            constexpr u32 trials = 4096;   // 每个密钥扫 256 个变体，控制总耗时
            u32 twinned = 0;
            for (u32 t = 0; t < trials; ++t) {
                byte k[op4::ks] = {};
                prng.fill_bytes(k, sizeof k);
                const auto rk0 = cipher::op4::soft::OP4(k).round_key();
                for (u32 x = 0; x < 256; ++x) {
                    if (x == k[0]) continue;
                    byte k2[op4::ks];
                    memcpy(k2, k, sizeof k2);
                    k2[0] = static_cast<byte>(x);
                    if (cipher::op4::soft::OP4(k2).round_key() == rk0) { ++twinned; break; }
                }
            }
            std::cout << std::format("\t孪生密度：{}/{} = {:.2f} %\n",
                twinned, trials, 100.0 * twinned / trials);
            // 仅 s=0 已证明 → ≥ ~0.29 %；若全部 s 破裂 → 预期 ~74 %
        }

        // ---- 3. 族塌缩精确值（验证 151）----
        {
            std::cout << "6. (x,0,…,0) 族塌缩统计\n";
            std::set<std::array<byte, op4::rks>> distinct;
            for (u32 x = 0; x < 256; ++x) {
                byte k[op4::ks] = {};
                k[0] = static_cast<byte>(x);
                distinct.insert(cipher::op4::soft::OP4(k).round_key());
            }
            std::cout << std::format("\t256 个密钥 → {} 套轮密钥\n", distinct.size());
        }
    }
}
// clang-format on

void op4_test()
{
    try {
        u64 seed = get_test_seed();
        differential_test(seed);
        roundtrip_test(seed);
        kat_test();

        avalanche_effect<AVALANCHE_EFFECT_TYPE::PLAINTEXT_DIFF>(seed ^ 0xA17A0000ULL);
        avalanche_effect<AVALANCHE_EFFECT_TYPE::KEY_DIFF>(seed ^ 0xA17A0001ULL);
        avalanche_effect<AVALANCHE_EFFECT_TYPE::NONCE_DIFF>(seed ^ 0xA17A0002ULL);
        avalanche_effect<AVALANCHE_EFFECT_TYPE::ROUNDKEY_DIFF>(seed ^ 0xA17A0003ULL);

        encryption_test();
        speed_test();

        security_test();
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
    }
}

int main()
{
#ifdef _WIN32
    UINT chcp = GetConsoleOutputCP();
    SetConsoleOutputCP(CP_UTF8);
#endif

    op4_test();

#ifdef _WIN32
    SetConsoleOutputCP(chcp);
#endif
    return 0;
}

#undef _CRT_SECURE_NO_WARNINGS
