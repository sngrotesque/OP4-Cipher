#include "op4.hh"

#include <immintrin.h>
#include <memory.h>

namespace {
    using s256 = __m256i;

    struct K8 {
        s256 b01;
        s256 b23;
        s256 b45;
        s256 b67;
    };

    inline void store256(void *x, s256 y) noexcept
    {
        _mm256_storeu_si256(reinterpret_cast<s256 *>(x), y);
    }

    inline s256 load256(const void *x) noexcept
    {
        return _mm256_loadu_si256(reinterpret_cast<const s256 *>(x));
    }

    inline s256 xor256(s256 x, s256 y) noexcept
    {
        return _mm256_xor_si256(x, y);
    }

    inline s256 rotl32x8(const s256 x, const int n) noexcept
    {
        return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
    }

    // 8 个块的转置状态执行一轮
    // vj 的 lane k = 第 k 块的第 j 个字；k0..k3 为广播后的轮密钥，m0..m3 为乘法常数
    inline void round8(
        s256 &v0, s256 &v1, s256 &v2, s256 &v3,
        const s256 k0, const s256 k1, const s256 k2, const s256 k3,
        const s256 m0, const s256 m1, const s256 m2, const s256 m3
    ) noexcept
    {
        // shift bit add
        const s256 u = _mm256_add_epi32(v2, v3);
        v0 = _mm256_add_epi32(_mm256_add_epi32(rotl32x8(v0, 13), v1), u);
        v1 = _mm256_add_epi32(_mm256_add_epi32(rotl32x8(v1, 7),  u), v0);
        const s256 p = _mm256_add_epi32(v0, v1);
        v2 = _mm256_add_epi32(_mm256_add_epi32(rotl32x8(v2, 11), v3), p);
        v3 = _mm256_add_epi32(_mm256_add_epi32(rotl32x8(v3, 15), p), v2);
        // multiply
        v0 = _mm256_mullo_epi32(v0, m0);
        v1 = _mm256_mullo_epi32(v1, m1);
        v2 = _mm256_mullo_epi32(v2, m2);
        v3 = _mm256_mullo_epi32(v3, m3);
        // round key add
        v0 = _mm256_xor_si256(v0, k0);
        v1 = _mm256_xor_si256(v1, k1);
        v2 = _mm256_xor_si256(v2, k2);
        v3 = _mm256_xor_si256(v3, k3);
    }

    // 8 个块的初始状态：nonce 三个字广播，计数器字 = ctr + {0..7}
    inline void init8(
        s256 &v0, s256 &v1, s256 &v2, s256 &v3,
        const s256 n0, const s256 n1, const s256 n2, const u32 ctr
    ) noexcept
    {
        v0 = n0;
        v1 = n1;
        v2 = n2;
        v3 = _mm256_add_epi32(
            _mm256_set1_epi32((int)ctr),
            _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7)
        );
    }

    // 4x8 转置：按字的转置状态 -> 连续 8 个 16B 密钥流块
    inline K8 pack8(s256 v0, s256 v1, s256 v2, s256 v3) noexcept
    {
        const s256 t0 = _mm256_unpacklo_epi32(v0, v1);
        const s256 t1 = _mm256_unpackhi_epi32(v0, v1);
        const s256 t2 = _mm256_unpacklo_epi32(v2, v3);
        const s256 t3 = _mm256_unpackhi_epi32(v2, v3);

        const s256 u0 = _mm256_unpacklo_epi64(t0, t2);   // [block0 | block4]
        const s256 u1 = _mm256_unpackhi_epi64(t0, t2);   // [block1 | block5]
        const s256 u2 = _mm256_unpacklo_epi64(t1, t3);   // [block2 | block6]
        const s256 u3 = _mm256_unpackhi_epi64(t1, t3);   // [block3 | block7]

        K8 k = {
            .b01 = _mm256_permute2x128_si256(u0, u1, 0x20), // [block0 | block1]
            .b23 = _mm256_permute2x128_si256(u2, u3, 0x20), // [block2 | block3]
            .b45 = _mm256_permute2x128_si256(u0, u1, 0x31), // [block4 | block5]
            .b67 = _mm256_permute2x128_si256(u2, u3, 0x31), // [block6 | block7]
        };

        return k;
    }

    inline void xor_store8(u8 *out, const u8 *in, const K8 k) noexcept
    {
        store256(out + 0,  xor256(load256(in + 0),  k.b01));
        store256(out + 32, xor256(load256(in + 32), k.b23));
        store256(out + 64, xor256(load256(in + 64), k.b45));
        store256(out + 96, xor256(load256(in + 96), k.b67));
    }

    inline void store8(u8 *out, const K8 k) noexcept
    {
        store256(out + 0,  k.b01);
        store256(out + 32, k.b23);
        store256(out + 64, k.b45);
        store256(out + 96, k.b67);
    }

    inline K8 ks8(
        s256 v0, s256 v1, s256 v2, s256 v3,
        const u32 (&trk)[Cipher::OP4_NR][4],
        const s256 m0, const s256 m1, const s256 m2, const s256 m3
    ) noexcept
    {
        for (u32 r = 0; r < Cipher::OP4_NR; ++r) {
            const s256 k0 = _mm256_set1_epi32((int)trk[r][0]);
            const s256 k1 = _mm256_set1_epi32((int)trk[r][1]);
            const s256 k2 = _mm256_set1_epi32((int)trk[r][2]);
            const s256 k3 = _mm256_set1_epi32((int)trk[r][3]);
            round8(v0, v1, v2, v3, k0, k1, k2, k3, m0, m1, m2, m3);
        }
        return pack8(v0, v1, v2, v3);
    }
}

namespace {
    inline void SecureZeroMemory(void *p, size_t n)
    {
        volatile char *vp = (volatile char *)p;
        while (n) {
            *vp++ = 0;
            n--;
        }
    }

    inline u32 rotl32(const u32 x, const u32 n)
    {
        return (x << n) | (x >> (32 - n));
    }

    inline u32 rotl8(const u32 x, const u32 n)
    {
        return (x << n) | (x >> (8 - n));
    }

    inline u32 load32le(const u8 x[4])
    {
        u32 w{};
        memcpy(&w, x, 4);
        return w;
    }

    void pack32le(u8 x[4], u32 w)
    {
        memcpy(x, &w, 4);
    }
}

namespace {
    using namespace Cipher;

    inline void prevent_zero_key(u8 key[OP4_KL]) noexcept
    {
        // Prevent weak keys
        for (u32 ki = 0; ki < OP4_KL; ++ki) {
            key[ki] ^= (((key[ki] + ki) - key[ki]) ^ (key[ki] << 1) ^ (key[ki] >> 4));
        }
    }

    inline void key_obfuscation(u8 k[OP4_KL]) noexcept
    {
        for (u32 i = 0; i < OP4_KL; i += 4) {
            k[i] += rotl8(k[i] ^ k[i + 1] ^ k[i + 2] ^ k[i + 3], 5);
        }
        u32 v[8]{};
        u32 t[8]{};

        t[0] = (v[0] = load32le(k));
        t[1] = (v[1] = load32le(k + 4));
        t[2] = (v[2] = load32le(k + 8));
        t[3] = (v[3] = load32le(k + 12));
        t[4] = (v[4] = load32le(k + 16));
        t[5] = (v[5] = load32le(k + 20));
        t[6] = (v[6] = load32le(k + 24));
        t[7] = (v[7] = load32le(k + 28));

        t[7] += rotl32((v[0] ^ v[7]) + v[6], 15);
        t[6] += rotl32((v[7] ^ v[6]) + v[5], 19);
        t[5] += rotl32((v[6] ^ v[5]) + v[4], 21);
        t[4] += rotl32((v[5] ^ v[4]) + v[3], 29);
        t[3] += rotl32((v[4] ^ v[3]) + v[2], 13);
        t[2] += rotl32((v[3] ^ v[2]) + v[1], 7);
        t[1] += rotl32((v[2] ^ v[1]) + v[0], 23);
        t[0] += rotl32((v[1] ^ v[0]) + v[7], 17);

        pack32le(k, t[0]);
        pack32le(k + 4, t[1]);
        pack32le(k + 8, t[2]);
        pack32le(k + 12, t[3]);
        pack32le(k + 16, t[4]);
        pack32le(k + 20, t[5]);
        pack32le(k + 24, t[6]);
        pack32le(k + 28, t[7]);
    }

    inline void key_schedule_transformation(u8 key[OP4_KL]) noexcept
    {
        for (u32 r = 0; r < OP4_NR; ++r) {
            prevent_zero_key(key);
            key_obfuscation(key);
        }
    }

    inline void key_extension(const u8 key[OP4_KL], u8 round_key[OP4_RKL]) noexcept
    {
        u8 copy_key[OP4_KL]{0};
        memcpy(copy_key, key, OP4_KL);

        for (u32 i = 0; i < OP4_NK; ++i) {
            key_schedule_transformation(copy_key);
            memcpy(round_key + i * OP4_KL, copy_key, OP4_KL);
        }

        SecureZeroMemory(copy_key, OP4_KL);
    }
}

namespace Cipher {
    OP4::OP4(const u8 key[OP4_KL])
    {
        if (!key) {
            throw std::runtime_error("key is nullptr.");
        }
        key_extension(key, m_round_key);

        for (u32 r = 0; r < OP4_NR; ++r) {
            for (u32 j = 0; j < 4; ++j) {
                m_table_rk[r][j] = load32le(m_round_key + r * OP4_BL + j * 4);
            }
        }
    }

    OP4::~OP4()
    {
        SecureZeroMemory(m_round_key, sizeof(m_round_key));
        SecureZeroMemory(m_table_rk, sizeof(m_table_rk));
    }

    void OP4::ctr_crypt(u8 *out, const u8 *in, size_t len, const u8 *n, u32 c) const
    {
        if (!out || !in || !n) {
            throw std::runtime_error("out/in/nonce is nullptr.");
        }
        if (len == 0) {
            return;
        }

        const s256 n0 = _mm256_set1_epi32((int)load32le(n + 0));
        const s256 n1 = _mm256_set1_epi32((int)load32le(n + 4));
        const s256 n2 = _mm256_set1_epi32((int)load32le(n + 8));
        const s256 m0 = _mm256_set1_epi32((int)0x71e961ddU);
        const s256 m1 = _mm256_set1_epi32((int)0x47dff15dU);
        const s256 m2 = _mm256_set1_epi32((int)0x172f4f2fU);
        const s256 m3 = _mm256_set1_epi32((int)0xf9c1e3c7U);

        u32 ctr = c;
        size_t full = len / OP4_BL;
        const size_t tail = len % OP4_BL;

        // 主循环：每次 16 块 = 每组 8 块交错
        while (full >= 16) {
            s256 a0, a1, a2, a3, b0, b1, b2, b3;

            init8(a0, a1, a2, a3, n0, n1, n2, ctr);
            init8(b0, b1, b2, b3, n0, n1, n2, ctr + 8);

            // 两组共用同一批轮密钥广播，编译器内联后会自动交织指令
            for (u32 r = 0; r < OP4_NR; ++r) {
                const s256 k0 = _mm256_set1_epi32((int)m_table_rk[r][0]);
                const s256 k1 = _mm256_set1_epi32((int)m_table_rk[r][1]);
                const s256 k2 = _mm256_set1_epi32((int)m_table_rk[r][2]);
                const s256 k3 = _mm256_set1_epi32((int)m_table_rk[r][3]);

                round8(a0, a1, a2, a3, k0, k1, k2, k3, m0, m1, m2, m3);
                round8(b0, b1, b2, b3, k0, k1, k2, k3, m0, m1, m2, m3);
            }

            xor_store8(out,       in,       pack8(a0, a1, a2, a3));
            xor_store8(out + 128, in + 128, pack8(b0, b1, b2, b3));

            out += 256;
            in += 256;
            full -= OP4_BL;
            ctr += OP4_BL;
        }

        // 剩余 8 块
        if (full >= 8) {
            s256 a0, a1, a2, a3;

            init8(a0, a1, a2, a3, n0, n1, n2, ctr);
            xor_store8(out, in, ks8(a0, a1, a2, a3, m_table_rk, m0, m1, m2, m3));

            out += 128;
            in += 128;
            full -= 8;
            ctr += 8;
        }

        // ---- 尾部（≤7 整块 + ≤15 字节）：多算几个块无所谓，反正每次调用只有一次 ----
        if (full > 0 || tail > 0) {
            alignas(32) u8 buf[128];
            s256 a0, a1, a2, a3;

            init8(a0, a1, a2, a3, n0, n1, n2, ctr);

            store8(buf, ks8(a0, a1, a2, a3, m_table_rk, m0, m1, m2, m3));

            const size_t t = (full * OP4_BL) + tail;
            for (size_t i = 0; i < t; ++i) {
                out[i] = in[i] ^ buf[i];
            }
        }
    }
}
