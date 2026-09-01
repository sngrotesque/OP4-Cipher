// src/op4.cc
#include <op4_soft.hh>
#include <key_extension.hh>

#include <memory.h>

namespace {
    using namespace cipher;

    constexpr u32 op4_sbl = op4::bl / 4;
    constexpr u32 op4_rks_32 = op4::rks / 4;

    inline void xor_with_iv(u32 block[op4_sbl], const u32 iv[op4_sbl])
    {
        block[0] ^= iv[0];
        block[1] ^= iv[1];
        block[2] ^= iv[2];
        block[3] ^= iv[3];
    }

    namespace forward {
        inline void cipher(byte out[op4::bl], const byte in[op4::bl], const byte rk[op4::rks])
        {
            u32 keystream[op4_rks_32] = {};
            u32 state[op4_sbl] = {};

            // 初始化
            for (u32 i = 0; i < op4_sbl; ++i) {
                state[i] = load32le(in + i * sizeof(u32));
            }
            for (u32 i = 0; i < op4_rks_32; ++i) {
                keystream[i] = load32le(rk + i * sizeof(u32));
            }

            // 加密
            for (u32 r = 0; r < op4::nr; ++r) {
                // shift bit add
                state[0] = rotl32(state[0], 13) + state[1] + state[2] + state[3];
                state[1] = rotl32(state[1], 7)  + state[2] + state[3] + state[0];
                state[2] = rotl32(state[2], 11) + state[3] + state[0] + state[1];
                state[3] = rotl32(state[3], 15) + state[0] + state[1] + state[2];
                // multiply
                state[0] *= 0x71e961ddU;
                state[1] *= 0x47dff15dU;
                state[2] *= 0x172f4f2fU;
                state[3] *= 0xf9c1e3c7U;
                // round key add
                xor_with_iv(state, keystream + (r * op4_sbl));
            }

            // 写入
            for (u32 i = 0; i < op4_sbl; ++i) {
                pack32le(out + i * sizeof(u32), state[i]);
            }
        }
    }

    namespace inverse {
        inline void cipher(byte out[op4::bl], const byte in[op4::bl], const byte rk[op4::rks])
        {
            u32 keystream[op4_rks_32] = {};
            u32 state[op4_sbl] = {};

            // 初始化
            for (u32 i = 0; i < op4_sbl; ++i) {
                state[i] = load32le(in + i * sizeof(u32));
            }
            for (u32 i = 0; i < op4_rks_32; ++i) {
                keystream[op4_rks_32 - i - 1] = load32le(rk + i * sizeof(u32));
            }

            // 解密
            for (u32 r = 0; r < op4::nr; ++r) {
                // round key add
                xor_with_iv(state, keystream + (r * op4_sbl));
                // multiply
                state[0] *= 0xf6e1fe75U;
                state[1] *= 0x185beaf5U;
                state[2] *= 0xfb0a57cfU;
                state[3] *= 0x4d82edf7U;
                // shift bit add
                state[3] = rotr32(state[3] - state[0] - state[1] - state[2], 15);
                state[2] = rotr32(state[2] - state[3] - state[0] - state[1], 11);
                state[1] = rotr32(state[1] - state[2] - state[3] - state[0], 7);
                state[0] = rotr32(state[0] - state[1] - state[2] - state[3], 13);
            }

            // 写入
            for (u32 i = 0; i < op4_sbl; ++i) {
                pack32le(out + i * sizeof(u32), state[i]);
            }
        }
    }
}

namespace cipher::op4::soft {
    OP4::OP4(const byte key[op4::ks])
    {
        if (!key) {
            throw std::runtime_error("key is nullptr.");
        }
        byte copy_key[op4::ks] = {};
        memcpy(copy_key, key, op4::ks);
        op4::key_extension(m_round_key, copy_key);
        memset(copy_key, 0, op4::ks);
    }

    OP4::~OP4()
    {
        SecureZeroMemory(m_round_key, sizeof(m_round_key));
    }

    void OP4::ecb_encrypt(byte *out, const byte *in, size_t len)
    {
        if (!out || !in) {
            throw std::runtime_error("out/in is nullptr.");
        }
        if (len % op4::bl != 0) {
            throw std::runtime_error("The block size must be a multiple of 16.");
        }
        if (len == 0) {
            return;
        }

        for (size_t i = 0; i < len; i += op4::bl) {
            forward::cipher(out + i, in + i, m_round_key);
        }
    }

    void OP4::ecb_decrypt(byte *out, const byte *in, size_t len)
    {
        if (!out || !in) {
            throw std::runtime_error("out/in is nullptr.");
        }
        if (len % op4::bl != 0) {
            throw std::runtime_error("The block size must be a multiple of 16.");
        }
        if (len == 0) {
            return;
        }

        for (size_t i = 0; i < len; i += op4::bl) {
            inverse::cipher(out + i, in + i, m_round_key);
        }
    }

    void OP4::ctr_crypt(byte *out, const byte *in, size_t len, const byte *n, u32 c) const
    {
        if (c == UINT32_MAX) {
            throw std::runtime_error("The counter has been exhausted.");
        }
        byte keystream[op4::bl] = {};
        byte state[op4::bl] = {};
        memcpy(keystream, n, 12);

        size_t remaining = len;
        while (remaining >= op4::bl) {
            pack32le(keystream + 12, c++);
            forward::cipher(state, keystream, m_round_key);
            for (u32 i = 0; i < op4::bl; ++i) {
                out[i] = in[i] ^ state[i];
            }
            out += op4::bl;
            in += op4::bl;
            remaining -= op4::bl;
        }
        if (remaining > 0) {
            pack32le(keystream + 12, c++);
            forward::cipher(state, keystream, m_round_key);
            for (size_t i = 0; i < remaining; i++) {
                out[i] = in[i] ^ state[i];
            }
        }
    }
}
