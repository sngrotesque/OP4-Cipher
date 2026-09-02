// include/key_extension.hh
#pragma once
#include <op4_constant.hh>
#include <bit_utils.hh>

namespace cipher::op4::detail {
    inline byte byte_top(byte x)
    {
        return x >> 4;
    }

    inline byte byte_bot(byte x)
    {
        return x & 0x0f;
    }

    inline byte byte_swap(byte x)
    {
        return (byte_bot(x) << 4) | byte_top(x);
    }
}

namespace cipher::op4::detail {
    constexpr u32 key_constant[8] = {
        0x38183a08U, 0x7bd0dfcaU, 0x25e9e4d5U, 0xcf4c5d88U,
        0x98317698U, 0x2ef6ef14U, 0x47c6abd9U, 0x644c7ad7U
    };

    inline void key_extension_step1(byte key[op4::ks], const byte origin_key[op4::ks])
    {
        for (u32 i = 0; i < 8; ++i) {
            pack32le(key + i * 4, load32le(origin_key + i * 4) ^ key_constant[i]);
        }
    }

    inline void key_extension_step2(byte key[op4::ks], const byte origin_key[op4::ks])
    {
        constexpr u32 ks_half = op4::ks / 2;
        for (u32 i = 0; i < ks_half; ++i) {
            key[i]           += origin_key[i] + byte_swap(origin_key[i + ks_half]);
            key[i + ks_half] += origin_key[i + ks_half] + byte_swap(origin_key[i]);
        }
    }

    inline void key_extension_step3(byte key[op4::ks], u32 iter)
    {
        constexpr u32 shift_n[8] = {7, 11, 21, 8, 2, 13, 12, 17};
        constexpr u32 golden = 0x9E3779B9U;

        u32 dk[8] = {}; // diffusion key

        for (u32 i = 0; i < (op4::ks / 4); ++i) {
            dk[i] = load32le(key + i * 4);
        }
        for (u32 r = 0; r < op4::nr; ++r) {
            u32 rc = golden * (r + 1 + iter * op4::nr);
            for (u32 i = 0; i < 8; ++i) {
                u32 x0 = dk[(i + 1) & 7] + dk[(i + 2) & 7];
                dk[i] += rotl32(x0, shift_n[i]) + dk[(i + 3) & 7] + rc;
            }
        }
        for (u32 i = 0; i < 8; ++i) {
            pack32le(key + i * 4, dk[i]);
        }
    }
}

namespace cipher::op4 {
    inline void key_extension(byte round_key[op4::rks], const byte key[op4::ks]) noexcept
    {
        byte flush_key[op4::ks]{0};
        memcpy(flush_key, key, op4::ks);

        detail::key_extension_step1(flush_key, key);

        for (u32 i = 0; i < (op4::nr / 2); ++i) {
            detail::key_extension_step2(flush_key, key);
            detail::key_extension_step3(flush_key, i);

            memcpy(round_key + i * op4::ks, flush_key, op4::ks);
        }

        SecureZeroMemory(flush_key, op4::ks);
    }
}
