// src/op4_key_extension.cc
#include <op4_key_extension.hh>
#include <bit_utils.hh>

namespace {
    constexpr u32 key_constant[8] = {
        /*
        941111816    2077286346   636085461    3477888392
        2553378456   787934996    1204202457   1682733783
        */
        0x38183a08U, 0x7bd0dfcaU, 0x25e9e4d5U, 0xcf4c5d88U,
        0x98317698U, 0x2ef6ef14U, 0x47c6abd9U, 0x644c7ad7U
    };
    constexpr u32 shift_n[8] = {7, 11, 21, 8, 2, 13, 12, 17};
    constexpr u32 golden = 0x9E3779B9U; // 2654435769, nothing up my sleeve
}

namespace cipher::op4::detail { 
    byte byte_swap(byte x)
    {
        return rotl8(x, 4);
    }

    void xor_key_constants(byte key[op4::ks], const byte origin_key[op4::ks])
    {
        for (u32 i = 0; i < (op4::ks / 4); ++i) {
            pack32le(key + i * 4, load32le(origin_key + i * 4) ^ key_constant[i]);
        }
    }

    void mix_key_halves(byte key[op4::ks], const byte origin_key[op4::ks])
    {
        constexpr u32 ks_half = op4::ks / 2;
        for (u32 i = 0; i < ks_half; ++i) {
            key[i]           += origin_key[i] + byte_swap(origin_key[i + ks_half]);
            key[i + ks_half] += origin_key[i + ks_half] + byte_swap(origin_key[i]);
        }
    }

    void diffuse_key_words(byte key[op4::ks], u32 iter)
    {
        u32 dk[8] = {}; // diffusion key

        for (u32 i = 0; i < (op4::ks / 4); ++i) {
            dk[i] = load32le(key + i * 4);
        }
        for (u32 r = 0; r < op4::nr; ++r) {
            u32 rc = golden * (r + 1 + iter * op4::nr);
            for (u32 i = 0; i < (op4::ks / 4); ++i) {
                u32 x0 = dk[(i + 1) & 7] + dk[(i + 2) & 7];
                dk[i] += rotl32(x0, shift_n[i]) + dk[(i + 3) & 7] + rc;
            }
        }
        for (u32 i = 0; i < (op4::ks / 4); ++i) {
            pack32le(key + i * 4, dk[i]);
        }
    }
}

namespace cipher::op4 {
    void key_extension(byte round_key[op4::rks], const byte key[op4::ks]) noexcept
    {
        byte flush_key[op4::ks]{0};
        memcpy(flush_key, key, op4::ks);

        detail::xor_key_constants(flush_key, key);

        for (u32 i = 0; i < (op4::nr / 2); ++i) {
            detail::mix_key_halves(flush_key, key);
            detail::diffuse_key_words(flush_key, i);

            memcpy(round_key + i * op4::ks, flush_key, op4::ks);
        }

        SecureZeroMemory(flush_key, op4::ks);
    }
}
