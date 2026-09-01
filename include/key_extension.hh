// include/key_extension.hh
#pragma once
#include <op4.hh>
#include <bit_utils.hh>

namespace cipher::op4 {
    inline void prevent_zero_key(byte key[op4::ks]) noexcept
    {
        // Prevent weak keys
        for (u32 ki = 0; ki < op4::ks; ++ki) {
            key[ki] ^= (((key[ki] + ki) - key[ki]) ^ (key[ki] << 1) ^ (key[ki] >> 4));
        }
    }

    inline void key_obfuscation(byte k[op4::ks]) noexcept
    {
        for (u32 i = 0; i < op4::ks; i += 4) {
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

    inline void key_schedule_transformation(byte key[op4::ks]) noexcept
    {
        for (u32 r = 0; r < op4::nr; ++r) {
            prevent_zero_key(key);
            key_obfuscation(key);
        }
    }

    inline void key_extension(byte round_key[op4::rks], const byte key[op4::ks]) noexcept
    {
        byte copy_key[op4::ks]{0};
        memcpy(copy_key, key, op4::ks);

        for (u32 i = 0; i < op4::nk; ++i) {
            key_schedule_transformation(copy_key);
            memcpy(round_key + i * op4::ks, copy_key, op4::ks);
        }

        SecureZeroMemory(copy_key, op4::ks);
    }
}
