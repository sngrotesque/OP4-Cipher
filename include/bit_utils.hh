// include/bit_utils.hh
#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <bit>

using byte = uint8_t;
using u32 = uint32_t;

namespace cipher {
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

    inline u32 rotr32(const u32 x, const u32 n)
    {
        return (x >> n) | (x << (32 - n));
    }

    inline u32 rotr8(const u32 x, const u32 n)
    {
        return (x >> n) | (x << (8 - n));
    }

    inline u32 load32le(const byte block[4])
    {
        u32 w = 0;

        if constexpr (std::endian::native == std::endian::little) {
            memcpy(&w, block, sizeof(w));
        } else if constexpr (std::endian::native == std::endian::big) {
            w = (static_cast<u32>(block[0]))       |
                (static_cast<u32>(block[1]) <<  8) |
                (static_cast<u32>(block[2]) << 16) |
                (static_cast<u32>(block[3]) << 24);
        }

        return w;
    }

    inline void pack32le(byte block[4], u32 w) {
        if constexpr (std::endian::native == std::endian::little) {
            memcpy(block, &w, sizeof(w));
        } else if constexpr (std::endian::native == std::endian::big) {
            block[0] = static_cast<byte>(w); w >>= 8;
            block[1] = static_cast<byte>(w); w >>= 8;
            block[2] = static_cast<byte>(w); w >>= 8;
            block[3] = static_cast<byte>(w);
        }
    }
}
