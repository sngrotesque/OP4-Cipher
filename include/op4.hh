#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

constexpr u32 OP4_BL = 16;                // Block length
constexpr u32 OP4_KS = 32;                // Key length
constexpr u32 OP4_NL = 12;                // Nonce length
constexpr u32 OP4_NK = 4;                 // Key word length
constexpr u32 OP4_NR = 8;                 // Number of rounds
constexpr u32 OP4_RKL = OP4_BL * OP4_NR;  // Length of the RoundKey

class OP4 {
private:
    alignas(16) u8 m_round_key[OP4_RKL] = {};
    alignas(16) u32 m_table_rk[OP4_NR][4] = {};

public:
    OP4() = delete;

public:
    OP4(const u8 key[OP4_KS]);
    ~OP4();

    OP4(const OP4 &other) = default;
    OP4 &operator=(const OP4 &other) = default;

public:
    void ctr_crypt(u8 *out, const u8 *in, size_t len, const u8 *n, u32 counter = 0) const;
};
