// include/op4_constant.hh
#pragma once
#include <bit_utils.hh>

namespace cipher::op4 {
    constexpr u32 bl = 16;        // Block length
    constexpr u32 ks = 32;        // Key length
    constexpr u32 ns = 12;        // Nonce length
    constexpr u32 nk = 4;         // Key word length
    constexpr u32 nr = 8;         // Number of rounds
    constexpr u32 rks = bl * nr;  // Length of the RoundKey
}
