// include/op4_key_extension.hh
#pragma once
#include <op4_constant.hh>

namespace cipher::op4 {
    namespace detail {
        byte byte_swap(byte x);
        void xor_key_constants(byte key[op4::ks], const byte origin_key[op4::ks]);
        void mix_key_halves(byte key[op4::ks], const byte origin_key[op4::ks]);
        void diffuse_key_words(byte key[op4::ks], u32 iter);
    }
    void key_extension(byte round_key[op4::rks], const byte key[op4::ks]) noexcept;
}
