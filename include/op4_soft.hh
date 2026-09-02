// include/op4_soft.hh
#pragma once
#include <op4_constant.hh>
#include <array>

namespace cipher::op4::soft {
    class OP4 {
    private:
        alignas(16) byte m_round_key[op4::rks] = {};

    public:
        OP4() = delete;
        OP4(const byte key[op4::ks]);
        ~OP4();

        OP4(const OP4 &other) = default;
        OP4 &operator=(const OP4 &other) = default;

    public:
        void ecb_encrypt(byte *out, const byte *in, size_t len);
        void ecb_decrypt(byte *out, const byte *in, size_t len);

        void ctr_crypt(byte *out, const byte *in, size_t len,
            const byte *n, u32 counter = 0) const;

    public:
        std::array<byte, op4::rks> round_key() const noexcept
        {
            return std::to_array(m_round_key);
        }
    };
}
