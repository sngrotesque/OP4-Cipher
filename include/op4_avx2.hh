// include/op4_avx2.hh
#pragma once
#include <op4_constant.hh>
#include <array>

namespace cipher::op4::avx2 {
    class OP4 {
    private:
        alignas(16) byte m_round_key[op4::rks] = {};
        alignas(16) u32 m_table_rk[op4::nr][4] = {};

    public:
        OP4() = delete;

    public:
        OP4(const byte key[op4::ks]);
        ~OP4();

        OP4(const OP4 &other) = default;
        OP4 &operator=(const OP4 &other) = default;

    public:
        void ctr_crypt(byte *out, const byte *in, size_t len,
            const byte *n, u32 counter = 0) const;

    public:
        std::array<byte, op4::rks> round_key() const noexcept
        {
            return std::to_array(m_round_key);
        }
    };
}
