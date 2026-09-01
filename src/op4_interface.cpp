// op4_interface.cpp
// clang-format off
#include <cstdint>
#include <cstring>
#include <op4.hh>

extern "C" {
    __declspec(dllexport) void *OP4_New(const uint8_t *key);
    __declspec(dllexport) void OP4_Free(void *ctx);
    __declspec(dllexport) int OP4_CTRCrypt(
        void *ctx, uint8_t *out, const uint8_t *in, uint32_t len,
        const uint8_t *nonce, uint32_t counter);
}

void *OP4_New(const uint8_t *key)
{
    try {
        auto *p = new Cipher::OP4(key);
        return p;
    } catch (...) {
        return nullptr;
    }
}

void OP4_Free(void *ctx)
{
    delete static_cast<Cipher::OP4 *>(ctx);
}

int OP4_CTRCrypt(void *ctx, uint8_t *out, const uint8_t *in, uint32_t len,
    const uint8_t *nonce, uint32_t counter)
{
    if (!ctx) {
        return 1;
    }

    try {
        auto *cipher = static_cast<Cipher::OP4 *>(ctx);
        cipher->ctr_crypt(out, in, len, nonce, counter);
        return 0;
    } catch (...) {
        return 2;
    }
}
