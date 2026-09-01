# OP4
![C++](https://img.shields.io/badge/C%2B%2B-11%2B-blue) ![SIMD](https://img.shields.io/badge/SIMD-AVX2-orange) ![Benchmark](https://img.shields.io/badge/benchmark-3.7%20GB%2Fs-brightgreen) ![License](https://img.shields.io/badge/license-MIT-green)

> **OP4** 是一个自行设计的 128-bit 分组对称加密算法：256-bit 密钥、96-bit nonce、CTR 模式，  
> 附带 AVX2 向量化实现。两个文件、零依赖，在消费级 CPU 上吞吐约 **3.7 GB/s**。

## 简介

OP4 是我个人设计并实现的对称加密算法。  
名字含义为四则运算（four fundamental operations of arithmetic）。

设计出发点：
- **以最简方式实现分组对称加密算法**：仅使用循环移位+加法+乘法完成算法核心逻辑。
- **对现代 CPU 友好**：配合状态转置的向量化实现（见 [SIMD 优化原理](#simd-优化原理)），性能从延迟受限区间推进到吞吐量受限区间；
- **极简部署**：C++11、无第三方依赖。

## 目录
- [安全性声明](#安全性声明)
- [算法规范](#算法规范)
- [性能](#性能)
- [SIMD 优化原理](#simd-优化原理)
- [构建与使用](#构建与使用)
- [使用须知（CTR 模式）](#使用须知ctr-模式)
- [测试](#测试)
- [路线图](#路线图)
- [许可证](#许可证)
- [作者](#作者)

## 安全性声明

**本算法未经过任何形式的第三方密码分析、审计或公开破解验证。**

- OP4 出于学习与探索密码设计的目的而编写，其安全性**没有**经过同行评议
- **请勿使用 OP4 保护任何有价值的数据。** 需要加密真实数据时，请选择经过充分分析的成熟方案（AES-256-GCM、ChaCha20-Poly1305 等）
- 当前只提供 CTR 模式：仅机密性、无完整性，密文可被任意比特翻转而不被察觉；

- 欢迎对算法本身做密码分析（见 [路线图](#路线图)）。

## 算法规范

### 参数
| 参数 | 值 | 说明 |
|---|---|---|
| 分组长度 | 128 bit | 4 × 32-bit 字，小端 |
| 密钥长度 | 256 bit | |
| Nonce 长度 | 96 bit | CTR 模式 |
| 计数器 | 32 bit | 小端，逐块递增 |
| 轮数 | 8 | |
| 轮密钥 | 128 字节 | 由32字节密钥分派为每轮16字节的密钥，密钥编排展开 |
| 分组函数 | 双射 | 轮函数每一步可逆（请看纯软件实现的 ECB 模式） |

### 轮函数

将 16 字节分组按小端解释为 4 个 32-bit 字 v0~v3，对 r = 0..7 依次执行：

```cpp
// 1) 移位混合（顺序更新：右边的 vi 取最新值；加法 mod 2^32）
v0 = rotl32(v0, 13) + v1 + v2 + v3
v1 = rotl32(v1,  7) + v2 + v3 + v0
v2 = rotl32(v2, 11) + v3 + v0 + v1
v3 = rotl32(v3, 15) + v0 + v1 + v2
// 2) 逐字模乘（mod 2^32；四个常数均为奇数，故可逆）
v0 = v0 * 0x71e961dd
v1 = v1 * 0x47dff15d
v2 = v2 * 0x172f4f2f
v3 = v3 * 0xf9c1e3c7
// 3) 轮密钥加（逐字异或 RK[r] 的 4 个小端字）
(v0, v1, v2, v3) ^= RK[r]
```

第 r 轮使用轮密钥的第 `16r .. 16r+15` 字节。

### 密钥编排

- **prevent_zero_key**（逐字节，消除全零/弱密钥）：
  ```cpp
  k[i] ^= ((k[i] + i) - k[i]) ^ (k[i] << 1) ^ (k[i] >> 4)    // u8 运算
  // 注：(k + i) - k ≡ i (mod 256)，即 k[i] ^= i ^ (k[i]<<1) ^ (k[i]>>4)
  ```

- **key_obfuscation**：
  1. 每 4 字节一组：`k[i] += rotl8(k[i] ^ k[i+1] ^ k[i+2] ^ k[i+3], 5)`；
  2. 将 32 字节按小端装入 8 个 u32（v[0..7]），做一轮 ARX 混合后加回：
  ```cpp
  t[i] = v[i]
  t[7] += rotl32((v[0]^v[7]) + v[6], 15)
  t[6] += rotl32((v[7]^v[6]) + v[5], 19)
  t[5] += rotl32((v[6]^v[5]) + v[4], 21)
  t[4] += rotl32((v[5]^v[4]) + v[3], 29)
  t[3] += rotl32((v[4]^v[3]) + v[2], 13)
  t[2] += rotl32((v[3]^v[2]) + v[1],  7)
  t[1] += rotl32((v[2]^v[1]) + v[0], 23)
  t[0] += rotl32((v[1]^v[0]) + v[7], 17)
  k[4i..4i+3] = LE32(t[i])
  ```

- **展开**：从原始密钥出发，执行 4 次快照，每次快照前迭代 8 轮
  (prevent_zero_key + key_obfuscation)，共得到 128 字节轮密钥：
  ```cpp
  state = key
  for i in 0..3:
      repeat 8 times: state = key_obfuscation(prevent_zero_key(state))
      round_key[32i .. 32i+31] = state
  ```

### CTR 模式

密钥流块 = `E(nonce[12] || LE32(counter))`，counter 从初始值起逐块 +1。
密文 = 明文 ⊕ 密钥流；末尾不足 16 字节的块截断使用密钥流。
**加密与解密是同一个操作。**

## 性能

测试环境：
- CPU：Intel Core i5-12400F（6C/12T，~4.4 GHz）
- 内存：32 GB（2 × 16 GB）DDR4-3200 双通道
- 编译：MSVC `-O2 -avx2`

| 实现 | 吞吐 | 折算成本 |
|---|---|---|
| 基准版（逐块处理，标量提取 + SSE） | ~250–300 MB/s | ~220 周期/块（延迟受限） |
| AVX2（状态转置 + 16 块批处理） | **~3,700 MB/s** | ~18 周期/块（吞吐受限） |

提升约 **13×**。此时输入+输出流量约 7.4 GB/s，仍远低于双通道 DDR4-3200 的实测内存带宽（~35 GB/s），瓶颈不在内存。

欢迎通过 Issue / PR 提交更多平台数据。

## SIMD 优化原理

基准版慢，不是因为“SIMD 用得不够”，而是三个结构性问题：
1. CTR 各块之间完全独立，基准版却逐块串行；
2. 轮内 `v0→v1→v2→v3` 是一条长加法依赖链，叠加 `vpmulld` 约 10 周期的延迟，
   单轮依赖链超过 20 周期——**延迟受限**，换更宽的指令也无济于事；
3. 轮内加法是跨字的（v0 要加 v1、v2、v3），“一块一个 xmm”的布局下只能
   extract 回标量再拼回寄存器，白白消耗大量指令。
优化的核心是**状态转置（SoA 布局）**：一次处理 8/16 块，让 4 个向量寄存器
分别装“所有块的第 j 个字”：

```text
内存布局（按块）:                转置布局（按字）:
block0 : w0 w1 w2 w3            V0 = [w0(b0) w0(b1) ... w0(b7)]
block1 : w0 w1 w2 w3            V1 = [w1(b0) w1(b1) ... w1(b7)]
...                             V2 = [w2(b0) ... w2(b7)]
                                V3 = [w3(b0) ... w3(b7)]   ← 计数器字
```

OP4 恰好有一个适合转置的性质：轮内所有“每字不同”的量——旋转量、乘法常数、轮密钥字都**只依赖字的位置 j，与块号无关**。  
于是它们全部退化为“每寄存器一个广播常数”，整个轮函数变成纯 lane-wise 的add / rotate / mul / xor，**一条 shuffle 都不需要**。  
只在最后做一次 4×8 转置（unpack + `vperm2i128`）把密钥流写回内存布局。

工程细节：
- 主循环交错两组 8 块，用独立块的吞吐掩盖 `vpmulld` 的延迟；
- 8 状态 × 2 组 + 4 乘法常数 + 4 轮密钥广播 = 16 个 ymm，恰好用满寄存器组；
- 轮密钥在构造函数中预转置缓存，加密时按字广播，避免运行时重排。

## 构建与使用

### 环境要求

- x86-64，**AVX2**（当前为编译期硬性要求；运行时检测与回退见路线图）
- C++11 及以上，无第三方依赖

### 目录结构

```text
op4/
├── include/op4.hh      # 公共 API
├── src/op4.cc          # AVX2 实现
├── example/            # 示例程序
├── test/               # 差分测试 / 测试向量
├── bench/              # 基准程序
├── LICENSE
└── README.md
```

### 编译

```bash
# g++ / clang++
g++ -O2 -mavx2 -I include src/op4.cc example/main.cpp -o op4_example
```

```bat
@REM MSVC
cl /O2 /arch:AVX2 /I include src\op4.cc example\main.cpp
```

### 示例

```cpp
#include "op4.hh"
#include <cstdio>
#include <cstring>
int main()
{
    using Cipher::u8;
    // 256-bit 密钥与 96-bit nonce（请使用安全随机源生成）
    u8 key[32]   = {0x00, 0x01, 0x02 /* ... */};
    u8 nonce[12] = {0x00, 0x01, 0x02 /* ... */};
    const char *msg = "Hello, OP4!";
    const size_t len = std::strlen(msg) + 1;
    u8 ct[64], pt[64];
    Cipher::OP4 cipher(key);
    cipher.ctr_crypt(ct, (const u8 *)msg, len, nonce, 0);  // 加密
    cipher.ctr_crypt(pt, ct, len, nonce, 0);                // 解密：再跑一遍即可
    std::printf("%s\n", pt);  // "Hello, OP4!"
    return 0;
}
```

### API

| 成员 | 说明 |
|---|---|
| `OP4(const u8 key[32])` | 由 256-bit 密钥构造，执行密钥编排；`key` 为空抛出 `std::runtime_error` |
| `void ctr_crypt(u8 *out, const u8 *in, size_t len, const u8 *n, u32 counter = 0) const` | CTR 加/解密 `len` 字节；支持 `out == in` 就地处理；`counter` 指定起始计数器，便于分段与并行 |

## 使用须知（CTR 模式）

1. **同一 (key, nonce) 组合绝不能重复使用**，否则等价于一次一密本复用，
   明文 XOR 即可还原。随机生成 nonce 时，请将消息规模控制在远小于 2^32 条；
2. **单条消息长度上限 64 GiB**（2^32 块 × 16 B）：计数器回绕后密钥流将重复，
   实际使用请保持远低于此值；
3. **CTR 不提供完整性保护**。若需要认证，请配合 MAC 做 encrypt-then-MAC，
   或直接使用 AEAD 方案（见安全性声明）。

## 测试

- **差分测试**：保留一份标量参考实现，与 AVX2 实现逐字节比对。覆盖长度
  `0, 1, 15, 16, 17, 127, 128, 129, 255, 256, 257, 4095, 4096, 4097, 1MB`，
  以及 `0xFFFFFFF0` 附近的计数器回绕场景；
- **就地加密**（`out == in`）与分段（非零 `counter` 起始）用例；
- 计划提交 KAT（已知答案）测试向量，供第三方实现验证（见路线图）。

一次实际测试
```text
key:                                                            nonce:
        d6 c4 15 30 be c2 fa 65 50 54 d0 b1 a6 a2 8e 34                 ed c4 2b 60 9f b4 a8 11 55 60 b1 8e
        99 b2 1e f4 91 1e 2d 5c 45 5d b9 bb 69 c1 41 b6
ciphertext:                                                     plaintext:
        fd 14 43 8d 7e a4 62 fd 4e 90 16 02 27 ed c9 29                 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a
        63 17 17 18 4a b2 89 67 23 6b fe d5 6f ed 81 d0                 48 6f 73 74 3a 20 77 77 77 2e 67 6f 6f 67 6c 65
        c4 e6 d1 63 cd f9 b7 06 a3 b9 5f 17 c0 c0 27 d6                 2e 63 6f 6d 0d 0a 0d 0a 00 00 00 00 00 00 00 00
decrypted:                                                      ciphertext:
        47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a                 fd 14 43 8d 7e a4 62 fd 4e 90 16 02 27 ed c9 29
        48 6f 73 74 3a 20 77 77 77 2e 67 6f 6f 67 6c 65                 63 17 17 18 4a b2 89 67 23 6b fe d5 6f ed 81 d0
        2e 63 6f 6d 0d 0a 0d 0a 00 00 00 00 00 00 00 00                 c4 e6 d1 63 cd f9 b7 06 a3 b9 5f 17 c0 c0 27 d6

Encrypting 256.00 MB of data, time consumption:
        Min time taken: 0.0624.
        Max time taken: 0.1133.
        Avg time taken: 0.0690.
Average performance: 3712.2728 MB/s.
```

## 路线图

- [ ] 运行时 CPU 特性检测与回退（AVX2 → SSE2 → 标量参考实现）
- [ ] AVX-512 实现（`vprold` + zmm 一次 16 块，预计再 1.5~2×）
- [ ] 多线程支持（按 counter 区间分片，近线性扩展）
- [ ] KAT 测试向量与 CI
- [ ] AArch64 NEON 移植
- [ ] C API / 语言绑定
- [ ] 公开征集密码分析结果（欢迎 issue 讨论）

## 许可证

以 [Apache 2.0](LICENSE) 许可证发布。

## 作者

OP4 由 [栀子鱼鱼花 (SN-Grotesque)](https://github.com/sngrotesque) 设计与实现。
