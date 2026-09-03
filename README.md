# OP4 (v2.0)
![C++](https://img.shields.io/badge/C%2B%2B-20%2B-blue) 
![SIMD](https://img.shields.io/badge/SIMD-AVX2-orange) 
![Benchmark](https://img.shields.io/badge/AVX2-3.8%20GB%2Fs-brightgreen) 
![Tests](https://img.shields.io/badge/tests-11%2F11%20passed-success) 
![License](https://img.shields.io/badge/license-APACHE2-green) 

> **OP4** 是一个自行设计的 128-bit 分组对称加密算法：256-bit 密钥、96-bit nonce、CTR 模式，
> 附带 AVX2 向量化实现。两个文件、零依赖，在消费级 CPU 上吞吐约 **3.8 GB/s**。

> OP4 由 [栀子鱼鱼花 (SN-Grotesque)](https://github.com/sngrotesque) 设计与实现。

**公开征集密码分析结果（欢迎 issue 讨论）**

一些自分析报告：
 - [密钥扩展算法](doc/key_extension.md)

---

## 目录
- [安全性声明](#安全性声明)
- [性能](#性能)
- [算法规范](#算法规范)
- [快速上手](#快速上手)
- [API 参考](#api-参考)
- [测试](#测试)
- [项目结构](#项目结构)
- [许可证](#许可证)

---

## 免责声明

> **OP4 是个人设计的加密算法，未经任何第三方密码分析人员审计。**  
> **请勿用于生产环境中的机密数据加密。**   
> 实际项目请使用 AES-256-GCM、ChaCha20-Poly1305 等经过广泛分析并标准化的算法。

### v2.0（当前版本）

通过对密钥扩展算法的重新设计，修复了 v1.0 所存在的密钥碰撞问题，同时优化了扩散性和混淆性。  
所有 v2.0 的测试均通过。无其他已知安全性问题。

安全护栏测试（详见[测试](#测试)）：

| 测试项 | 结论 |
| :--- | :--- |
| 密钥碰撞回归（不同密钥共享轮密钥） | 未发现 |
| 单字节前缀密钥族（256 个密钥的轮密钥塌缩） | 256 套不同轮密钥 |
| 字节 0 孪生密度（4096 组随机密钥） | 0.00 % |
| feed 位置敏感性（半字节交换守卫） | 通过 |
| 迭代轮常数守卫（rc 退化检测） | 通过 |
| slide 构造守卫（K' = F1⊕C） | 通过 |

### v1.0（历史版本）

密钥扩展算法存在严重的密钥碰撞问题，详情请看 [v1.0_security.md](https://github.com/sngrotesque/OP4-Cipher/blob/v1.0-unsafe/v1.0_security.md)。  
只需构建如下两个密钥即可得到完全相同的轮密钥：
- **KeyA** 为 `01 00 00 00 ... 00 00 00`
- **KeyB** 为 `cc 00 00 00 ... 00 00 00`

### 公开征集密码分析

欢迎通过 Issue 提交差分分析、积分分析、代数分析、侧信道分析等任何攻击思路。  
尤其是对轮函数（仅 8 轮）和密钥扩展（无密钥白化、无常数表查找）的分析。

---

## 性能

### OP4-Cipher

测试环境：
- **CPU**：Intel Core i5-12400F
- **内存**：32 GB（2 × 16 GB）DDR4 3200 MHz
- **编译**：MSVC `/O2 /arch:AVX2`
- **数据量**：16 MB CTR 加密，10 次取平均

| 实现 | 吞吐 |
| :--- | :--- |
| AVX2（状态转置 + 16 块批处理） | **3809 MB/s** |
| 纯软件（标量逐块） | 364 MB/s |
| 加速比 | **~10.5×** |

### 与主流算法对比（同硬件测试）

在相同机器上使用 OpenSSL 3.3.0（`openssl speed -evp`，MSVC `/O2` 编译，
AES 走 AES-NI，ChaCha20 走 AVX2）进行对比，取大块（≥8 KB）渐近吞吐：

| 算法 | 8 KB 块 | 16 KB 块 | 渐近吞吐 |
| :--- | :--- | :--- | :--- |
| AES-256-CTR (AES-NI) | 8297710 k | 8336173 k | **~8.0 GB/s** |
| **OP4 (AVX2)** | — | — | **~3.8 GB/s** |
| ChaCha20 (AVX2) | 3396785 k | 3401875 k | ~3.3 GB/s |

> OP4 的 3.8 GB/s 为 16 MB 输入下自测程序结果（与上表大块渐近吞吐量级可比）；  
> AES / ChaCha20 为 `openssl speed` 结果。

分块尺寸明细（`openssl speed` 原始数据，单位 MB/s）：

| 块大小 | AES-256-CTR | ChaCha20 | 备注 |
| :--- | ---: | ---: | :--- |
| 16 B | 688 | 450 | 小块受调用开销支配 |
| 64 B | 2357 | 769 | |
| 256 B | 5523 | 1579 | |
| 1024 B | 7384 | 3205 | |
| 8192 B | 8103 | 3317 | |
| 16384 B | 8140 | 3322 | |

- **vs ChaCha20（同为 AVX2、纯软件轮函数）**：OP4 略快（3.8 vs 3.3 GB/s，约 +15%）。  
  两者均无专用指令加速，对比能反映轮函数本身的吞吐效率。
- **vs AES-256-CTR（AES-NI 专用指令）**：AES-NI 在硬件层面单轮完成一个完整分组，
  OP4 落后约 2.1×。这是「纯通用指令轮函数」与「专用密码指令」的固有差距，
  也是目前所有非 AES 算法（包括 ChaCha20）面对 AES-NI 的共同处境。
- OP4 的 AVX2 实现（3.8 GB/s）约为其纯软件实现（364 MB/s）的 **10.5×**。

欢迎通过 Issue / PR 提交更多平台数据。

---

## 算法规范

### 参数

| 参数 | 值 | 说明 |
| :--- | :--- | :--- |
| 分组长度 | 128 bit | 4 × 32-bit 字，小端 |
| 密钥长度 | 256 bit | 32 字节 |
| Nonce 长度 | 96 bit | CTR 模式 |
| 计数器 | 32 bit | 小端，逐块递增 |
| 轮数 | 8 | |
| 轮密钥长度 | 128 字节 | 32 字节密钥编排展开为 8 × 16 字节 |
| 分组函数 | 双射 | 轮函数每一步可逆 |

### 轮函数

每轮对 4 个 32-bit 状态字 `(s0, s1, s2, s3)` 执行以下运算：

1. **移位-加法层**
    ```
    s0 = rotl32(s0, 13) + s1 + s2 + s3
    s1 = rotl32(s1,  7) + s2 + s3 + s0
    s2 = rotl32(s2, 11) + s3 + s0 + s1
    s3 = rotl32(s3, 15) + s0 + s1 + s2
    ```
    注意此处使用顺序更新（后更新依赖先更新），因此不可并行展开为矩阵形式。

2. **乘法层（模 2^32）**
    ```
    s0 *= 0x71e961dd
    s1 *= 0x47dff15d
    s2 *= 0x172f4f2f
    s3 *= 0xf9c1e3c7
    ```
    4 个常数均为模 2^32 的奇数，保证可逆（乘法逆元存在）。
    逆常数分别为 `0xf6e1fe75`, `0x185beaf5`, `0xfb0a57cf`, `0x4d82edf7`。

3. **轮密钥异或**
    ```
    s0 ^= rk[r][0]
    s1 ^= rk[r][1]
    s2 ^= rk[r][2]
    s3 ^= rk[r][3]
    ```
    其中 `rk[r][j]` 为第 r 轮的 32-bit 轮密钥字。

### 密钥扩展

256-bit 主密钥 K 通过三阶段扩展为 8 × 128-bit 轮密钥（共 128 字节）：

1. **常数异或**
    ```
    F = K ⊕ key_constant[0..7]
    ```
    其中 `key_constant` 为 8 个固定 32-bit 常数（见 `key_extension.hh`）。

2. **半字节交换反馈**（迭代 4 次）
    ```
    F[i]        += K[i]        + byte_swap(K[i + 16])
    F[i + 16]   += K[i + 16]   + byte_swap(K[i])
    ```
    其中 `byte_swap(x)` 交换字节 x 的高 4 位与低 4 位。

3. **扩散变换**（迭代 4 次，每次 8 轮）
    ```
    rc = 0x9E3779B9 * (r + 1 + iter * 8)
    dk[i] += rotl32(dk[(i+1)&7] + dk[(i+2)&7], shift_n[i]) + dk[(i+3)&7] + rc
    ```
    其中 `shift_n[8] = {7, 11, 21, 8, 2, 13, 12, 17}`，`0x9E3779B9` 为黄金比例常数。  
    每轮 Step 2 + Step 3 的结果作为一个 16 字节的轮密钥快照依次输出。

### CTR 模式

计数器块 `nonce(96-bit) ‖ counter(32-bit)` 作为轮函数输入，输出密钥流与明文异或。  
计数器从 `ctr` 开始逐块递增。加密与解密为同一操作。

---

## 快速上手

### 环境要求

- C++20 编译器（依赖 `std::endian`、`std::bit`、`std::format`、`std::to_array`）
  - MSVC 2022 (v19.30+)
  - GCC 12+
  - Clang 15+
- AVX2 指令集（AVX2 实现所需；纯软件实现无额外要求）

### 构建

直接编译（以 MSVC 为例）：
```cmd
cl /O2 /arch:AVX2 /std:c++20 /EHsc /I include src\op4_avx2.cc src\op4_soft.cc test\test.cc
```

### 基本加解密

```cpp
#include <op4.hh>

byte key[ciper::op4::ks] = { /* ... */ };
byte nonce[ciper::op4::ns] = { /* ... */ };

// 默认使用 AVX2 实现（不支持时请包含 op4_soft.hh 并使用 cipher::op4::soft::OP4）
ciper::OP4 cipher(key);
// 加密
cipher.ctr_crypt(ciphertext, plaintext, len, nonce);
// 解密
cipher.ctr_crypt(decrypted, ciphertext, len, nonce);
```

### 切换到纯软件实现

```cpp
#include <op4_soft.hh>
cipher::op4::soft::OP4 cipher(key);
cipher.ecb_encrypt(out, in, len);   // ECB 模式（仅软件实现提供）
cipher.ecb_decrypt(out, in, len);
cipher.ctr_crypt(out, in, len, nonce);  // CTR 模式
```

---

## API 参考

### `cipher::OP4`（默认命名空间，指向 AVX2 实现）

#### 构造/析构

```cpp
OP4(const byte key[op4::ks]);   // 32 字节密钥
~OP4();                          // 析构时安全擦除轮密钥
```

- 密钥指针为 `nullptr` 时抛出 `std::runtime_error`。
- 析构函数会调用 `SecureZeroMemory` 清除轮密钥存储。

#### CTR 加密/解密

```cpp
void ctr_crypt(byte *out, const byte *in, size_t len, const byte *n, u32 counter = 0) const;
```

- `n`：12 字节 nonce，**同一密钥下不同会话必须使用不同 nonce**（否则密钥流重用导致安全失效）。
- `counter`：起始计数器，默认 0。当 `counter == UINT32_MAX` 时抛出异常。
- `len`：任意长度（含非 16 倍数）。尾部不足 16 字节时使用密钥流前缀。
- 加密与解密为同一操作（异或密钥流）。
- 任意 `out`、`in`、`n` 为 `nullptr` 时抛出 `std::runtime_error`。

#### 轮密钥获取

```cpp
std::array<byte, op4::rks> round_key() const noexcept;
```

返回 128 字节轮密钥的拷贝（用于分析/调试，不推荐生产使用）。

### `cipher::op4::soft::OP4`（纯软件实现）

除 `ctr_crypt` 外，额外提供 ECB 模式：

```cpp
void ecb_encrypt(byte *out, const byte *in, size_t len);  // len 必须是 16 的倍数
void ecb_decrypt(byte *out, const byte *in, size_t len);  // len 必须是 16 的倍数
```

ECB 模式的 `len` 非 16 倍数时抛出 `std::runtime_error`。

### 安全注意事项

- **Nonce 重用**：同一密钥下重用 nonce + counter 组合会导致密钥流重用，XOR 两条密文即可泄露明文异或。
- **密钥流上限**：32-bit counter 限制单次会话最多 2^32 块（64 GB）数据。
- **无认证**：OP4 仅提供机密性，**不提供完整性保护**。如需 AEAD，建议外层附加 HMAC 或 Poly1305。
- **内存擦除**：析构时会擦除轮密钥，但调用方需自行管理明文/密文缓冲区。

---

## 测试

测试程序 `test/test.cc` 覆盖以下 11 类测试：
| 测试项 | 目的 | 当前结果 |
| :--- | :--- | :--- |
| 差分测试（1184 组用例） | AVX2 与软件实现输出一致性 | PASS |
| CTR 往返（含跨实现组合） | 密文可还原为明文 | PASS |
| ECB 往返 | 密文可还原为明文 | PASS |
| 首块密钥流 KAT（已知答案） | 软件实现与 AVX2 一致；golden 向量匹配 | PASS |
| 雪崩效应（明文， 100 万样本） | 平均比例 ~50%，无粘滞位 | PASS（50.00 %） |
| 雪崩效应（密钥， 100 万样本） | 平均比例 ~50%，无粘滞位 | PASS（50.00 %） |
| 雪崩效应（Nonce, 100 万样本） | 平均比例 ~50%，无粘滞位 | PASS（50.00 %） |
| 雪崩效应（轮密钥， 100 万样本） | 密钥扩展输出的 SAC | PASS（50.00 %） |
| 密钥碰撞回归（v1.0 漏洞守卫） | 不同密钥不得共享轮密钥 | PASS |
| 结构化密钥塌缩统计 | 256 个单字节前缀密钥 → 256 套轮密钥 | PASS |
| 安全性测试（孪生密度 / feed 敏感性 / 迭代常数 / slide 守卫） | 密钥扩展质量 | PASS |

### 运行测试

支持通过环境变量覆盖随机种子以保证可复现：

```bash
OP4_TEST_SEED=0x4f5034c0ffee2026
```

---

## 项目结构

```
.
├── include/
│   ├── op4.hh              # 对外入口，默认指向 AVX2 实现
│   ├── op4_avx2.hh         # AVX2 实现接口
│   ├── op4_soft.hh         # 纯软件实现接口
│   ├── op4_constant.hh     # 算法常量（块长、密钥长、轮数等）
│   ├── key_extension.hh    # 密钥扩展算法
│   └── bit_utils.hh        # 位运算工具（rotl/rotr/load32le/pack32le 等）
├── src/
│   ├── op4_avx2.cc         # AVX2 实现（SIMD 状态转置 + 16 块批处理）
│   └── op4_soft.cc         # 纯软件实现（ECB + CTR）
├── test/
│   ├── test.hh             # 测试工具（PRNG、hex 转换、报告）
│   └── test.cc             # 测试用例
└── README.md
```

### SIMD 优化原理

AVX2 实现的核心技巧是**状态转置**：
- 纯软件实现中，每个 128-bit 块的 4 个 32-bit 状态字按块内顺序处理。
- AVX2 实现将 8 个独立块的对应状态字打包进 256-bit 向量寄存器：
  向量 `v0` 的 lane k 存放第 k 块的 `s0`，`v1` 的 lane k 存放第 k 块的 `s1`，依此类推。
- 这样每个 `_mm256_add_epi32` / `_mm256_mullo_epi32` 指令可同时处理 8 个块。
- 主循环进一步将两组 8 块交错为 16 块批处理，利用编译器内联后的指令级并行度。
- 处理完成后通过 `unpack` + `permute2x128` 指令组合将转置状态还原为 8 个连续的
  128-bit 密钥流块。
