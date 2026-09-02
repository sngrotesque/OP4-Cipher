# OP4 (v1.0)
![C++](https://img.shields.io/badge/C%2B%2B-11%2B-blue) ![SIMD](https://img.shields.io/badge/SIMD-AVX2-orange) ![Benchmark](https://img.shields.io/badge/benchmark-3.7%20GB%2Fs-brightgreen) ![License](https://img.shields.io/badge/license-MIT-green)

> **OP4** 是一个自行设计的 128-bit 分组对称加密算法：256-bit 密钥、96-bit nonce、CTR 模式，  
> 附带 AVX2 向量化实现。两个文件、零依赖，在消费级 CPU 上吞吐约 **3.7 GB/s**。

> OP4 由 [栀子鱼鱼花 (SN-Grotesque)](https://github.com/sngrotesque) 设计与实现。

**公开征集密码分析结果（欢迎 issue 讨论）**

## 简介

OP4 是我个人设计并实现的对称加密算法。  
名字含义为四则运算（four fundamental operations of arithmetic）。

设计出发点：
 - **以最简方式实现分组对称加密算法**：仅使用循环移位+加法+乘法完成算法核心逻辑。
 - **对现代 CPU 友好**：配合状态转置的向量化实现（见 [SIMD 优化原理](#simd-优化原理)），性能从延迟受限区间推进到吞吐量受限区间；
 - **极简部署**：C++11、无第三方依赖。

## 目录
 - [安全性声明](#安全性声明)
 - [性能](#性能)
 - [算法规范](#算法规范)

## 安全性声明

1.  **v1.0** 版本实锤密钥扩展算法存在极其严重的密钥碰撞情况，详情请看 [Security.md](v1.0_security.md)。
    只需要构建这样两个密钥，即可得到完全相同的轮密钥：
    - **KeyA** 为 `01 00 00 00 ... 00 00 00`
    - **KeyB** 为 `cc 00 00 00 ... 00 00 00`

## 性能

测试平台：
1. Windows 10 22H2
    测试环境：
    - CPU：Intel Core i5-12400F（6C / 12T，~4.4 GHz）
    - 内存：32 GB（2 × 16 GB）DDR4-3200 双通道
    - 编译：MSVC `-O2 -avx2`

    | 实现 | 吞吐 |
    | :--- | :--- |
    | 基准版（逐块处理，标量提取 + SSE） | ~360-385 MB/s |
    | AVX2（状态转置 + 16 块批处理） | **3680-3830 MB/s** |

    提升约 **12×**。此时输入+输出流量约 7+ GB/s，仍远低于双通道 DDR4-3200 的实测内存带宽（~35 GB/s），瓶颈不在内存。

欢迎通过 Issue / PR 提交更多平台数据。

## 算法规范

### 参数
| 参数 | 值 | 说明 |
| :--- | :--- | :--- |
| 分组长度 | 128 bit | 4 × 32-bit 字，小端 |
| 密钥长度 | 256 bit | |
| Nonce 长度 | 96 bit | CTR 模式 |
| 计数器 | 32 bit | 小端，逐块递增 |
| 轮数 | 8 | |
| 轮密钥 | 128 字节 | 由32字节密钥分派为每轮16字节的密钥，密钥编排展开 |
| 分组函数 | 双射 | 轮函数每一步可逆（请看纯软件实现的 ECB 模式） |
