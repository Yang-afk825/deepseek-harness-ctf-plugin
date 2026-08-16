# deepseek-harness-ctf-plugin

面向 **CTF（Capture The Flag）解题** 的 [DeepSeek Harness](https://github.com/deepseek-ai/DeepSeek-Harness) 插件 —— 让 Harness 的 agent **会打 CTF 题**。

> 基于 Cordis 插件框架，核心理念「一切皆插件」。本项目注册 **8 个解题工具** + **11 个 CTF 技能**，把 agent 从「被动工具箱」升级成「会自己识别题型、定策略、调用工具、解出 flag、写 WriteUp」的解题 agent。

---

## ✨ 能力清单

### 🔧 8 个工具（`ctx.tools`）

| 工具 | 功能 | 实现 |
|------|------|------|
| `hash_identify` | 按长度/字符集识别 30+ 哈希算法（MD5/SHA/CRC/NTLM…） | 纯 JS |
| `smart_decode` | 自动尝试 Base64 / Hex / URL / ROT13 链式解码 | 纯 JS |
| `caesar_brute` | 凯撒密码全 26 位移爆破 | 纯 JS |
| `classical_cipher` | 30+ 古典密码（维吉尼亚/栅栏/培根/猪圈/摩斯/棋盘…） | Python bridge |
| `crypto_hash` | MD5/SHA1/SHA256/SHA512/HMAC/CRC 计算 | Python bridge |
| `crypto_aes` | AES 加解密（ECB/CBC，PKCS7） | Python bridge |
| `crypto_rc4` | RC4 加解密 | Python bridge |
| `rsa_basic` | RSA 加解密/密钥生成/因子分解提示 | Python bridge |

### 🧠 11 个技能（`ctx.skills`）

| 技能 | 方向 |
|------|------|
| `solve-challenge` | 解题编排器：环境检测 → 信息收集 → 题型分类 → Quick Wins |
| `ctf-crypto` | 密码学攻击（RSA/AES/ECC/格/PRNG…） |
| `ctf-web` | Web 漏洞（SQLi/XSS/SSTI/SSRF/JWT/反序列化…） |
| `ctf-pwn` | 二进制利用（栈/堆/格式化字符串/ROP…） |
| `ctf-reverse` | 逆向工程 |
| `ctf-forensics` | 取证/隐写/流量分析 |
| `ctf-misc` | 杂项（编码/隐写/沙箱逃逸…） |
| `ctf-osint` | 开源情报 |
| `ctf-malware` | 恶意软件/网络流量分析 |
| `ctf-ai-ml` | AI/ML 方向 |
| `ctf-writeup` | 标准化 WriteUp 生成 |

---

## 🏗️ 架构：三层能力闭环

```
┌─────────────────────────────────────────────────┐
│  L3 闭环层：拿题 → 识别题型 → 定策略 → 执行 →   │
│              提 flag → 写 WriteUp（全自动）      │
├─────────────────────────────────────────────────┤
│  L2 技能层（ctx.skills）：解题流程 + 题型识别     │
│      从 ctf-skills 的 SKILL.md 零重写加载          │
├─────────────────────────────────────────────────┤
│  L1 工具层（ctx.tools）：会算                    │
│      纯 JS 3 个 + Python bridge 复用 5 个          │
└─────────────────────────────────────────────────┘
```

**核心设计：资产复用，零重写。**

- **纯 JS 工具**：哈希识别、智能解码、凯撒爆破，零外部依赖
- **Python bridge**：`py/ctf_bridge.py` 通过 `execFileSync` 调用系统 Python，`sys.path` 动态插入 Yang-Web 路径，复用其 `misc_crypto` / `crypto_engine` 两大引擎（30+ 古典密码 + AES/RC4/RSA），**不用重写任何算法**
- **技能层**：`ctx.skills.registerProvider` 按需从本地 ctf-skills 仓库加载 11 个 SKILL.md

---

## 📦 安装与使用

> ⚠️ 本插件开发于 **DeepSeek Harness v0.1.0-rc.5** monorepo，推荐在该 monorepo 内使用（依赖 workspace 协议 + tsdown 构建）。

### 方式一：放入 Harness monorepo（推荐）

```bash
# 将本仓库内容放到 monorepo 的 packages/ctf/dsh-ctf/
# 在 tsconfig.host.json 的 references 中加包路径
# pnpm install && pnpm run build:lib:host
```

### 方式二：作为独立插件加载到 web profile

```bash
# 1. 在 ~/.dsh/profiles/web/package.json 加依赖
#    "dependencies": { "@deepseek-ai/dsh-ctf": "file:<本仓库路径>" }
# 2. 在 cordis.patch.yml 加
#    - insert: [{ id: dsh-ctf, name: '@deepseek-ai/dsh-ctf' }]
# 3. dsh web --port 8787
```

**Python bridge 依赖**：系统需有 Python 3（bridge 默认调用 `python`/`python3`，可用 `PYTHON_BINARY` 环境变量指定），以及 Yang-Web 引擎路径（可用 `YANG_WEB_PATH` 指定，默认从包内相对定位）。

---

## ✅ 验证实录

两道题**全自动**解出（agent 独立完成，无逐步喂题）：

### 1. RSA 题
agent 加载 `ctf-crypto` 技能 + 调 `rsa_basic`，推理并解出明文。

### 2. 多层编码题（caesar(7) → base64 → hex）
agent 独立完成：识别题型 → 链式解码（hex → base64）→ 凯撒爆破（shift=7）→ 提 flag → 写 WriteUp。

```
密文：5546704b536e74714d47747764573566616d383063485666644452365957783566513d3d
flag：ISCC{c0ding_ch4in_m4ster}
```

---

## 📁 目录结构

```
.
├── src/
│   └── index.ts          # 插件入口：8 工具 + 11 技能注册
├── py/
│   ├── ctf_bridge.py     # Python bridge（复用 Yang-Web 引擎）
│   ├── test_bridge.mjs   # bridge 功能测试
│   └── test_skills.mjs   # 技能加载测试
├── package.json
├── tsconfig.json
└── README.md
```

---

## ⚠️ 已知限制与后续

- 技能 SKILL.md content 偏大（ctf-crypto 约 3.8 万字符），需精简链接描述、深度文档改 fs 按需读
- Python bridge 依赖本机 Yang-Web 引擎路径，跨机部署需配置 `YANG_WEB_PATH`
- 未接沙箱层（L4），真实 pwn/web 题的隔离执行环境待接入
- npm 上的 `@deepseek-ai/dsh-*` 包版本（0.0.1-rc.1）较本插件开发时的 monorepo（0.1.0-rc.5）旧，API 可能有差异

---

## License

[MIT](./LICENSE)
