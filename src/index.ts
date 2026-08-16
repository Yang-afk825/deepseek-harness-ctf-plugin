/**
 * dsh-ctf：面向 CTF（Capture The Flag）解题的 Harness 工具插件。
 *
 * 当前提供三个纯 JS 实现、零外部依赖的基础工具：
 * - hash_identify  按长度/字符集识别常见哈希算法
 * - smart_decode   自动尝试 Base64 / Hex / URL / ROT13 解码
 * - caesar_brute   对凯撒密码做全 26 位移爆破
 *
 * 后续可继续接入 Yang-Web 的更多引擎（RSA 攻击、SQLi、隐写等）。
 * @module @deepseek-ai/dsh-ctf
 */

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'
import type { SkillCandidate, SkillDefinition } from '@deepseek-ai/dsh-skill'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'dsh-ctf'
export const inject = ['tools', 'skills']

// ---------------------------------------------------------------------------
// hash_identify 实现
// ---------------------------------------------------------------------------

interface HashPattern {
  algorithms: string[]
  test: (s: string) => boolean
}

const HASH_PATTERNS: HashPattern[] = [
  { algorithms: ['MD5', 'MD4', 'NTLM', 'LM', 'RipeMD-128', 'Haval-128', 'MySQL5'], test: (s) => /^[a-f0-9]{32}$/i.test(s) },
  { algorithms: ['SHA-1', 'Haval-160', 'RipeMD-160', 'Tiger-160'], test: (s) => /^[a-f0-9]{40}$/i.test(s) },
  { algorithms: ['SHA-256', 'SHA3-256', 'BLAKE2s', 'GOST'], test: (s) => /^[a-f0-9]{64}$/i.test(s) },
  { algorithms: ['SHA-512', 'SHA3-512', 'BLAKE2b', 'Whirlpool'], test: (s) => /^[a-f0-9]{128}$/i.test(s) },
  { algorithms: ['MySQL323', 'CRC16'], test: (s) => /^[a-f0-9]{16}$/i.test(s) },
  { algorithms: ['CRC32'], test: (s) => /^[a-f0-9]{8}$/i.test(s) },
]

function identifyHash(hash: string): string {
  const trimmed = hash.trim()
  if (trimmed.length === 0) return '空输入，无法识别'
  for (const p of HASH_PATTERNS) {
    if (p.test(trimmed)) return `可能是: ${p.algorithms.join(' / ')}（${trimmed.length} 个十六进制字符）`
  }
  return `未匹配常见哈希格式。输入 ${trimmed.length} 字符，非纯 hex 或长度不在 8/16/32/40/64/128 范围内`
}

// ---------------------------------------------------------------------------
// smart_decode 实现
// ---------------------------------------------------------------------------

/** 判断字符串里可打印 ASCII 的占比是否足够高（用于过滤解码乱码） */
function printableRatio(s: string): number {
  if (s.length === 0) return 0
  let printable = 0
  for (const c of s) {
    const code = c.charCodeAt(0)
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127)) printable++
  }
  return printable / s.length
}

function tryBase64(s: string): string | null {
  if (!/^[a-zA-Z0-9+/=]+$/.test(s) || s.length % 4 !== 0) return null
  try {
    const out = Buffer.from(s, 'base64').toString('utf8')
    if (out.length === 0) return null
    return printableRatio(out) > 0.85 ? out : null
  } catch {
    return null
  }
}

function tryHex(s: string): string | null {
  if (!/^[a-f0-9]+$/i.test(s) || s.length % 2 !== 0) return null
  try {
    const out = Buffer.from(s, 'hex').toString('utf8')
    if (out.length === 0) return null
    return printableRatio(out) > 0.85 ? out : null
  } catch {
    return null
  }
}

function tryUrlDecode(s: string): string | null {
  if (!/%[0-9a-fA-F]{2}/.test(s)) return null
  try {
    const out = decodeURIComponent(s)
    return out === s ? null : out
  } catch {
    return null
  }
}

function rotShift(s: string, shift: number): string {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97
    return String.fromCharCode(((c.charCodeAt(0) - base + 26 + shift) % 26) + base)
  })
}

function smartDecode(s: string): string {
  const results: string[] = []
  const b64 = tryBase64(s)
  if (b64 !== null) results.push(`[Base64] ${b64}`)
  const hex = tryHex(s)
  if (hex !== null) results.push(`[Hex] ${hex}`)
  const url = tryUrlDecode(s)
  if (url !== null) results.push(`[URL] ${url}`)
  const r13 = rotShift(s, 13)
  if (r13 !== s && printableRatio(s) < 0.9) results.push(`[ROT13] ${r13}`)
  if (results.length === 0) return '未识别出常见编码。可能需要 base32、异或、古典密码或其它手段进一步分析'
  return results.join('\n')
}

// ---------------------------------------------------------------------------
// caesar_brute 实现
// ---------------------------------------------------------------------------

// 常见英文单词，用于给爆破结果做一个粗略的"像不像明文"评分
const COMMON_WORDS = ['the', 'flag', 'ctf', 'and', 'you', 'are', 'this', 'that', 'with', 'have', 'from', 'this', 'password', 'key', 'hello', 'world']

function scoreEnglish(s: string): number {
  const lower = s.toLowerCase()
  let score = 0
  for (const w of COMMON_WORDS) {
    if (lower.includes(w)) score += w.length
  }
  return score
}

function caesarBrute(s: string): string {
  const lines: string[] = []
  let bestShift = -1
  let bestScore = -1
  for (let shift = 0; shift < 26; shift++) {
    const dec = rotShift(s, -shift)
    const sc = scoreEnglish(dec)
    if (sc > bestScore) {
      bestScore = sc
      bestShift = shift
    }
    lines.push(`ROT${String(shift).padStart(2, '0')}: ${dec}`)
  }
  if (bestShift >= 0 && bestScore > 0) {
    lines.push('')
    lines.push(`>>> 最可能是 ROT${bestShift}（命中英文特征）`)
  }
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// Python bridge 调用（复用 Yang-Web 引擎）
// ---------------------------------------------------------------------------

const PYTHON = process.env.CTF_PYTHON ?? 'C:/Program Files/Python312/python.exe'
const BRIDGE = process.env.CTF_BRIDGE ?? fileURLToPath(new URL('../py/ctf_bridge.py', import.meta.url))

function execPython(tool: string, args: Record<string, unknown>): string {
  try {
    const out = execFileSync(PYTHON, [BRIDGE, tool, JSON.stringify(args)], {
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 4 * 1024 * 1024,
      windowsHide: true,
    })
    return out.trim()
  } catch (e) {
    const err = e as { message?: string; stdout?: string; stderr?: string }
    const stdout = err.stdout ? `\nstdout: ${err.stdout}` : ''
    const stderr = err.stderr ? `\nstderr: ${err.stderr}` : ''
    return `Python 执行失败: ${err.message ?? String(e)}${stdout}${stderr}`
  }
}

function parseBridgeOutput(raw: string): string {
  try {
    const obj = JSON.parse(raw) as {
      error?: string
      result?: unknown
      results?: Array<{ key: string; text: string }>
      ciphers?: Array<{ id: string; name: string }>
    }
    if (obj.error) return `错误: ${obj.error}`
    if (obj.result !== undefined) return String(obj.result)
    if (obj.results) return obj.results.map((r) => `ROT${r.key}: ${r.text}`).join('\n')
    if (obj.ciphers) return obj.ciphers.map((c) => `${c.id} — ${c.name}`).join('\n')
    return raw
  } catch {
    return raw
  }
}

// ---------------------------------------------------------------------------
// ctf-skills 技能层（复用 ctf-skills 仓库的 SKILL.md）
// ---------------------------------------------------------------------------

const CTF_SKILLS_DIR = process.env.CTF_SKILLS_DIR ?? 'C:/Users/阳/.qclaw/skills/ctf-skills/ctf-skills-main/ctf-skills-download'

const CATEGORY_DIRS = [
  'ctf-crypto', 'ctf-web', 'ctf-pwn', 'ctf-reverse', 'ctf-forensics',
  'ctf-misc', 'ctf-osint', 'ctf-malware', 'ctf-ai-ml', 'ctf-writeup',
  'solve-challenge',
]

interface ParsedSkillMd {
  name: string
  description: string
  content: string
}

function parseSkillMd(raw: string): ParsedSkillMd | null {
  const m = raw.match(/^---\s*\r?\n([\s\S]*?)\r?\n---\s*\r?\n?/)
  const fm = m?.[1]
  if (!m || fm === undefined) return null
  const nameM = fm.match(/^name:\s*(.+?)\s*$/m)
  const descM = fm.match(/^description:\s*(.+?)\s*$/m)
  const name = nameM?.[1]?.trim()
  const description = descM?.[1]?.trim()
  if (!name || !description) return null
  return {
    name,
    description,
    content: raw.slice(m[0].length).trim(),
  }
}

function loadSkillMd(filePath: string): ParsedSkillMd | null {
  if (!existsSync(filePath)) return null
  try {
    return parseSkillMd(readFileSync(filePath, 'utf8'))
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// 插件入口
// ---------------------------------------------------------------------------

export function apply(ctx: Context): void {
  ctx.tools.register(defineTool({
    name: 'hash_identify',
    description: '根据长度和字符集识别一段哈希/密文可能的算法类型（MD5、SHA-1、SHA-256 等）。CTF 解题时先判断哈希类型再选择爆破/破解方式。',
    parameters: {
      hash: { type: 'string', required: true, description: '待识别的哈希或密文字符串' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      return identifyHash(args.hash)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'smart_decode',
    description: '自动尝试对一段文本做 Base64 / Hex / URL / ROT13 解码，返回所有成功的结果。CTF 解题时遇到编码过的密文可先调用本工具。',
    parameters: {
      text: { type: 'string', required: true, description: '待解码的字符串' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      return smartDecode(args.text)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'caesar_brute',
    description: '对凯撒密码（Caesar cipher）做全 26 位移爆破，列出所有结果并标注最像英文明文的位移。',
    parameters: {
      text: { type: 'string', required: true, description: '凯撒密码密文' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      return caesarBrute(args.text)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'classical_cipher',
    description: '古典密码与编码的编解码/爆破，复用 Yang-Web misc_crypto 引擎，支持 base64/base32/base58/base85/hex/url/html/unicode/morse/caesar/vigenere/rail_fence/bacon/pigpen/polybius/atbash/rot13/qwe/phone/adfgx 等 30+ 种。operation=list 列出全部可用类型；caesar 支持 brute 爆破（无需 key）。',
    parameters: {
      operation: { type: 'string', required: true, description: '操作：encode 编码 / decode 解码 / brute 爆破（仅 caesar）/ list 列出可用类型' },
      cipher: { type: 'string', description: '密码类型 id，如 base64、caesar、vigenere、morse、rail_fence 等' },
      text: { type: 'string', description: '待处理的文本' },
      key: { type: 'string', description: '密钥（vigenere/caesar/rail_fence/adfgx 等需要）' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      const payload: Record<string, unknown> = {
        operation: args.operation,
        cipher: args.cipher ?? '',
        text: args.text ?? '',
        key: args.key ?? '',
      }
      return parseBridgeOutput(execPython('classical', payload))
    },
  }))

  ctx.tools.register(defineTool({
    name: 'crypto_hash',
    description: '计算常见哈希摘要，支持 md5/sha1/sha224/sha256/sha384/sha512/sha3_256/sha3_512/blake2b/crc32。CTF 中用于校验、爆破目标或比对已知哈希。',
    parameters: {
      algorithm: { type: 'string', required: true, description: '算法名：md5/sha1/sha256/sha512/sha3_256/sha3_512/blake2b/crc32 等' },
      text: { type: 'string', required: true, description: '待计算的文本' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      return parseBridgeOutput(execPython('hash', { algorithm: args.algorithm, text: args.text }))
    },
  }))

  ctx.tools.register(defineTool({
    name: 'crypto_aes',
    description: 'AES 对称加解密（ECB/CBC），复用 Yang-Web 纯 Python 实现。encrypt 输出 hex 密文，decrypt 输入 hex 密文输出明文。',
    parameters: {
      operation: { type: 'string', required: true, description: 'encrypt 加密 / decrypt 解密' },
      text: { type: 'string', required: true, description: '明文（encrypt）或 hex 密文（decrypt）' },
      key: { type: 'string', required: true, description: '密钥字符串（16/24/32 字节对应 AES-128/192/256）' },
      mode: { type: 'string', description: 'ecb 或 cbc，默认 ecb' },
      iv: { type: 'string', description: 'CBC 模式的 IV（16 字节字符串）' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      return parseBridgeOutput(execPython('aes', {
        operation: args.operation,
        text: args.text,
        key: args.key,
        mode: args.mode ?? 'ecb',
        iv: args.iv ?? '',
      }))
    },
  }))

  ctx.tools.register(defineTool({
    name: 'crypto_rc4',
    description: 'RC4 流密码加解密。encrypt 输出 hex 密文，decrypt 输入 hex 密文输出明文。',
    parameters: {
      operation: { type: 'string', required: true, description: 'encrypt 加密 / decrypt 解密' },
      text: { type: 'string', required: true, description: '明文（encrypt）或 hex 密文（decrypt）' },
      key: { type: 'string', required: true, description: 'RC4 密钥' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      return parseBridgeOutput(execPython('rc4', { operation: args.operation, text: args.text, key: args.key }))
    },
  }))

  ctx.tools.register(defineTool({
    name: 'rsa_basic',
    description: 'RSA 基础运算：encrypt 用公钥 (n,e) 加密，decrypt 用私钥 (n,d) 解密，factor_hint 给出模数 n 的因式分解提示。',
    parameters: {
      operation: { type: 'string', required: true, description: 'encrypt / decrypt / factor_hint' },
      text: { type: 'string', description: '待加密明文或待解密的 hex 密文' },
      n: { type: 'number', description: '模数 n' },
      e: { type: 'number', description: '公钥指数 e' },
      d: { type: 'number', description: '私钥指数 d' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      return parseBridgeOutput(execPython('rsa', {
        operation: args.operation,
        text: args.text ?? '',
        n: args.n ?? 0,
        e: args.e ?? 0,
        d: args.d ?? 0,
      }))
    },
  }))

  ctx.skills.registerProvider(() => ({
    name: 'ctf-skills',
    async list() {
      const candidates: SkillCandidate[] = []
      for (const dir of CATEGORY_DIRS) {
        const filePath = join(CTF_SKILLS_DIR, dir, 'SKILL.md')
        const meta = loadSkillMd(filePath)
        if (!meta) continue
        candidates.push({
          name: meta.name,
          description: meta.description,
          invocation: { modelInvocable: true, userInvocable: false },
          provider: 'ctf-skills',
          source: 'custom',
          rank: 0,
          locator: filePath,
          resourceBase: { kind: 'directory', path: join(CTF_SKILLS_DIR, dir) },
          path: filePath,
        })
      }
      return candidates
    },
    async get(candidate) {
      const filePath = String(candidate.locator)
      const meta = loadSkillMd(filePath)
      if (!meta) return undefined
      const result: SkillDefinition = {
        name: meta.name,
        description: meta.description,
        content: meta.content,
        invocation: { modelInvocable: true, userInvocable: false },
        provider: 'ctf-skills',
        source: 'custom',
        resourceBase: { kind: 'directory', path: dirname(filePath) },
        path: filePath,
      }
      return result
    },
  }))
}
