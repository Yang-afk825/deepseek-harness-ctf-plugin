import { execFileSync } from 'node:child_process'

const PY = 'C:/Program Files/Python312/python.exe'
const BRIDGE = 'C:/Users/阳/.qclaw/workspace/DeepSeek-Harness/packages/ctf/dsh-ctf/py/ctf_bridge.py'

function call(tool, args) {
  try {
    const out = execFileSync(PY, [BRIDGE, tool, JSON.stringify(args)], {
      encoding: 'utf8',
      timeout: 30000,
    })
    return out.trim()
  } catch (e) {
    return `EXEC ERROR: ${e.message}\n${e.stdout ?? ''}${e.stderr ?? ''}`
  }
}

const tests = [
  ['classical', { operation: 'decode', cipher: 'base64', text: 'ZmxhZ3tjdGZfY2hhbGxlbmdlfQ==' }],
  ['classical', { operation: 'decode', cipher: 'caesar', text: 'khoor', key: '3' }],
  ['classical', { operation: 'decode', cipher: 'morse', text: '.... . .-.. .-.. ---' }],
  ['classical', { operation: 'encode', cipher: 'vigenere', text: 'FLAG', key: 'CTF' }],
  ['hash', { algorithm: 'md5', text: 'admin' }],
  ['hash', { algorithm: 'sha256', text: 'flag' }],
  ['aes', { operation: 'encrypt', text: 'flag{test}', key: '0123456789abcdef', mode: 'ecb' }],
  ['aes', { operation: 'decrypt', text: 'b7e54da327378862e13c68682e576541', key: '0123456789abcdef', mode: 'ecb' }],
  ['rc4', { operation: 'encrypt', text: 'hello', key: 'key' }],
  ['rsa', { operation: 'factor_hint', n: 3233 }],
  ['classical', { operation: 'brute', cipher: 'caesar', text: 'uryyb jbeyq' }],
]

for (const [tool, args] of tests) {
  const result = call(tool, args)
  console.log(`[${tool}] ${JSON.stringify(args).slice(0, 60)}`)
  console.log(`  => ${result}`)
  console.log('')
}
