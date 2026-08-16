#!/usr/bin/env python3
"""CTF bridge — DeepSeek Harness dsh-ctf 插件的 Python 后端。

统一接口:  python ctf_bridge.py <tool> '<json-args>'
输出 JSON 到 stdout（ensure_ascii=False）。

tool 列表: classical / hash / aes / rc4 / rsa
"""
import sys
import json

# Windows 下 stdout 默认 GBK，遇到 emoji/乱码会 UnicodeEncodeError；强制 UTF-8 输出。
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

YANG_WEB = r'C:\Users\阳\.qclaw\workspace\Yang-web'
if YANG_WEB not in sys.path:
    sys.path.insert(0, YANG_WEB)

from yang_web.core import misc_crypto, crypto_engine  # noqa: E402


def _classical(args):
    op = args.get('operation', 'decode')
    cipher = args.get('cipher', '')
    text = args.get('text', '')
    key = args.get('key', '')
    if op == 'list':
        return {'ciphers': misc_crypto.list_ciphers()}
    if op == 'encode':
        return {'result': misc_crypto.encode(cipher, text, key=key)}
    if op == 'brute':
        if cipher in ('caesar',):
            out = []
            for k in range(1, 26):
                out.append({'key': str(k), 'text': misc_crypto.decode('caesar', text, key=str(k))})
            return {'results': out}
        return {'error': f'不支持的爆破类型: {cipher}（目前仅支持 caesar）'}
    return {'result': misc_crypto.decode(cipher, text, key=key)}


def _hash(args):
    algo = (args.get('algorithm') or 'md5').lower()
    text = args.get('text', '')
    fns = {
        'md5': crypto_engine.calc_md5,
        'sha1': crypto_engine.calc_sha1,
        'sha224': crypto_engine.calc_sha224,
        'sha256': crypto_engine.calc_sha256,
        'sha384': crypto_engine.calc_sha384,
        'sha512': crypto_engine.calc_sha512,
        'sha3_256': crypto_engine.calc_sha3_256,
        'sha3_512': crypto_engine.calc_sha3_512,
        'blake2b': crypto_engine.calc_blake2b,
        'crc32': crypto_engine.calc_crc32_hex,
    }
    fn = fns.get(algo)
    if fn is None:
        return {'error': f'不支持的算法: {algo}，可选: {", ".join(fns)}'}
    return {'result': fn(text)}


def _aes(args):
    op = args.get('operation', 'decrypt')
    text = args.get('text', '')
    key = args.get('key', '0123456789abcdef')
    mode = (args.get('mode') or 'ecb').lower()
    iv = args.get('iv', '')
    if op == 'encrypt':
        return {'result': crypto_engine.aes_string_encrypt(text, key, mode, iv)}
    return {'result': crypto_engine.aes_string_decrypt(text, key, mode, iv)}


def _rc4(args):
    op = args.get('operation', 'decrypt')
    text = args.get('text', '')
    key = args.get('key', '')
    if op == 'encrypt':
        return {'result': crypto_engine.rc4_encrypt(text, key)}
    return {'result': crypto_engine.rc4_decrypt(text, key)}


def _rsa(args):
    op = args.get('operation', '')
    if op == 'encrypt':
        return {'result': crypto_engine.rsa_encrypt(
            args.get('text', ''), args.get('n', 0), args.get('e', 0))}
    if op == 'decrypt':
        return {'result': crypto_engine.rsa_decrypt(
            args.get('text', ''), args.get('n', 0), args.get('d', 0))}
    if op == 'factor_hint':
        return {'result': crypto_engine.rsa_factorize_hint(args.get('n', 0))}
    return {'error': '需要 operation: encrypt / decrypt / factor_hint'}


DISPATCH = {
    'classical': _classical,
    'hash': _hash,
    'aes': _aes,
    'rc4': _rc4,
    'rsa': _rsa,
}


def main():
    try:
        tool = sys.argv[1]
        args = json.loads(sys.argv[2])
    except (IndexError, json.JSONDecodeError) as e:
        print(json.dumps({'error': f'参数错误: {e}'}, ensure_ascii=False))
        return
    handler = DISPATCH.get(tool)
    if handler is None:
        print(json.dumps(
            {'error': f'未知工具: {tool}，可选: {", ".join(DISPATCH)}'}, ensure_ascii=False))
        return
    try:
        result = handler(args)
    except Exception as e:  # noqa: BLE001
        result = {'error': f'{type(e).__name__}: {e}'}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
