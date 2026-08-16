import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const CTF_SKILLS_DIR = 'C:/Users/阳/.qclaw/skills/ctf-skills/ctf-skills-main/ctf-skills-download'
const CATEGORY_DIRS = ['ctf-crypto', 'ctf-web', 'ctf-pwn', 'ctf-reverse', 'ctf-forensics', 'ctf-misc', 'ctf-osint', 'ctf-malware', 'ctf-ai-ml', 'ctf-writeup', 'solve-challenge']

function parseSkillMd(raw) {
  const m = raw.match(/^---\s*\r?\n([\s\S]*?)\r?\n---\s*\r?\n?/)
  const fm = m?.[1]
  if (!m || fm === undefined) return null
  const nameM = fm.match(/^name:\s*(.+?)\s*$/m)
  const descM = fm.match(/^description:\s*(.+?)\s*$/m)
  const name = nameM?.[1]?.trim()
  const description = descM?.[1]?.trim()
  if (!name || !description) return null
  return { name, description, content: raw.slice(m[0].length).trim() }
}

let total = 0
let contentChars = 0
for (const dir of CATEGORY_DIRS) {
  const fp = join(CTF_SKILLS_DIR, dir, 'SKILL.md')
  if (!existsSync(fp)) { console.log(`❌ 缺失: ${dir}`); continue }
  let meta
  try { meta = parseSkillMd(readFileSync(fp, 'utf8')) } catch (e) { console.log(`❌ 读失败 ${dir}: ${e.message}`); continue }
  if (!meta) { console.log(`❌ 解析失败: ${dir}`); continue }
  total++
  contentChars += meta.content.length
  console.log(`✅ ${meta.name}  (content ${meta.content.length} 字符)  — ${meta.description.slice(0, 50)}...`)
}
console.log(`\n共 ${total}/${CATEGORY_DIRS.length} 个 skill 加载成功，content 总计 ${contentChars} 字符`)
