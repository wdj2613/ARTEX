#!/usr/bin/env bash
# sync-skills.sh 的场景测试（不依赖 Docker，用临时目录模拟挂载布局）
#
#   ./scripts/sync-skills.test.sh
#
# 覆盖：首次安装 / 内置升级(用户没改) / 内置升级(用户改过) / 内置未变(用户改过)
#       用户自建技能 / 用户删除内置文件 / 幂等
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SYNC="$HERE/sync-skills.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

pass=0
fail=0
ok()   { pass=$((pass+1)); echo "  PASS  $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL  $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# 每个场景一套干净目录
setup() {
	B="$ROOT/$1/builtin"; S="$ROOT/$1/skills"
	mkdir -p "$B" "$S"
	export ARTEX_SKILL_BUILTIN_DIR="$B" ARTEX_SKILL_DIR="$S"
}
mk_skill() { # $1=builtin 根 $2=技能名 $3=SKILL.md 内容 $4=附加文件相对路径(可选)
	mkdir -p "$1/$2"
	printf '%s\n' "$3" > "$1/$2/SKILL.md"
	[ "${4:-}" ] && { mkdir -p "$(dirname "$1/$2/$4")"; printf 'ref v1\n' > "$1/$2/$4"; }
	return 0
}
run() { sh "$SYNC" > "$ROOT/out.txt" 2>&1; echo "$(cat "$ROOT/out.txt")"; }

echo "== 1 首次安装 =="
setup s1
mk_skill "$B" alpha "---\nname: alpha\n---" references/a.md
out=$(run)
check "装上 alpha/SKILL.md"          '[ -f "$S/alpha/SKILL.md" ]'
check "装上子目录文件"                '[ -f "$S/alpha/references/a.md" ]'
check "日志报告新增"                  'grep -q "新增 alpha/SKILL.md" <<<"$out"'

echo "== 2 内置未变 + 用户改过 =="
printf 'user edited\n' > "$S/alpha/SKILL.md"
out=$(run)
check "用户版本被保留"                'grep -q "user edited" "$S/alpha/SKILL.md"'
check "无写操作日志"                  '! grep -q "更新\|冲突" <<<"$out"'

echo "== 3 内置升级 + 用户改过的同一文件 =="
mk_skill "$B" alpha "---\nname: alpha\nv: 2\n---" references/a.md
printf 'ref v2\n' > "$B/alpha/references/a.md"
out=$(run)
check "未改过的文件跟随更新"          'grep -q "ref v2" "$S/alpha/references/a.md"'
check "改过的文件仍保留用户版"        'grep -q "user edited" "$S/alpha/SKILL.md"'
check "冲突文件另存 incoming"         '[ -f "$S/alpha/SKILL.md.incoming" ]'
check "incoming 内容就是内置新版"     'grep -q "v: 2" "$S/alpha/SKILL.md.incoming"'

echo "== 4 冲突后用户合并，再同步不再冲突 =="
cp "$S/alpha/SKILL.md.incoming" "$S/alpha/SKILL.md"
rm -f "$S/alpha/SKILL.md.incoming"
out=$(run)
check "再次同步无冲突日志"            '! grep -q "冲突" <<<"$out"'
check "内容等于内置新版"              'cmp -s "$S/alpha/SKILL.md" "$B/alpha/SKILL.md"'

echo "== 5 用户自建技能 / 自建文件不受影响 =="
mkdir -p "$S/my-own"; printf 'mine\n' > "$S/my-own/SKILL.md"
printf 'extra\n' > "$S/alpha/notes.md"
out=$(run)
check "自建技能目录保留"              '[ -f "$S/my-own/SKILL.md" ]'
check "自建技能未出现在同步日志"      '! grep -q "my-own" <<<"$out"'
check "自建文件保留"                  '[ -f "$S/alpha/notes.md" ]'

echo "== 6 用户删除内置文件 → 不补回 =="
rm -f "$S/alpha/references/a.md"
out=$(run)
check "被删的文件没有复活"            '[ ! -f "$S/alpha/references/a.md" ]'

echo "== 7 幂等 =="
out=$(run)
check "第三次运行无写操作"            '! grep -q "新增\|更新\|冲突" <<<"$out"'

echo "== 8 state 文件形态 =="
check "state 是普通文件"              '[ -f "$S/.skill-sync-state" ]'
check "state 不是 .md（不会被当技能）" '[[ "$(basename "$S/.skill-sync-state")" != *.md ]]'
check "state 记录了 hash"              '[ "$(grep -c "^alpha/SKILL.md " "$S/.skill-sync-state")" = 1 ]'

echo "== 9 无内置源时静默跳过（裸机路径） =="
setup s9
out=$(ARTEX_SKILL_BUILTIN_DIR="$ROOT/s9/none" sh "$SYNC" 2>&1)
check "退出码 0 且无输出"              '[ $? = 0 ] && [ -z "$out" ]'

echo
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" = 0 ]
