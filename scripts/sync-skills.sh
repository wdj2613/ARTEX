#!/bin/sh
# 内置技能同步（文件级三方合并）
#
# 为什么需要它：容器里 /app/skills 是宿主绑定挂载（UI 的技能上传/编辑接口
# 都写这个目录），镜像里 COPY 进去的内置技能会被挂载完全遮蔽——于是每次
# 换版镜像里的 skills 更新一条也到不了线上（实测 0.4.0→0.4.3 全丢）。
# 又不能简单用镜像覆盖：那会抹掉用户在 UI/宿主上做的修改与上传的技能。
#
# 做法：镜像内另存一份内置源（/app/skills-builtin，不被挂载遮蔽），启动时
# 按【文件】做三方合并。判据是三个 hash：
#   内置旧版 hash  = 上次同步记在 .skill-sync-state 里的值（用户改之前的内置内容）
#   内置新版 hash  = 镜像内该文件的当前内容
#   目标现有 hash  = 挂载目录里用户当前的版本
#
#   - 目标不存在 + 无记录           → 新增（首次安装）
#   - 目标不存在 + 有记录           → 用户删掉了，不补
#   - 现有 == 新版                  → 已一致，跳过
#   - 现有 == 内置旧版              → 用户没改过，跟随镜像更新
#   - 内置旧版 == 新版（内置没变）  → 用户改过，保留
#   - 三者都不同（双方都改了）      → 保留用户版，新版另存 <文件>.incoming
#
# 只遍历内置源里的文件；用户自建技能、用户新增的文件一律不碰。
# state 文件是技能目录顶层的普通文件（非目录、非 .md），既不会被 norma 的
# skill.LoadDir 当技能加载，也不会出现在 GET /api/skills 的列表里。
set -u

SKILLS_DIR="${ARTEX_SKILL_DIR:-/app/skills}"
BUILTIN_DIR="${ARTEX_SKILL_BUILTIN_DIR:-/app/skills-builtin}"
STATE_FILE="$SKILLS_DIR/.skill-sync-state"

# 裸机部署没有内置源，直接跳过（保持 start.sh 在容器外的行为不变）。
[ -d "$BUILTIN_DIR" ] || exit 0
[ -d "$SKILLS_DIR" ] || mkdir -p "$SKILLS_DIR" 2>/dev/null || exit 0
[ -f "$STATE_FILE" ] || : > "$STATE_FILE" 2>/dev/null || exit 0

hash_file() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

NEW_STATE=$(mktemp 2>/dev/null) || exit 0
LIST=$(mktemp 2>/dev/null) || { rm -f "$NEW_STATE"; exit 0; }
trap 'rm -f "$NEW_STATE" "$LIST"' EXIT INT TERM

changed=0

for srcdir in "$BUILTIN_DIR"/*/; do
	[ -d "$srcdir" ] || continue
	name=$(basename "$srcdir")
	# 只有含 SKILL.md 的目录才算内置技能（与 norma skill.LoadDir 的判据一致）。
	[ -f "$srcdir/SKILL.md" ] || continue
	dstroot="$SKILLS_DIR/$name"

	# 先落清单再遍历：用管道进 while 会起子 shell，changed 就带不出来了。
	( cd "$srcdir" && find . -type f | LC_ALL=C sort | sed 's|^\./||' ) > "$LIST" 2>/dev/null || continue

	while IFS= read -r rel; do
		[ -n "$rel" ] || continue
		src="$srcdir$rel"
		dst="$dstroot/$rel"
		key="$name/$rel"
		newh=$(hash_file "$src")
		[ -n "$newh" ] || continue
		oldh=$(awk -v k="$key" '$1==k{print $2; exit}' "$STATE_FILE" 2>/dev/null)
		printf '%s %s\n' "$key" "$newh" >> "$NEW_STATE"

		if [ ! -e "$dst" ]; then
			if [ -n "$oldh" ]; then
				continue   # 用户删过这个文件，尊重删除，不补
			fi
			mkdir -p "$(dirname "$dst")" 2>/dev/null
			if cp -p "$src" "$dst" 2>/dev/null; then
				echo "[skills-sync] 新增 $key"
				changed=1
			fi
			continue
		fi

		curh=$(hash_file "$dst")
		[ "$curh" = "$newh" ] && continue        # 已是最新
		if [ "$curh" = "$oldh" ]; then           # 用户没动过 → 跟随镜像
			if cp -p "$src" "$dst" 2>/dev/null; then
				echo "[skills-sync] 更新 $key"
				changed=1
			fi
		elif [ "$oldh" = "$newh" ]; then         # 内置没变、用户改过 → 保留
			continue
		else                                     # 双方都改 → 保留用户版，新版另存
			if cp -p "$src" "$dst.incoming" 2>/dev/null; then
				echo "[skills-sync] 冲突，保留你的版本：$key（内置新版另存 $key.incoming）"
				changed=1
			fi
		fi
	done < "$LIST"
done

mv "$NEW_STATE" "$STATE_FILE" 2>/dev/null || true
[ "$changed" = 1 ] && echo "[skills-sync] 内置技能同步完成"
exit 0
