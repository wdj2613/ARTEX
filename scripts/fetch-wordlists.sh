#!/usr/bin/env bash
# 准备字典与 nuclei 模板（不打进镜像的大体积资源）。
#
# 用法：
#   ./scripts/fetch-wordlists.sh [目标目录]     # 默认当前目录
#
# 产出的两个目录由 docker-compose.yml 只读挂载：
#   <目标目录>/wordlists        → 容器 /opt/artex/wordlists
#   <目标目录>/nuclei-templates → 容器 /root/.local/share/nuclei-templates
#
# 国内网络受限时先 export https_proxy=http://<host>:7890
set -euo pipefail

DEST="${1:-.}"
mkdir -p "$DEST/wordlists" "$DEST/nuclei-templates"

SECLISTS="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
# 路径与文件名以 SecLists 仓库现状为准（部分历史文件名已改名，例如
# directory-list-2.3-medium.txt → DirBuster-2007_directory-list-2.3-medium.txt）
download() { # <url> <目标名> <最少行数>
  local url="$1" name="$2" min="$3" out="$DEST/wordlists/$2"
  echo "-> $name"
  curl -fsSL --retry 2 -m 300 -o "$out" "$url"
  local lines
  lines=$(wc -l < "$out")
  if [ "$lines" -lt "$min" ]; then
    echo "!! $name 只有 $lines 行（期望 >= $min），下载可能失败或被限流" >&2
    return 1
  fi
  echo "   ok ${lines} 行"
}

download "$SECLISTS/Discovery/Web-Content/common.txt" common.txt 4000
download "$SECLISTS/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt" dir-medium.txt 100000
download "$SECLISTS/Discovery/DNS/subdomains-top1million-5000.txt" subdomains-5000.txt 4000
download "$SECLISTS/Usernames/top-usernames-shortlist.txt" usernames.txt 10
download "$SECLISTS/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt" passwords-top10k.txt 9000

if [ ! -f "$DEST/nuclei-templates/README.md" ]; then
  echo "-> nuclei-templates"
  tmp=$(mktemp -d)
  curl -fsSL --retry 2 -m 900 -o "$tmp/nt.zip" \
    https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip
  unzip -q -o "$tmp/nt.zip" -d "$tmp"
  mv "$tmp"/nuclei-templates-main/* "$DEST/nuclei-templates/"
  rm -rf "$tmp"
  echo "   ok $(find "$DEST/nuclei-templates" -name '*.yaml' | wc -l) 个模板"
else
  echo "-> nuclei-templates 已存在，跳过"
fi

echo
echo "完成："
du -sh "$DEST/wordlists" "$DEST/nuclei-templates"