# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/artex。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/artex ./cmd/artex
#   docker build -t artex:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# 出网代理（可选）：本地构建若访问 GitHub/PyPI 受限，传 --build-arg HTTPS_PROXY=http://<host>:7890。
# 空值等于不走代理；CI（GitHub Actions 云端）不传也能直连。
ARG HTTPS_PROXY
ARG PIP_INDEX_URL=https://pypi.org/simple
# 常用工具 + recon 常备件 + 渗透工具（bookworm 源直接有）：
#   sqlmap / whatweb / hydra / sshpass / masscan / dirb / gobuster / ffuf / wapiti + 既有 nmap。
# 字典不打进镜像（1.5GB 级），由 compose 只读挂载 /opt/artex/wordlists。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
      sqlmap whatweb hydra sshpass masscan dirb gobuster ffuf wapiti \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# nuclei / subfinder：bookworm 没有，用 projectdiscovery 官方 release 按架构下载。
# （nuclei 模板不随镜像发布，由 compose 挂载到 /root/.local/share/nuclei-templates。）
RUN if [ "$TARGETARCH" = "arm64" ]; then ARCH=arm64; else ARCH=amd64; fi; \
    [ -n "$HTTPS_PROXY" ] && P="--proxy $HTTPS_PROXY" || P=""; \
    curl -fsSL --retry 2 $P -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_${ARCH}.zip" \
    && unzip -o -q /tmp/nuclei.zip -d /usr/local/bin && rm /tmp/nuclei.zip \
    && curl -fsSL --retry 2 $P -o /tmp/subfinder.zip \
      "https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_linux_${ARCH}.zip" \
    && unzip -o -q /tmp/subfinder.zip -d /usr/local/bin && rm /tmp/subfinder.zip \
    && nuclei -version 2>&1 | head -1 && subfinder -version 2>&1 | head -1
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
# Python 依赖基线：agent 在任务里反复 pip install 的库（线上 48h 实测 25 次运行时安装，
# 落在容器可写层、换镜像全丢），打进镜像省掉每次重复安装与出网依赖。
RUN pip3 install --no-cache-dir -i "$PIP_INDEX_URL" \
      requests PySocks python-socks paramiko mmh3 pyjwt bcrypt PyNaCl websocket-client \
    && rm -rf /root/.cache/pip
WORKDIR /app
# 预编译好的对应架构二进制（dist/amd64/artex 或 dist/arm64/artex）
COPY dist/${TARGETARCH}/artex /app/artex
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
