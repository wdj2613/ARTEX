# 更新日志

本项目的重要变更记录在此文件中，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

### 构建与镜像

- **内置技能改为启动时按文件级三方合并同步（修「镜像里的 skills 更新到不了线上」）**（`Dockerfile` + `start.sh` + 新增 `scripts/sync-skills.sh`）。容器里 `/app/skills` 是宿主绑定挂载——UI 的 `POST /api/skills/upload`、`PUT /api/skills/{name}/files/...` 全写这个目录，所以镜像 `COPY skills/ /app/skills/` 会被挂载**完全遮蔽**：实测 0.4.0→0.4.3 期间对 `skills/` 的所有改进（已装工具表、nuclei `-jsonl` 纪律、`cve_lookup` 提示）一条都没到线上，宿主那份仍停在 10-28 的旧版，`scopesentry` 还被编辑坏成 `http: //<主机>`。现在镜像另存一份不被遮蔽的内置源 `COPY skills/ /app/skills-builtin/`，`start.sh` 启动前调 `scripts/sync-skills.sh` 逐**文件**比对三个 hash（内置旧版 / 内置新版 / 目标现有）后合并：用户改过的文件**永远保留**、用户没改过的跟随镜像更新、用户自建技能与新增文件一律不碰、用户删掉的内置文件不补回、双方都改时保留用户版并把新版另存 `<文件>.incoming`。不能简单用镜像覆盖：那会抹掉用户在 UI 里做的修改和上传的技能。同步状态记在 `<skills>/.skill-sync-state`（普通文件、非 `.md`，`skill.LoadDir` 不当技能、`GET /api/skills` 不列出来）；裸机部署没有内置源目录，脚本自动跳过。场景测试 `scripts/sync-skills.test.sh`（9 场景 20 条断言）。

### 工具链

- **`skills/playwright-cli` 补 `mcps: browser`**：browser MCP 在 `mcp_servers` 里是 enabled 的，缺这个字段时它的工具对所有 agent 全局提前解锁（白占上下文、权限面也更大）；写上后由 norma 的 `mcps` 门控成「加载 playwright-cli 技能时才解锁」（`server/assembly.go` 的 `gated` 集合）。该字段此前只存在于宿主机手工改的副本里、仓库从来没有，换机或重建镜像就丢。

## [0.4.3] - 2026-10-30

### 概要

本版说明覆盖自上个已发布版本（0.4.2）以来的改动。

- **Agent**：新增 `cve_lookup` 工具，把「这个组件/CVE 有什么已知漏洞」变成一条**可执行命令** —— 查镜像内置的 nuclei 模板库（实测 14164 条 / 4536 条带 CVE），每条结果带 `next`（`nuclei -t <模板绝对路径>` + `-jsonl` 落盘），跑完的 `request`/`response` 直接当 finding 证据；按 CVE 精确查零噪声，同一 CVE 的多个模板按 verified→CVSS→EPSS 去重。
- **Agent**：`cve_lookup` 增加**在线情报**补充（默认关，设置页可开）—— 本地模板库零命中时自动查 NVD / OSV / GitHub PoC / EPSS，给出 CVSS、是否已被野外利用（CISA KEV）、受影响版本区间和公开 PoC 线索，补上「CVE 刚公布、模板还没写出来」那个时间窗口。在线结果**不给可执行命令**，必须自行构造请求验证。
- **构建**：nuclei 模板目录改为 `/root/nuclei-templates`（nuclei 自己的默认解析路径）。这是线上 nuclei 真实执行 **0 次**的根因 —— 模板装在 `.local/share` 下，任何不带 `-t` 的命令都报 `no templates provided for scan`，而工具箱文档给 agent 的两条命令恰好都不带 `-t`。
- **Agent**：worker 提示词新增代码拥有的「CVE 验证链」段（DB 覆盖提示词也丢不掉），并把「多个候选写进**同一条**意图批量跑」写死 —— 逐条派单摘要相似度 0.89，会被意图去重闸判重。
- **Web**：系统设置新增「漏洞情报（在线检索）」卡片：总开关关闭时只渲染开关与一句说明、其余配置项一律不出现；打开后才展开来源开关、NVD API Key / GitHub Token（各带「已配置」徽标与独立保存，密钥永不回传前端）、独立出口代理与「测试检索」按钮；开了开关但一个 Key 都没配时只提示额度、不阻断使用。
- **文档**：`pentest-toolbox` 技能里的 nuclei 命令改为必须 `-jsonl` 落盘，并写明已知 CVE 号别用 `-id`、模板随镜像内置不要 `-update`。

### Agent

- **新增 `cve_lookup` 工具：把「这个组件/CVE 有什么已知漏洞」变成一条可执行命令**（`cveidx/` 新包 + `agent/cvelookup.go`）。数据源是镜像内置的 nuclei 模板库（实测 14142 条，其中 4657 条带 `cve-id`，1899 条模板名里带版本约束表达式）——模板本身就是请求+匹配器，所以检索结果能直接落到 `nuclei -t <模板绝对路径>` 上，跑完的 `-jsonl` 里带 `request`/`response`，就是 finding 需要的可复现证据，**不需要**额外查流量表。底层不解析版本区间：线上资产指纹里只有 **7%** 带版本号（3/43），做版本匹配等于自造假精度，版本约束交给模板自己的 matcher 判定。三条刻意的限制：① 无版本号的组件名查询把候选压到 top 3（上限 10）并在出参标注 `version_unknown` —— 实测按产品名宽泛匹配时单条资产能捞出 **126** 个历史 CVE（"Apache" 一条），worker 的 1200s 墙钟根本跑不完；② 只返回候选与命令，**不返回漏洞结论**，没真实触发就不能进 finding（与既有「严禁把 CVE 匹配当 finding」的纪律一致）；③ 模板目录缺失时降级为 `{"available": false}` 而不是 500。工具同时给 worker 和 planner，注册走既有的内置工具播种（`toolcatalog.go`），无需迁移。
- **`cve_lookup` 增加在线情报补充（本地模板库零命中时才查，默认关）**（新包 `cveonline/`）。镜像内置的模板库是快照，CVE 刚公布、模板还没写出来时本地必然零命中——这个时间窗口只能靠在线源补。四个源：**NVD**（CVSS / CISA KEV / 版本区间 / 参考链接）、**OSV**（npm/PyPI/Go/Packagist 的包级区间）、**GitHub**（公开 PoC 数量与样例）、**EPSS**（利用概率，随 NVD 一起批量取）。三条刻意的取舍：① 在线结果**不产生 `next` 命令**——它只有版本区间和链接、没有请求与匹配器，硬凑命令会诱导模型把未验证的东西当 finding 报；② **缺 key 不关闭功能**（与 `web_search` 相反）：三个源不配 key 都能用，key 只提额度（NVD 5→50 次/30s、GitHub 未认证 10 次/分钟），降级状态写进出参的 `degraded` 让模型自己知道；③ 单源失败一律降级、绝不上升为工具错误，本地模板结果必须照常可用。实测两个必须的修正：NVD 的 `keywordSearch` 没有排序参数、默认按 CVE 号升序返回（"apache http server" 555 条的前 3 条是 1999 年的），所以要先用一次请求读 `totalResults` 再翻到最后一页取最新；GitHub 搜索把 `in:readme` 去掉，否则按 star 排序会把 `How-To-Secure-A-Linux-Server`（3.2 万星安全清单）当成首条 PoC。
- **worker 提示词新增代码拥有的「CVE 验证链」段**（`worker.go` 的 `workerCVESpec`，追加在工具箱段之后、进度留痕之前，有单测锁住且 DB 覆盖提示词也丢不掉）。补的是"什么时候该用模板"这个缺环：拿到组件名/版本先 `cve_lookup`，按返回的 `next` 命令跑（`-jsonl` 强制落盘），命中后用 jsonl 的 request/response 报 finding，未命中记 `inferred` 事实。**强调多个候选写进同一条意图批量跑**——实测同资产下逐条 CVE 意图的摘要 Dice 相似度 **0.889**，远超意图去重闸的 0.50 阈值，逐条派单会被判重。main agent 不带这段（它在 `directActionHeads` 里禁 nuclei）。

### 构建与镜像

- **修 nuclei 模板目录：装到 `/root/nuclei-templates`，而不是 `/root/.local/share/nuclei-templates`**（`Dockerfile` + `docker-compose.yml` 挂载注释）。这是线上 nuclei 真实执行 **0 次**的根因：nuclei 自己在 `.config/nuclei/.templates-config.json` 里认的默认目录是 `/root/nuclei-templates`，模板装在 `.local/share` 下导致默认解析拿不到，任何不带 `-t` 的命令都报 `Could not run nuclei: no templates provided for scan`，而 `skills/pentest-toolbox` 给 agent 的两条命令恰好都不带 `-t`。实测符号链接不能替代（仍报错），`nuclei -update-templates` 才是写到这个目录。compose 里补了「挂载前先 `docker cp` 出内置模板」的说明——空目录会把内置模板盖成空。

### 文档

- **`skills/pentest-toolbox` 的 nuclei 命令修正**：两条命令都改带 `-jsonl -o`（纯文本输出进不了证据链），并写明「已知 CVE 号别用 `-id`（单独使用会报 no templates provided），用 `cve_lookup` 返回的 `-t <绝对路径>`」「模板随镜像内置，不要 `-update`」。

### Web

- **设置页新增「漏洞情报（在线检索）」卡片**：总开关关闭时**只渲染一个开关和一句说明**，其余配置项一律不出现（对应"关掉就不该看到多余设置"）；打开后才展开三个来源的独立开关、NVD API Key 与 GitHub Token（各自带「已配置」徽标和独立保存按钮，密钥永不回传前端）、独立出口代理、以及「测试检索」按钮。**打开但一个 Key 都没配**时给琥珀色提示并明确写清「功能可用，只是额度低」，不阻断使用——因为这三个源本来就不需要 Key。测试按钮拿表单当前值真跑一次（不吃缓存），失败时把每个源的具体原因带进 toast，能立刻分辨是 Key 错、代理不通还是被限流。对应后端新增 `POST /api/settings/cve-online/test`。
- **任务详情新增「空转指标」卡片（只读聚合，不新增埋点）**：要回答「agent 有没有在原地打转」，但口径不能用「同一 URL 请求了几次」——渗透本来就要对同一攻击面反复施压（fuzz、口令喷洒、payload 变异），生产实测路径级重复率 56.3%，Top 明细全是 `shopapi/system/config`、`login_api`、`shop/fuzz` 这类正常目标，而「完全相同的命令」重复只有 1.1%，也就是重复请求 = 攻击强度，不是浪费。因此改看两个信号：① **工具返回有没有新信息**（同任务同工具、`summary` 完全相同的占比，排除错误返回与 <15 字的过短摘要，否则 `ok` / `0` 这类天然重复会把噪声当空转），② **意图有没有产出**（终态意图里 `payload.progress.yields` 为空或 0 的占比）。数据全部来自已有的 `activity` 与 `exploration_nodes`，**不建表、不加列、不加埋点**：新增 `GET /api/exploration/void-stats`（`db/void_stats.go` + `server/void_stats.go`，无任务或无数据返回 `{"available": false}` 而不是 500），前端在任务详情概览页加一张卡片，按工具列出重复率前 6 名。同步补了 `web/src/lib/mock/handler.ts` 的 mock 响应，让 `NEXT_PUBLIC_MOCK=1` 的 demo 也能看到这张卡。

## [0.4.2] - 2026-10-29

### 概要

本版说明覆盖自上个已发布版本（0.4.0）以来的全部改动；0.4.1 未单独发版，改动一并计入。

- **LLM**：仪表盘 / 任务列表 / 任务详情三处 token 统计全部改读 `llm_usage` 计量账本，旧口径少算的 45%（归档任务归零 876M、`compactor`/`btw`/`goals` 通道不计、中断 run 丢账、日图按任务创建日归桶）一并修掉。
- **LLM**：任务详情「按会话分解」改由账本给出 `main:<段>` / `plan` / `intent:<id>`；`session` 列上线前的历史行按任务回退旧记录（覆盖 99%+），跨上线点的任务随新数据自然收敛。
- **LLM**：任务列表 token 列合并归档聚合，归档任务不再显示 0；仪表盘「任务数」不再把跨 profile 的同一任务重复计。
- **LLM**：三条对账恒等式成立 —— 仪表盘 = Σ任务列表(含归档) + Σ会话（实测精确相等）、详情 total = Σ会话行、Σ日图 = 合计。
- **删除**：仪表盘「旧版 / 新版」数据源开关、3 个前端零调用的 token 接口与 5 个旧聚合函数；`/api/exploration/tokens` 出参不变，前端 0 行改动。
- **Agent**：新增主 Agent 边界闸（`mainagent_direct_action`）—— 主 Agent 自己下场用 Bash 打目标（实测单回合烧 67.8M 输入 token、零正文）会被 `PreToolUse` 钩子拦下，并提示改用 `add_intent` / `steer_work` / `set_goals`。
- **Agent**：系统设置新增「主 Agent 边界闸」三档（仅提醒 / 收紧 Bash / 关闭），提示词尾部追加代码拥有的「人机接口边界」段，有单测锁住。
- **Web**：仪表盘新增「出口 IP」卡片（真实出口 + 代理出口、往返延迟、失败原因，可手动刷新，不新增接口）；同时删掉顶栏常驻出口 IP 与 `show_egress_ip` 设置项。
- **Web（0.4.1）**：手机端「任务 → 发现」列表标签重叠、「发现详情」内容被裁切两处修复（未单独发版，随本版发布）。

### LLM

#### 修复的问题

- **仪表盘 token 统计并成一本账（`llm_usage`），删掉「旧版 / 新版」两套口径**：两套不是新老算法，而是两个不同粒度的账 —— `activity` 每次 agent run 结束写一条 `kind='result'`（累计快照），`llm_usage` 每次模型调用写一行。旧口径在仪表盘上少算 **45%**（1,066.7M vs 1,953.3M），四个原因全部实测：已归档任务的账被抽进 manifest（876M 归零）、`compactor`/`btw`/`goals` 这些不写 `activity` 的通道整条不计、进程被杀或超时的 run 一条账都没有、日图还按**任务创建日**归桶（10-25 一天 602M、10-23/24 全 0）。归档链路早就只从 `llm_usage` 算聚合，写侧一直认定的真源就是它 —— 缺的只是读路径。现在仪表盘、任务列表、任务详情三处读路径统一走 `llm_usage`，`activity` 的 token 字段降级为事件快照（只供实时展示，不再进统计）。
- **任务详情「按会话分解」改由计量账本给出，并给历史行留回退**：账本原来没有会话维度，所以「每段主会话 / 每个意图花了多少」只有旧账本能给。现在 `llm_usage.session` 记录 transcript 会话 id，映射成 UI 的 `main:<seg>` / `plan` / `intent:<id>`（后台 lane 与 chat 只进总量、不生成会话行）。`session` 列上线前的行全是 NULL，直接切会被统计成空 —— 因此**按任务**回退：该任务一行带 session 的调用都没有时，用 `activity` 的 run 行还原（实测覆盖 99%~100%），有一行就只认账本，两套永不同时相加（同一笔消耗两种描述，并集必然双计）。跨上线点的任务暂时只显示上线后新增的调用，随数据自然收敛。
- **任务列表的 token 列改读计量账本，并补上归档任务的聚合**：列表原来只读 `activity`，归档任务行被抽走后一律显示 0，导致仪表盘总量与列表求和对不上（差 876M）。改成读 `llm_usage` 并用 `COALESCE(task_archives.aggregate_stats->'tokens')` 兜住归档任务；顺手修掉仪表盘「任务数」把各 profile 的 tasks 相加的双计（一个任务跨 3 个 profile 会被算 3 次），改取账本的 distinct 任务数（含归档）。
- **仪表盘合计与「任务列表求和」严格相等**：已硬删除的任务**有意**保留账本行（历史记账，`db/tasks.go` 有明确注释），但这些行再也无法在任何页面查到，计入仪表盘就会让「仪表盘 = Σ任务列表(含归档) + Σ会话」不成立（实测差 0.4M）。改为三个全局聚合（`UsageByProfile` / `UsageDaily` / `UsageTaskCount`）统一带上「chat 行 或 所属任务仍存在」的谓词：账本一行不删，仪表盘不统计查不到的行，差值为 0（实测 1,993,718,154 = 1,993,718,154）。

#### 删除的功能

- **仪表盘「旧版 / 新版」数据源开关，以及两个前端零调用的 token 接口**：开关连同 `tokenByProfileOld` / `dailyTokenDataOld` / `convTokens` 两套派生、每 5s 空打一次的 `api.tokenStats()`（取的是"当前活跃任务"的量，其状态从未渲染）一起删除；后端删掉 `GET /api/tokens/daily`、`GET /api/tokens/conversations`、`GET /api/llm/records/by-model` 三个无调用方接口，以及 `TokenTotalsAll` / `TokenDailyAll` / `TokenStatsByWorker` / `TokenStatsBySession` / `ConversationTokenSummaries` 五个旧聚合函数与它们的 DTO。`/api/exploration/tokens` 保留原出参形状只换实现，前端 0 行改动。chat 页仍用 `conversation_activities` 实时算「这次对话花了多少」，那是另一个问题。

### Agent

#### 新增的功能

- **主 Agent 边界闸（`mainagent_direct_action`）**：主 Agent 是人类操作员的接口——回答问题、把人的要求转成目标（`set_goals` / `add_intent` / `steer_work`），执行交给规划者与 worker；但它的工具面挂着含 Bash 的默认工具集，实测会在收到「继续任务，已设好全局代理」后自己下场 27 分 44 秒、51 轮、60 次 Bash（几乎全是 curl / DNS / 验源站），一个回合烧掉 67.8M 输入 token 且零正文输出。提示词只能劝，所以在主 Agent 会话上新增 `PreToolUse` 钩子（`agent/mainagent_boundary.go`）：按 shell 段切词判定「自己直接对目标动手」的命令形态（网络客户端、扫描器、DNS/连通性探测、脚本内的出网调用），命中即拦下该次调用，并把替代通道（`add_intent` / `steer_work` / `set_goals` / `get_worker_output`）写回给模型。判定不只看段首词，`sudo -u … curl`、`cat urls | xargs -n1 nmap` 也能命中；段首是本地查看类命令（`grep` / `cat` / `jq` / `git` …）的段直接跳过，避免「`grep -o "https://…" run.log`」这类读日志操作被误伤。
- **提示词尾部新增代码拥有的「人机接口边界」段**：回答优先（先给一到三句人话再动手）、被问到项目现状时只用只读平台工具回答（不为回答去连目标）、被下达要求时翻译成项目目标、自己不直接对目标动手。它追加在渲染后的正文之后，DB 里改过的提示词正文删不掉（与 `artifactSpec` / `workerToolboxSpec` 同一惯例），并有单测锁住。
- **系统设置新增「主 Agent 边界闸」卡片**：三档 `仅提醒（默认）` / `收紧 Bash` / `关闭边界闸`，保存即时生效（每次工具调用读一次 settings）；`收紧 Bash` 在拦截之上把主 Agent 的 Bash 收窄为本任务目录内的只读查看命令白名单。归一化规则：未配置、读库出错、写错值一律回 `warn`，不允许配置缺失把闸悄悄关掉。

### Web

#### 删除的功能

- **顶栏「出口 IP」显示**：直连 / 全局代理出口 IP 常驻顶栏既占页面头部空间，又要求进任意页面都能看到，而它实际只在「偶尔确认代理是否生效」时有价值。删除整个 `egress-ip-banner.tsx`（Provider + Navbar）、设置页的「在顶栏显示出口 IP」开关（含开关状态、保存逻辑、保存代理后顺手重探顶栏的那一步）、后端 `show_egress_ip` 设置项（KV 常量、settingsPayload 出参、PUT 入参字段与分支）与前端 `Settings` 类型 / mock 字段。历史库里的 `settings.show_egress_ip` 行不再被读取，留库不动。设置页的「测试」按钮与探测明细保留——那是排查代理配置用的。

#### 新增的功能

- **仪表盘「出口 IP」卡片**：进仪表盘自动探测一次（未配置全局代理时只探直连），卡片内两栏并排显示<b>真实出口</b>（不经过代理的 IP）与<b>代理出口</b>（经已保存的全局代理出网的 IP），各带连通状态点、往返延迟与失败原因（取首个出错地址，`refused`=代理没开、`timeout`=出不了网），右上角可手动刷新——轮询不触发探测，避免每 5s 发一次真实出网请求。数据复用已有的 `POST /api/settings/proxy/test`，不新增接口、不新增表。响应式：窄屏单列堆叠、`sm` 以上两列，IPv6 用 `break-all` + `[overflow-wrap:anywhere]` 断行；390px 与 1280px 实测卡片无裁切、页面无横向滚动（`documentElement.scrollWidth` 等于视口宽，越界元素 0 个）。
- **仪表盘 token 卡片的统计口径与任务数**：卡片不再随「旧版/新版」开关跳变，数据源标注固定为 `llm_usage`；「任务数」改用账本的 distinct 任务数，跨 profile 的任务不再被重复计（同一任务跑过 3 个 profile 会被算 3 次）。

## [0.4.1] - 2026-10-28

本版未单独打 tag / 发 Release，改动并入 0.4.2。

### Web

#### 修复的问题

- **手机端「任务 → 发现」列表的标签重叠**：行容器是 `flex`（不换行），严重度标签与「流量证据 N 条」标签虽为 `whitespace-nowrap` 却仍是默认 `flex-shrink: 1`，390px 视口下被压到文字宽度以下，造成字体重叠。改为外层 `flex-wrap` + 两个标签 `shrink-0`；「流量证据」前缀在 `sm` 以下隐藏、只留「N 条」省宽度，桌面端文案不变。
- **手机端「发现详情」页内容被裁切**：概览区 `grid gap-4 lg:grid-cols-3` 未声明窄屏列，隐式列按 `auto`（= max-content）被内容撑到 **786px**，而容器仅 326px，导致 130 个元素超出视口右边界被硬切。改为显式 `grid-cols-1`（`minmax(0,1fr)`）+ 子项 `min-w-0`；摘要与证据块的 `whitespace-pre-wrap` 补 `break-words [overflow-wrap:anywhere]`，长 URL / 无空格串不再撑宽。

## [0.3.23] - 2026-10-28

### 自更新

#### 修复的问题

- **发布源指向本仓库**：`selfupdate` 的 `Repo` 原值指向一个已不存在的仓库（实测 GitHub API 返回 404），设置页「版本与更新」点检查更新必然失败并提示「仓库尚未发布任何正式版本」。现改为 `wdj2613/ARTEX`，并补注释说明发布方式：推 `v*` tag 后由 `release.yml` 自动构建五平台包、生成 `SHA256SUMS` 并创建 Release。资产命名两侧本就对齐（`AssetName` 与 `build.sh` 都去掉 tag 的 `v` 前缀，`artex-<版本>-<os>-<arch>.zip`）。

### CI

#### 修复的问题

- **release 工作流的镜像 job 改推 GHCR**：原 `docker` job 推 Docker Hub 且依赖 `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` 两个 secrets，本仓库没有这两个值，导致每次推 tag 都留一个永久失败的 job。改为 `ghcr.io/${{ github.repository }}`，用内置 `GITHUB_TOKEN` 并新增 `packages: write` 权限，本仓库无需任何额外配置即可全绿。

## [0.3.22] - 2026-10-28

### 工具链

#### 新增的功能

- **补齐 projectdiscovery 探测链**：新增 `httpx` v1.12.0（存活与指纹探测）、`dnsx` v1.3.1（子域解析）、`katana` v1.8.0（接口爬取），与既有 `subfinder`/`nuclei` 构成完整链路 `subfinder → dnsx → httpx → nuclei`。三者 bookworm 源都没有，按 `TARGETARCH` 从官方 release 下载；下载层改为循环，一个失败即中断（不再静默跳过）。镜像 3.1 → 3.2GB。
- **提示词与技能同步**：工具箱清单恢复为 15 个已装工具（含 httpx/dnsx/katana），并写明典型串联顺序；技能里三处因"镜像没有该工具"而写的替代方案（dig 循环、curl 提取源码、playwright 抓包）恢复为标准命令。测试断言改为正向 13 个工具名 + 反向 `nikto`/`hashcat`（这两个确实未装，提示词不得提及）。

## [0.3.21] - 2026-10-28

### 工具链

#### 修复的问题

- **字典与 nuclei 模板改为随镜像发布**：0.3.20 把字典与模板交给宿主机挂载，换一台机器部署时挂载源目录不存在——Docker 会静默创建空目录并挂载，反而把镜像内容盖成空的，agent 找不到字典、nuclei 没有规则可跑，开箱即不可用。现在字典（5 个文件共 2.1MB）随仓库发布并 `COPY` 进镜像 `/opt/artex/wordlists`，nuclei 模板（84MB）在构建时下载进镜像 `/root/.local/share/nuclei-templates`（单独成层，改代码或改字典都不会让它重下；下载失败只告警不中断构建）。
- **compose 挂载降级为可选覆盖**：两行挂载改为注释保留，想换更大的字典（如全量 SecLists）时跑 `scripts/fetch-wordlists.sh` 再启用即可——bind mount 天然覆盖镜像内置的同名路径，不需要额外开关。

#### 新增的功能

- **提示词补强两条纪律**：①「字典直接用，不要现造」——线上实测 agent 因找不到字典，现场写生成器造了 7 个脚本、38 个字典文件（4.2 MB），且每个意图重造一遍；通用字典已内置，只有针对性字典（目标默认口令、用户名组合）才需要生成。②「网络失败先重试再下结论」——线上 10-22 一次 `github: 000` 之后 agent 就永久断定「无外网」再没回头试，而实测同一容器随后 github/pypi 均可达；单次失败应重试/换源，不要一次失败就放弃整条路线。
- **修正提示词与镜像的工具清单一致性**：初版提示词与技能里列了 `httpx`/`dnsx`/`katana`，但镜像并未安装这三个，agent 照着试必然撞空。现在提示词、技能、测试断言三处统一为实际已装的 12 个工具（`nmap masscan ffuf gobuster dirb whatweb nuclei wapiti sqlmap hydra sshpass subfinder`），并加反向断言禁止再出现未安装的工具名。

## [0.3.20] - 2026-10-28

### 工具链

#### 新增的功能

- **镜像内置渗透工具链**：apt 层补充 `sqlmap` `whatweb` `hydra` `sshpass` `masscan` `dirb` `gobuster` `ffuf` `wapiti`（bookworm 源直接可装，多架构 CI 不受影响），另按架构下载 `nuclei`（v3.11.1）与 `subfinder`（v2.17.0）官方二进制。此前容器里只有 nmap/curl/python，agent 把目录爆破、口令爆破、指纹识别全部手搓成 curl 循环（线上 48h 实测：手写 curl 1,802 次、`which`/找字典试探 65 次、运行时 pip install 25 次）。
- **Python 依赖基线**：把 agent 反复在运行时安装的 `requests` `PySocks` `python-socks` `paramiko` `mmh3` `pyjwt` `bcrypt` `PyNaCl` `websocket-client` 打进镜像（运行时安装落在容器可写层，每次换镜像全丢）。本地构建可 `--build-arg PIP_INDEX_URL=...` 指定镜像源。
- **字典与 nuclei 模板走挂载不进镜像**：`wordlists/`（common / dir-medium / subdomains-5000 / usernames / passwords-top10k）与 nuclei 模板由 `scripts/fetch-wordlists.sh` 下载到宿主机，compose 只读挂载到 `/opt/artex/wordlists` 与 `/root/.local/share/nuclei-templates`；镜像体积不被字典撑大。生产 compose 同步加了两个挂载。
- **工具箱使用规约进入提示词（worker + mainagent）**：代码-owned 段 [F]，改 DB 提示词也丢不掉——按场景选工具（ffuf/httpx/sqlmap/hydra/subfinder/…）、字典固定路径、自装工具后必须 `create_custom_tool` 注册、`command -v` 只确认一次。配套新增 `pentest-toolbox` 技能（工具清单 + 标准命令模板 + 纪律），`TestToolboxSpecSurvivesOverride` 锁定该段在 DB 覆盖下依然存在。

## [0.3.19] - 2026-10-26

### 移动端适配

#### 修复的问题

- **播报板把时间/图标竖起来，正文宽度多出四成**：原来一行分成「时间列 4.5rem + 图标列 1.75rem + 正文」三栏横排，左侧光固定宽度就吃掉 108px —— 390px 手机上占掉三分之一，正文只剩 210px。改成左栏一列 2.5rem、时间在上、类型图标居中、相对时间在下的竖排，时间轴竖线从中穿过（文字用卡片底色遮罩），正文列宽 210→294px（+40%），正文段落 184→272px（+48%）；桌面端正文 797→861px。
  同时：收起态摘要从 2 行放宽到 3 行（`line-clamp-3` + `break-words`），行内上下内边距 `py-3`→`py-2.5`，卡片左右内边距窄屏 `px-4`→`px-2`，日期分隔线跟着收窄到 `pl-12`。

#### 其它修复

- 行首时间只显示到分钟（完整时间在 `title` 与展开区里），日期分隔符补空格：「7月26日周日」→「7月26日 周日」。

## [0.3.18] - 2026-10-26

### 移动端适配

#### 修复的问题

- **任务 LLM 配置弹层超出屏幕，「当前配置」点不到**：弹层原本只有宽度约束没有高度约束，内部也不滚动。手机上（尤其横屏或小屏）内容比视口高，底部「当前配置」下拉被推到屏幕外，无法切换当前激活模型。实测 390×420 视口下弹层高 445px、底部溢出 67px、下拉完全不可见；改为 `max-h-[min(85dvh,34rem)] + overflow-y-auto` 后弹层 357px、可滚动，下拉可见可选（已用无头浏览器验证选中生效且弹层不关闭）。配置链列表本身也加了 `max-h-64` 内部滚动，链再长也不会把操作区顶出屏幕。
- **发现列表在手机上是 960px 宽的固定表格**：`min-w-[60rem]` 让窄屏只能看到前两列、其余全靠横向拖动；漏洞名称/摘要又被 `nowrap` 截断，等于看不到内容。现在窄屏只保留「严重度 / 漏洞名称」两列，名称与摘要改为换行 + `line-clamp`，资产/状态/所属任务/时间/操作在窄屏隐藏，并把「状态」并入名称列（否则手机上改不了状态）；桌面端行为不变。实测 390px 下表格 358px 收进屏幕、内容换行、无横向溢出。
- **仪表盘任务表右列被裁掉**：`Card` 是 `overflow-hidden`，内部 `table` 没有横向滚动容器，窄屏右侧列直接消失。补 `overflow-x-auto` 包裹层。

#### 内部实现

- **全站 `vh` → `dvh`**（16 处）：移动端浏览器地址栏会让 `100vh` 大于可视高度，导致整页容器底部内容被顶出屏幕、弹层底部按钮被切。涉及流量/命令/LLM 记录/资产页的 `h-[calc(100vh-…)]`、图视图的 `72vh/68vh`、以及 8 个弹层的 `max-h-[…vh]`。

## [0.3.17] - 2026-10-26

### 上下文压缩

#### 修复的问题

- **超长块永远压不动，导致"后期反复压缩"**：`group()` 只有下界没有上界，任务后期整条方向的冷节点会连成一个 360+ 成员的巨块，压缩提示词长到模型直接返回空正文；块压不出来就一直是"未覆盖"，于是每轮 planner 都重试同一个巨块。线上 task 6 的日志证据：89 条压缩失败（67 条 `empty body from model`、22 条整轮预算耗尽）、同一块最多重试 8 次、块规模最大 384 个成员、压缩器累计 955 次调用里 405 次失败。现在按 `MaxMembers=40` 沿图切分（真实边 + 同父兄弟，扁平扇出也能切开），单块始终可压。
  - **压不动就二分，而不是整块丢弃**：一次压缩失败时把块对半拆开重试，最多拆两层；能覆盖一半也胜过覆盖零。
- **压缩失败会静默丢掉已有覆盖，把压缩变成死循环**：`major()` 原本先 `supersede` 旧 digest 再重建，重建失败时旧覆盖已经删掉 → 成员重新变成"未压缩" → 冷集合再次越过阈值 → 下一轮又压同一个块。线上表现为 `active` digest 只剩 36 个而 `superseded` 有 166 个。现在改为**先建后删**：新 digest 落库成功后，才回收"成员已重新覆盖"的旧 digest（`retirableDigests`），任何失败都不会让成员失去覆盖。
- **单块慢把整轮预算吃光**：整轮共用一个 5 分钟 context，线上出现过同一秒内 20 个块集体 `context deadline exceeded`。现在每个块独立 60 秒超时，单块超时只跳过该块；整轮预算仍然保留作为总闸。
- **失败块每轮重发**：按块签名记失败次数，失败后按 1/2/4/8 轮指数退避，成功或内容变化（签名变）立即解除。

#### 其它修复

- 压缩成功时补一条 `[compaction] ok exp=.. digest=.. members=.. chars=..` 日志：此前成功完全静默，只有失败可见，命中率无从统计。

## [0.3.16] - 2026-10-25

### 知识共享

#### 新增的功能

- **跨任务知识检索：规划者可以复用别的任务已经确认过的漏洞与手法**：任务级共享本来就有（`list_findings` / `list_facts` 覆盖本任务 + 直接关联任务），但"直接关联"依赖 `task_relations` 表，线上**只有 1 条记录** → 跨任务继承事实上不存在。而同一批目标常被多个任务反复打（线上 17 个资产被 2~3 个任务共用，同一厂商的多个部署分散在不同任务里），成果互不可见：71 条事实里显式写着"与 fact 1969 同构"这类交叉引用，**全部是同任务内引用，没有一次跨任务引用**。
  - **`search_knowledge(q)`（仅 planner）**：在所有任务里检索漏洞（`findings`）与探索事实（`exploration_nodes`），按「同资产交集 > 严重度 > 命中在标题/摘要 > 只命中正文」排序，**只返回指针**（`node_id`/`finding_id` + 摘要 ≤120 字 + 来源 `task_id` 与任务描述 + `same_asset`），全文用 `node_detail` 取。
  - **被动展示，零查询成本**：`graph_overview` 新增 `cross_task_findings`——只列**资产与本任务有交集**的其他任务已确认漏洞（≤8 条，按严重度），没有交集就不出现（全新目标的历史结论不适用，避免误导）。
  - **三道防重复闸**（针对"反复查询把上下文吃光"）：①只回指针不回全文（线上 `admin` 命中 709 条、摘要合计 17.8 万字符 ≈ 6 万 token）；②同一关键词在本任务内只展开一次，重复搜只回数量与前 5 个引用；③不同关键词合计受任务级额度约束（默认 6，设置项 `agent_knowledge_query_budget`，1~50），用完即拒并指向替代工具。查询账本落 `knowledge_queries` 表（归一化关键词为主键，重启不失效），命中集合变化时覆盖快照并在下次检索时提示"比上次多了/少了多少"。
  - **口径说明**：结果标明来源任务——**手法可迁移，结论不能直接搬**，工具描述明确要求在本目标复验后再落库。

### Agent

#### 修复的问题

- **worker 不再用阻塞式 `sleep` 烧意图预算**：一条意图只有一次性的墙钟预算（`run_seconds`，默认 1200 秒），而 worker 习惯用 `sleep 115` 原地等后台的爆破/枚举脚本——线上 2569 个工具回合里带 sleep，累计阻塞 74 小时，单任务就占 68 小时，多数意图的预算被睡光后直接 exhausted，期间没有任何进展。现在两层同时收敛：
  - **提示词侧**：worker 系统提示词末尾新增代码-owned 的「等待类任务的执行方式」段（与「中间产物输出规约」同级，改 DB 提示词也丢不掉），明确要求长跑任务用 `run_in_background` / `nohup` 起后台，再用 `TaskOutput` 或 `tail`/`grep -c` 抽查进度。
  - **调用侧**：worker 的工具调用前置钩子会拦下超过 30 秒的纯阻塞 `sleep`，直接返回「改用后台执行 + 轮询」的指令（带 `run_in_background` 的调用与短等待不受影响，脚本内部的 sleep 不管）。这条管控只作用于 worker，规划者/主 Agent 没有一次性墙钟预算，不受影响。

### Web

#### 新增的功能

- **系统设置页新增「跨任务知识检索」开关与关键词额度**：开关控制 `search_knowledge` 是否开放（默认开启），额度输入框限定 1~50 整数、越界直接提示不提交，保存走乐观更新 + 失败回滚并 toast。卡片里写明三道防重复规则与「结论必须在本目标复验」的口径，用户不用查文档就知道代价与边界。

- **系统设置页新增「意图去重闸」开关**：三档可选——仅提醒（默认，照常创建意图并把重复提醒回给规划者）、拦截在跑方向（同一方向已有 worker 在跑时拒绝创建）、关闭去重。改动即时生效、对下一轮规划生效；保存失败会回滚选中态并提示。

### 意图管理

#### 新增的功能

- **意图进度留痕：撞预算收尾后，规划者终于能看到「做到哪、还剩什么」**：意图是一次性时间预算的原子任务，撞到步数/墙钟上限就被迫收尾（线上 task#4 有 212 条这样收场，平均产出还有 1.5 个事实/发现——不是白跑，是被打断）。但此前进度只活在 worker 的临时脚本和 transcript 里（该任务 worker 转录单条最大 66MB），规划者看不到完成到哪个分片、剩哪些候选，只能原样再开一条同义意图从头跑。
  - **新工具 `report_progress`（仅 worker）**：每推完一个分片写一次 `completed` / `remaining` / `next_step`，直接落到意图节点的 `payload.progress`，后一次覆盖前一次（不叠历史噪声）。
  - **代码-owned 提示词段「进度留痕」**：说清「不汇报就等于这次预算白烧」，与产物规约、等待规范同级，改 DB 提示词也丢不掉。
  - **收尾自动补写**：worker 一次都没汇报时（撞墙钟被就地打断的常见情形），引擎在终态落库时自动补一条 `auto: true` 的记录，写明终态原因（max_turns / timeout / killed）与本次产出量，节点不再对"为什么停"完全沉默；worker 汇报过则保留其内容，只补终态与产出。
  - **概览可见**：`graph_overview` 的意图条目带上精简版进度（completed / remaining / next_step / auto），规划者不用再额外读轨迹就能判断「续跑还是换方向」。

#### 修复的问题

- **`add_intent` 增加近似去重闸，拦住"同一件事反复开新意图"**：此前创建意图没有任何服务端查重，去重全靠规划者自查。线上 task#4 的 395 条意图里 385 条（97%）是续跑型同义意图，前 6 小时 170M token 换到 5 条发现，之后 41 小时又烧 514M 只多 1 条；其中 79.5% 的 summary 直接把上一条意图的 id 写进了正文（`【续跑·#1510 done、…】`），重复是显式可判的。
  - **两个判定信号**：①summary 里出现 `#N` 且 N 是本任务已有意图；②与已有意图摘要的 Dice 相似度 ≥ 0.50（中文 bigram + 端口/主机/用户名等 ASCII 整词）。阈值在线上 395 条真意图上标定：续跑型 p50=0.57 / p90=0.88，真正的新方向最大只有 0.49，取 0.50 时误报为 0。
  - **处置分档，不一刀切**：命中**仍在场**（open/running/paused）的重复 → 提示"用 `steer_work` 纠偏或换方向"；命中**已结束**的重复 → 只提示"续跑可以，但要把本轮新增什么写清楚"。续跑是正当能力，不会被拦掉。
  - **模式可调**：新增设置项 `agent_intent_dedup`（`off` / `warn`（默认，照常创建+返回 `warnings`）/ `block`（重复对象仍在场时拒绝创建）），通过 `PUT /api/settings` 即时切换，无需重启。

#### 内部实现

- **`db.IntentDigests`**：按 id 倒序返回本探索的意图摘要快照（id/state/summary），供 `add_intent` 查重使用，避免每次都拉全量节点。
- **`db.SetIntentProgress` / `db.IntentProgress`**：把进度合并进意图节点 `payload.progress`，并读回（终态补写与概览展示共用）。

#### 其它修复

- **`kill_work` 改为幂等，已结束或尚未领取的意图不再报错**：规划者被意图收尾唤醒后常回头去终止这条刚结束的意图，此前一律返回「意图 N 当前没有运行中的 work（可能已结束或未被领取）」，既误导模型（看起来像操作失败）又让真正跑偏的意图没人去收——实测线上 32 次调用里 25 次落在这类"其实已经结束"的意图上。现在按状态给出确定结果：已结束（done/blocked/exhausted/stopped）直接回报其状态并视为成功；未在执行（open/paused）直接标记 stopped，省掉被 worker 领走后再白跑一轮；运行中才向 work 发终止信号。竞态下（读到 running、发信号时 work 恰好自行收尾）同样按成功回报，不再把正常收尾当失败。
- 意图终态的判定收敛到 `db.IntentTerminalState` 一处：存储层的状态落库与工具层的判定共用同一事实源，避免两边对"已结束"的理解漂移。
