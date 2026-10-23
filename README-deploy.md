# ClassSoftwareHub 后端 · 腾讯云 EdgeOne Pages 部署说明

## 项目结构

| 文件 | 作用 |
|---|---|
| `functions/api/[[default]].js` | 主后端（移植自 CF Worker `classhub` 生产版），承接全部 `/api/**` 路由 |
| `functions/status.js` | 状态页 `/status`（HTML 仪表盘，30 秒自动刷新） |

状态数据接口：`GET /api/status`，返回各子系统健康度（KV / OSS / GitHub API / 签名配置）与运行统计。

## 与 CF Worker 的差异（已实现）

| CF 组件 | 腾讯侧替代 |
|---|---|
| `export default { fetch }` 入口 | `onRequest(context)` 桥接（`functions/api/[[default]].js` 尾部） |
| Durable Object `DownloadGate` | 状态存储二选一（自动优先级）：① EdgeOne KV（绑定名 **`CSH_STATE`**）；② EdgeOne Blob（`@edgeone/pages-blob`，命名空间 `csh-state`，免审批免配置，首次调用自动创建）。两者同协议 shim：`idFromName().fetch()` 调用面不变 |
| `cloudflare:sockets` TCP 中继 | OSS V4 预签名直连 HTTPS（`ossSignedUrl` + 重写的 `relayOpen` / `relayListDetailed`） |
| `scheduled` cron（孤儿回收） | 懒触发：`/api/dl-ticket` 每 20 分钟搭车执行一次 `runGc`；`/api/gc` 手动接口保留 |
| Response.json 兼容性 | 运行时头部有 polyfill |

## 控制台配置步骤

1. 创建 Pages 项目并导入本目录（Git 集成或直接上传）。
2. **状态存储（默认零配置）**：代码自动走 Blob 存储（`getStore('csh-state')`），无需申请审批，部署后发首个闸门请求即自动建命名空间。可选优化：若已开通 EdgeOne KV，创建命名空间 → 绑定变量名 `CSH_STATE`，代码即自动优先 KV（切换当日每日配额计数清零一次，持久登记表无需迁移）。
3. **环境变量**：按下表逐项配置（与 CF Worker 绑定同名同值）。

### 环境变量清单（原 CF `classhub` 绑定）

| 名称 | 类型 | 值来源 |
|---|---|---|
| `ALLOWED_ORIGIN` | 文本 | 同 CF 原值 |
| `DL_MODE` | 文本 | 建议填 `direct`（腾讯侧无独立中继，auto 亦可用） |
| `DL_DAILY_LIMIT` / `DL_DIRECT_MONTHLY_GB` / `DL_RELAY_MONTHLY_GB` | 文本 | 同 CF 原值 |
| `GC_ORPHAN_MINUTES` / `GC_STALE_RECORD_HOURS` | 文本 | 同 CF 原值 |
| `GITHUB_OWNER` / `GITHUB_REPO` / `GITHUB_BRANCH` | 文本 | 同 CF 原值 |
| `OSS_BUCKET` / `OSS_ENDPOINT` / `OSS_PREFIX` / `OSS_PUBLIC_BASE` / `OSS_REGION` | 文本 | 同 CF 原值 |
| `SUBMIT_REQUIRE_SOURCE` / `SUBMIT_MAX_PER_DAY` / `SUBMIT_MAX_PENDING` | 文本 | 同 CF 原值 |
| `DL_SIGN_SECRET` | 密钥 | 同 CF 原值（本地存于 `.workbuddy/dl-sign-secret.txt`） |
| `GITHUB_TOKEN` | 密钥 | 同 CF 原值（CF 侧只写不可读，需从 GitHub 侧取） |
| `OSS_ACCESS_KEY_ID` / `OSS_ACCESS_KEY_SECRET` | 密钥 | 阿里云 RAM 子账号密钥 |
| `PURGE_TOKEN` | 密钥 | 本地存于 `.workbuddy/purge-token.txt` |
| `RELAY_HOST` / `RELAY_PORT` / `RELAY_TOKEN` | 密钥/文本 | 中继相关；腾讯侧文件操作已改直连，可留空 |
| `SIGN_API_KEY` | 密钥 | 同 CF 原值 |

## 已知行为差异 / 风险

1. **KV 最终一致**：原 Durable Object 是强一致单点；KV 为最终一致。每日配额（票据 25 次/设备/天）在极端并发下可能少量超发；文件登记表在低频管理操作下实际无竞争。原 15 分钟孤儿回收窗口不受影响。
2. **CPU 限制 200ms**：纯流式转发不受影响；签名为纯 crypto 计算，无压力。
3. **OSS 直连签名**：`ossSignedUrl` 完整复用生产验证过的 V4 签名模式（`/桶/键` 规范 URI + host 额外签名头）。部署后通过 `/status` 页的 OSS 探测项即可确认（探测 = 真实 ListObjects 调用）。
4. **中继通道**：`/api/dl-ticket` 返回的 relay 路径走的是本函数自身（`/api/dl`），内部已改为 OSS 直连拉流，客户端无感。`RELAY_*` 三个变量仅剩统计语义。

## 验收清单（部署后逐项执行）

1. `GET /status` → 页面全绿（KV / OSS / GitHub API 三项必须「正常」）。
2. `GET /api/mirror-sign?url=<GitHub 直链>` → 返回 `success:true` 与 `url`。
3. 网页端「加速下载」走新域 → 文件 sha256 与官方一致。
4. `POST /api/submit`（真实投稿一次）→ GitHub Issue 生成、OSS 对象落桶。
5. 教室喊话：发送 → 教室机轮询收到。

## 域名

- 目标：`api.classsoftwarehub.cn`（EdgeOne 控制台添加自定义域 → 节点提供者把该子域 CNAME 到 EdgeOne 分配的接入点）。
- 无 ICP 备案时走境外 POP（国内可达性远好于被阻断的 132614.xyz，但非腾讯大陆节点）。
- 建议同时绑定 `api.classsoftwarehub.us.ci` 作备份入口（DNS 在自己手里，5 分钟生效）。

## 客户端收尾（部署验收通过后）

- Win7 桌面端 `MirrorSign.cs` 端点数组首位替换为新域。
- 网页端 `githubMirror.ts` 的 `fetchSelfSignedUrl` 同步加新域。
- Win10 端按 `win10-sign-domain-handoff.md` 同步。
