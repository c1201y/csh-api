# ClassSoftwareHub 后端 · 腾讯云 EdgeOne Pages 部署说明

## 项目结构

| 文件 | 作用 |
|---|---|
| `functions/api/[[default]].js` | 主后端（移植自 CF Worker `classhub` 生产版），承接全部 `/api/**` 路由 |
| `functions/status.js` | 状态页 `/status`（HTML 仪表盘，30 秒自动刷新） |
| `functions/admin.js` | 管理后台页面 `/admin`（登录、激活码签发、设备封禁） |

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

### 正版校验相关（桌面端构建签名 / 激活码）

| 名称 | 类型 | 说明 |
|---|---|---|
| `CSH_BUILD_SECRET` | 密钥 | 官方构建签名密钥；必须与桌面端打包用的值一致（桌面端 `.secrets/build-secret.txt`） |
| `CSH_BUILD_SECRET_OLD` | 密钥 | 上一把构建密钥，轮换过渡期用，平时留空 |
| `CSH_LICENSE_SECRET` | 密钥 | 激活码与令牌签名密钥；**不要**与构建密钥相同 |
| `CSH_LIC_ENFORCE` | 文本 | `true` 才真正拦截；默认 `false`（观察期，只在控制台打 `license: would deny`） |
| `CSH_LIC_ENFORCE_AT` | 文本 | 定时开闸：到该 ISO 时间点后 `enforce` 自动为 `true`，无需再次部署。与 `CSH_LIC_ENFORCE` 任一成立即生效 |
| `CSH_LIC_LEGACY_UNTIL` | 文本 | 旧客户端（不带 `X-CSH-Build`）豁免截止日，ISO 时间 |
| `CSH_LIC_BROWSER_ORIGINS` | 文本 | 浏览器豁免域名，逗号分隔，默认 `classsoftwarehub.cn,www.classsoftwarehub.cn` |
| `CSH_LICENSE_DAYS` / `CSH_OFFICIAL_TOKEN_DAYS` | 文本 | 激活令牌 / 官方自动签发令牌的有效天数（365 / 30） |
| `CSH_LIC_TRY_PER_DAY` | 文本 | 同一来源每天激活尝试上限，默认 30 |

上线顺序：先发带签名的桌面版 → 后端以 `CSH_LIC_ENFORCE=false` 部署并观察日志 → 确认无误后设
`CSH_LIC_LEGACY_UNTIL` 与 `CSH_LIC_ENFORCE=true`。判定流程与环境变量含义见桌面端仓库
`docs/正版校验与服务端接入.md`。

过渡期建议：把 `CSH_LIC_ENFORCE_AT` 设为截止日（如首批签名版发布后 30 天），`CSH_LIC_ENFORCE`
保持 `false` 只观察；到点后自动开始拦截，不必再进控制台。要提前开闸就直接把 `CSH_LIC_ENFORCE`
改成 `true`。`/api/status` 的 `license` 字段会同时给出 `enforce` 与 `enforceAt`。

### 管理后台（`/admin`）

维护者登录后签发激活码、查看已激活设备、封禁设备。后台不是公开页面，但也没有独立域：
**必须配好下面两项才能登录**，否则页面会提示「后台未配置」。

| 名称 | 类型 | 说明 |
|---|---|---|
| `CSH_ADMIN_USER` | 文本 | 后台账号，默认 `admin` |
| `CSH_ADMIN_PASS` | 密钥 | 后台密码（明文比对，定长比较）。与 `CSH_ADMIN_PASS_SHA256` 二选一 |
| `CSH_ADMIN_PASS_SHA256` | 密钥 | 密码的 SHA-256 十六进制（小写）。设置后优先于 `CSH_ADMIN_PASS`，避免在控制台留明文 |
| `CSH_ADMIN_SESSION_SECRET` | 密钥 | 会话签名密钥；留空时回落 `CSH_LICENSE_SECRET`。建议单独配一把，便于轮换会话而不动激活码 |
| `CSH_ADMIN_API_TOKEN` | 密钥 | 服务间令牌（≥16 位）。观测台用它调用 `/api/admin/*`，无需浏览器会话；留空则只能走 Cookie 登录 |

会话有效期 12 小时，Cookie 为 `csh_adm`，属性 `HttpOnly; Secure; SameSite=Strict; Path=/`。
同一来源连续登录失败 10 次锁定 30 分钟；写操作额外校验 `Sec-Fetch-Site` 与 `Origin`/`Referer`，
跨站提交直接 403。**因为带 `Secure`，请通过 https 访问后台**（本地 http 调试时 Cookie 不会落地）。

### 激活码签发与设备管理

1. 打开 `https://<后端域名>/admin`，用上面的账号登录。
2. 「签发激活码」填数量（1–50）与备注，点「生成」。生成的码可单个点击复制，也可「复制全部」；
   记录会留在下方「签发记录」里，随时回来复制。
3. 用户把客户端的**设备码**发给你时（激活对话框里有），可对照「已激活设备」确认是哪一台；
   要停用某台设备，点「封禁」选时长（1 天 / 3 天 / 7 天 / 30 天 / 永久）并填原因，
   原因会原样出现在客户端提示里。
4. 封禁立即生效：被停用设备调受保护接口（提交、回声洞、反馈、OSS 直传、教室喊话）与再次激活
   都返回 `429 {"code":"csh_device_banned"}`，即使手里的令牌还没过期。

### 设备信誉与 429

客户端在请求头 `X-CSH-Did`（或 `X-CSH-Device`）里带上设备标识后，服务端会：

1. **封禁优先**：命中 `lic:ban:<device>` 的请求直接回 `429`，`code=csh_device_banned`，
   换 IP / 换网络也甩不掉。被停用设备重新激活同样 429。
2. **按设备限速**：`dl-ticket` 60 次/分、`oss-sign` 与 `mirror-sign` 40 次/分、
   `submit` 6 次/分、`echocave` 20 次/分、`feedback` 10 次/分、`activate` 10 次/分；
   超限回 `429`，`code=csh_device_rate_limited`，并记录一条违规事件。
3. **活动日志**：通过时把最近请求写入 `lic:ev:<device>`（每 10 分钟最多一条），
   后台可经 `GET /api/admin/device-events?device=...` 查看事件、封禁与当日报数。

设备标识建议用 `SystemIdentification.GetSystemIdForPublisher()`（Win10+）生成，
取不到时退回本地持久随机 ID。没有设备码的请求仍走各接口原有的 IP/配额逻辑。

语义边界（重要）：

- 激活码是**离线签名凭证**，服务端不查表就能验。因此吊销只对「尚未激活」的码有效；
  已激活的码不允许吊销（接口返回 409），要停用只能封禁设备或轮换 `CSH_LICENSE_SECRET`。
- 签发时序列号取 `lic:seq` 与索引中的最大值加一，单维护者场景够用；多人同时签发有极小概率撞号
  （KV 非原子），撞了会在列表里表现为同一序列号被覆盖，重新签一个即可。
- 后台记录只是对账用的索引（`lic:c:idx` / `lic:dev:idx`，各保留最近 200 条），
  删记录不影响已发出激活码的可用性。

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
6. `GET /admin`（https）→ 输错密码被拒并累计次数，正确密码进入控制台，刷新页面仍保持登录。
7. 后台生成 1 个码 → 在非官方构建里激活 → 「签发记录」显示已激活、「已激活设备」出现该设备码。
8. 对该设备「封禁」→ 客户端下一次在线操作被拒（`csh_device_banned`，提示里带原因）→「解封」后恢复。
9. 本地回归：`node smoke-admin.mjs` 全 PASS（内存 KV，不需要部署）。

## 域名

- 目标：`api.classsoftwarehub.cn`（EdgeOne 控制台添加自定义域 → 节点提供者把该子域 CNAME 到 EdgeOne 分配的接入点）。
- 无 ICP 备案时走境外 POP（国内可达性远好于被阻断的 132614.xyz，但非腾讯大陆节点）。
- 建议同时绑定 `api.classsoftwarehub.us.ci` 作备份入口（DNS 在自己手里，5 分钟生效）。

## 客户端收尾（部署验收通过后）

- Win7 桌面端 `MirrorSign.cs` 端点数组首位替换为新域。
- 网页端 `githubMirror.ts` 的 `fetchSelfSignedUrl` 同步加新域。
- Win10 端按 `win10-sign-domain-handoff.md` 同步。
