# geektrace

Android-first 的**外部观测式**动态追踪工具，只面向 **已 root 的测试设备**。目标是在不向目标 App 注入 agent、不修改目标内存和文件的前提下，尽可能完整地还原：

- 启动链：zygote fork → 进程命名 → APK/DEX/so 加载 → 加固壳行为 → MainActivity
- 安全检测：root / App 列表 / ADB / 开发者选项 / 调试器 / 环境完整性
- 数据路径：文件、内存映射、Binder、TLS、HTTP、加解密与哈希
- 覆盖率：native 基本块/分支/循环；Java 层能力边界单独标注
- 证据链：稳定 JSONL 事件、调用栈开关、AI 可直接分析的 run 摘要

> 当前版本 **v0.1.0（alpha）**：首选设备端原生 `geektraced`，支持文本配置、内嵌 BPF、常驻等待目标 App 与 UID 过滤；Python CLI 保留为可选的定位、报告和 ADB 冷启动工具。自建 bench APK、arm64/x86_64 二进制和 host 数据链路已完成离线验证。真机方面，Android 13 / Linux 4.19 已完成 bench 实测：自动回退 perf-buffer、8/8 CPU 注册、14/14 可挂载探针（16 个程序中 2 个 `syscalls/` tracepoint 由 raw_syscalls 接管而跳过），openat 路径改由 sys_exit + procfs 回填，22 秒采集 355 条事件。Android 14 / Linux 5.10.236 也已完成 Bench 实测：ringbuf、13/15 探针、TLS/EVP 明文与 SIGINT 清理正常，20 秒写入 70,418 条事件、0 ringbuf drop。首次真机请先使用 bench 并按 [docs/USAGE.md](docs/USAGE.md) 收集日志。本轮源码与 host 内嵌设备 assets 已更新，`dist/` 发布包尚未重建。
>
> - 使用说明：[docs/USAGE.md](docs/USAGE.md)
> - 设计方案：[docs/DESIGN.md](docs/DESIGN.md)
> - 任务清单：[docs/TASKS.md](docs/TASKS.md)
>
> 本轮（2026-10-27）新增，重点是**更低的足迹、更小的扰动与跨内核一致能力**：
> - **库探针懒挂载**：默认不再预埋 uprobe，而是等目标进程确实映射了某个库之后，再把探针挂到**目标实际加载的那份 so** 上（同名库时 App 自带的那份优先）；目标没用到的库保持原始代码页（`--eager-uprobes` 可回到启动即挂载行为）。
> - **默认跳过共享 /system 副本（FIPS 实测）**：在 4.19 真机上，给 `/system/lib64/libcrypto.so` 挂 uprobe 会让无关系统进程在 BoringSSL FIPS 完整性自检中 `SIGABRT`（`sha256sum`、`cat`、`ps` 均复现）；只挂 apex Conscrypt 副本则完全正常。因此 `/system/lib*` 的 libssl/libcrypto 副本默认跳过，并在日志里写明原因；需要时用 `--libssl PATH` / `--libcrypto PATH` 显式指定该文件（会重新引入 FIPS 副作用）。art 共享副本同样跳过。
> - **< 5.8 的 openat 路径回填**：旧内核没有 `bpf_probe_read_user*`，helper 4/45 对用户地址返回 `EFAULT`。legacy 镜像在 openat 入口暂存 dfd/flags，在 `raw_syscalls/sys_exit` 带出 fd，broker 用 `/proc/<pid>/fd/<fd>` 回填路径。事件带 `fd` 与 `"path_source":"proc_fd"`；fd 在 broker 读取前已关闭时如实标 `capture_status: read_failed`（实测约一半短生命周期 open 会如此），不伪造路径。5.10 镜像不包含该程序，行为不变。
> - **多副本覆盖**：App 通常同时映射 Conscrypt 的 libcrypto（Java 加密）和系统副本（native 链接）；系统副本默认不碰，只挂 Conscrypt 副本，挂了几份写进 `tool.capability` 的 `libraries` / `library_copies`。
> - **副本预算**：`--lib-copies N` 限制 crypto 每类最多挂几份（默认 2）；TLS 固定只挂 1 份 Conscrypt。Bench 实测（4.19）：2 份库、14 个探针、0 失败。
> - **足迹清单**：`summary.md` 新增 **8.2 Footprint / 可见面**，逐条列出本次 trace 对目标/系统可见的面（root、broker 进程、tracefs 定义、共享库代码页断点、时序扰动、目标内 agent/写入），并明确写“这不是隐身证明”。
> - **预埋时机三档**：`--pre-arm on-sight`（默认，目标一出现就布）、`eager`（开跑即布）、`lazy`（目标映射该库才布，足迹最小但可能漏掉启动阶段的加密）。
> - **`payload_limit`**：每次事件从目标读出的字节上限，`0` 表示完全不读目标内存，只留元数据。
> - **`tool.capability` 事件**：开跑前先声明本机实际能力（事件通道、用户内存读取是否可用、payload 上限、栈支持、探针数、实际挂载的库），让报告能区分“未观察到”和“本机不支持”。
> - **`policy.capture_status`**：区分 `captured / truncated / read_failed / metadata_only / empty`，避免把“没采到”当成“没有”。
> - **`geektrace graph`**：把请求、加密调用、代码位置、检测结论连成带置信度的证据图。
> - **`geektrace preflight`**：APK 静态盘点 + 检测候选清单 + 设备能力自检 + 观测计划（面向已授权 App 的事先预演）。
> - **profile 真实生效**：`ai / stealth / safe` 映射到设备侧的 payload 上限与栈开关；`coverage / deep` 仍标记为设备端未实现。
>
> **真机复测（Android 14 / 5.10.236 / KernelSU / arm64，Bench 自建 App）**：
> 20–25 秒采集稳定产出 **14 万条事件、0 丢事件、0 解析错误、0 seq 缺口**；加密调用 14 万次可完整还原；
> 检测面命中 root×7、hook_integrity×4、debugger×1，每条都能回溯到原始 `file.open` 证据；
> `TracerPid=0`；停止后 `tracefs/uprobe_events` 为空，无残留。

## 快速开始

首选单个原生 `geektraced`，手机端不需要 Python、配置文件或控制脚本。先确认设备已连接且 `adb shell su -c id` 返回 `uid=0`。首次推送 arm64 设备二进制：

```bash
adb shell mkdir -p /data/local/tmp/geektrace
adb push device/build/geektraced_arm64 /data/local/tmp/geektrace/geektraced
adb shell chmod 755 /data/local/tmp/geektrace/geektraced
```

每次追踪只运行一条命令：

```bash
adb shell su -c "/data/local/tmp/geektrace/geektraced -f com.example.app"
```

终端会像 `frida-server` 一样保持前台运行。此时手动打开并操作 App；结束后按 `Ctrl+C`，同一进程会清理 uprobe 并退出。事件写到设备 `/data/local/tmp/geektrace/events.jsonl`，诊断直接显示在终端。换 App 时 `Ctrl+C` 后用新包名重新执行即可，无需重新安装或修改配置。

```bash
adb pull /data/local/tmp/geektrace/events.jsonl runs/events.jsonl
```

`geektraced` 内嵌 BPF 对象，探针在目标启动前挂载，随后按包名对应 UID 等待；可跨目标重启持续采集。默认不采集其他 App 的 zygote fork。事件通道自动选择：Linux 5.8+ 使用 BPF ringbuf；没有 ringbuf 的旧内核自动回退到 perf event buffer，探针集合和 JSONL schema 不变。`--config` 和旧的自动化入口仅作为高级/兼容用法保留，日常不需要。

Python wheel 是可选的报告工具：

```bash
python -m pip install dist/geektrace-0.1.0/geektrace-0.1.0-py3-none-any.whl
geektrace import runs/device-bench --app com.geektrace.bench
geektrace report runs/device-bench --format md

# 可选：按明文/密文字节定位；stack=true 才能带回已采集的用户态 PC
geektrace locate runs/device-bench 'hex:aabbccdd' --capture capture.pcap --format md
```

`locate` 将直接 crypto 字节命中标为 `payload_exact`，抓包/网络与 crypto 的时间近邻只标为 `temporal_inferred`，不会把时间相近伪装成因果证明。

```bash
# 请求 → 加密调用 → 代码位置的证据图（每条边都带置信度）
geektrace graph runs/device-bench --format md

# 面向已授权 App 的事先预演：APK 静态盘点 + 检测候选 + 设备能力 + 观测计划
geektrace preflight --apk app.apk --app com.example.app --out runs/preflight
```

原有 host 一次性冷启动仍保留：

```bash
geektrace doctor
geektrace run --app com.geektrace.bench --duration 30s \
  --activity com.geektrace.bench/.MainActivity
```

从源码构建设备二进制和安装可选 CLI：

```bash
./device/build.sh
python -m pip install -e host --no-build-isolation
```

没有设备时可验证数据格式与报告链路：

```bash
geektrace demo
geektrace run --app com.geektrace.bench --dry-run
geektrace schema --validate runs/<session>
```

导入报告后的目录包含 `events.jsonl`、`manifest.json`、`summary.md/json`、`events/index.json`、`README.log.md` 和 schema。原始 JSONL 始终是唯一事实源。

## 自建 bench app

`tests/benchapp` 是一个 Java + JNI 的轻量测试 App（包名 `com.geektrace.bench`），
用于在真实设备上验证启动链、检测行为、私有目录文件、native 分支、crypto 和 TLS
观测。它使用公开 NIST/标准向量与本地 TLS loopback，不访问外部网络。

```bash
# 需要 Android SDK + NDK + JDK；无需 Gradle 或联网
bash tests/benchapp/build.sh
# 产物：tests/benchapp/build/GeekTraceBench.apk

# 连接设备后安装并启动
bash tests/benchapp/build.sh --install
```

构建脚本会生成本地签名 key 与 TLS P12（位于 `tests/benchapp/keys/`，已忽略）；
确定性测试向量见 [tests/golden/bench-crypto-vectors.json](tests/golden/bench-crypto-vectors.json)。
当前未连接 root 设备，APK 已通过 `aapt2` / `zipalign -P 16` / `apksigner` 校验，
但运行时行为（Conscrypt/TLS、memfd、检测检查）尚未在设备上验证。

## 设备侧 eBPF 采集

`device/` 下是一个不依赖 libbpf/BTF 的最小闭环：自包含 BPF C 探针 + 静态
`geektraced`（raw `bpf()` syscall、tracefs uprobe、ringbuf/perf event buffer），用于在已 root 设备上
验证“eBPF 观测目标进程且目标内无注入”。

日常采集使用 `device/geektrace.sh` 和设备端 `geektracectl`：单文件 broker 内嵌 BPF，
通过 `geektrace.conf` 指定包名，`duration=0` 常驻等待，停止时拉取 JSONL。Python 只在
需要摘要时执行 `geektrace import`。原有 `geektrace run` 和 `device/run_poc.sh` 保留为
一次性冷启动与调试备用流程。

```bash
./device/build.sh                    # 产出 arm64/x86_64 内嵌 BPF 的 geektraced
./device/geektrace.sh bench          # 一键完成安装、采集、停止和拉取
```

PoC 当前采集：

- `process.fork`：默认仅目标 UID 发起的 fork；host 冷启动或显式 `zygote_forks=true` 时也采集 zygote/zygote64 fork；
- `file.open`：目标 UID 的 `openat` 路径/dfd/flags；5.8+ 由内核直接复制路径，< 5.8 由 `sys_exit` 的 fd + procfs 回填（`args.fd`、`args.path_source`），回填失败时 `capture_status=read_failed`；
- `net.connect`：`connect` 入口的 fd、地址族、IPv4/IPv6 地址与端口；尚未关联返回值或 SSL fd；
- `net.tls_write` / `net.tls_read`：`SSL_write` 输入明文，以及 `SSL_read` 返回后的明文头部与返回值（最多 256B）；
- `crypto.evp_update` / `crypto.digest` / `crypto.sign_update` /
  `crypto.verify_update`：EVP 输入长度与头部；`EVP_EncryptUpdate`、`EVP_DecryptUpdate`
  另有返回事件，包含返回值、输出长度、输出头部，并以 `call_id` 与同一次入口事件配对；
- `detect.finding`：复用高信号 `file.open` 证据观测 root 路径、调试器状态、hook/完整性和网络状态读取，通过 `evidence_ids` 回查；
- `tool.capability`：开跑时声明本机实际能力（通道、用户内存读取、payload 上限、栈、探针数、实际挂载的库），用于区分“未观察到”和“本机不支持”；
- 库探针默认**懒挂载**：只有当目标进程确实映射了 `libssl.so`/`libcrypto.so` 时才附加，且挂在目标加载的那份 so 上；共享 `/system/lib*` 副本默认跳过（FIPS 自检实测），App 自带副本与 apex Conscrypt 副本优先，`--libssl/--libcrypto` 可强制指定；
- payload 读取上限由 `payload_limit` 控制（0 = 完全不读目标内存）；
- 可选 `stack=true`：TLS/crypto 事件最多采集 8 个用户态 PC，broker 通过 `/proc/PID/maps` 输出 module/file_offset；失败写入 `tool.gap`。

`run_poc.sh` 输出 `events.jsonl`、`broker.log`、`target-status.txt`（含
`Name/Pid/TracerPid/Threads`，在启动约 3 秒后采样一次，只能证明该时刻无常驻调试器）。
采集结束后，脚本会用宿主机的 `python3`/`python`
（可用 `GT_PYTHON` 指定）自动执行 `geektrace import`，把同一目录补成标准 run：
`manifest.json`、`summary.md`、`summary.json`、`README.log.md`、`events/index.json`、
`schema/event.v1.json`。`target-status.txt` 会解析进 `manifest.json` 的 `target`
字段，`summary.md` 会显式给出 `TracerPid`（0 表示无常驻调试器）。

若宿主机没有 Python，脚本只保留原始 `events.jsonl` 并给出提示，可稍后手动补：

```bash
PYTHONPATH=host/src python -m geektrace import runs/poc-<时间戳> \
  --app com.geektrace.bench
```

`import` 会校验每条事件、统计无效行、拒绝混合 session 与 app 冲突，并基于原始事件
重新生成摘要；重复执行是幂等的。原始 `events.jsonl` 始终是唯一事实源，也可直接用
`jq`/Python 分析。

已知限制（PoC 阶段）：

- 事件通道自动选择：Linux 5.8+ 用 BPF ringbuf；4.14–5.7 用 perf event buffer（legacy helper 25/4/45），4.18 以下自动改用不含 `bpf_get_stack` 的镜像。4.19 真机实测：16 个程序中 14 个可挂载探针全部挂上、0 失败，22 秒 355 条事件，栈 16/16 解析；同址 entry/return uprobe 是否可并存由启动探测决定；
- 每次事件的 payload 最多 **255 字节**（`policy.capture_status` 与 `policy.omitted_bytes` 会写明是否被截断）；`payload_limit=0` 时完全不读取目标内存；
- 库探针懒挂载意味着进程刚启动的一小段时间内可能还没有 TLS/crypto 探针（事件会缺失并写入 `tool.gap`），需要全覆盖时用 `--pre-arm eager`；
- **多副本与系统副本**：Java 加密走 Conscrypt 的 libcrypto；native 加密若链接系统 libcrypto，默认不会自动挂载该共享副本（FIPS 自检会让无关系统进程 abort），这类目标的 native 加密证据会缺失，需要时用 `--libcrypto /system/lib64/libcrypto.so` 显式承担副作用；
- 高频加密（例如一次签名循环刷 10 万次）会显著拉高事件量；环形缓冲已放大到 64 MiB 并持续排空，仍不够时报告会写 `tool.drop`，不要把缺失误读成“没有加密”；
- `connect` 只有 syscall 入口，不含返回值；TLS 握手、HTTP 解析、fd↔SSL 与五元组关联尚未实现；
- EVP 算法名、key/IV 尚未解析；每次调用只保留最多 256B 输入/输出头部，不能用截断数据反向排除关键词；
- 当前栈是最多 8 个用户态 PC 的 maps 解析，不是基于 CFI 的完整 unwind，也不保证 Java/ART 帧；
- 不支持动态 so 定位失败时的自动回退，`--libssl/--libcrypto` 路径需与设备一致；
- ringbuf/perf 通道溢出导致的丢事件会在结束时写入 `tool.drop`；探针部分挂载失败、栈采集失败、用户内存读取失败和 entry/return 状态保存失败会写入 `tool.gap`。高频 openat 仍可能挤占通道，长跑需要观察 drop/gap；
- 正常退出/收到 SIGINT/SIGTERM 时会移除动态 uprobe；若被 SIGKILL 或宿主断连，
  同名 uprobe 可能残留，下次启动会先移除同名定义，也可重启设备清理；
- `geektrace run` 当前只支持 `cold-start` 模式；`ai/stealth/safe` 三个 profile 已真实映射到设备参数（payload 上限与栈开关），`coverage/deep` 仍标记为设备端未实现。设备端常驻等待由独立
  `geektracectl` 提供。`attach`、断线重连仍未实现；
- 检测 finding 目前只覆盖高信号文件路径；ADB/开发者属性、App 列表 Binder、完整设备/环境/RASP 检测仍未闭环；
- 加固解包、DEX 内存扫描、loader/ART/JNI/Binder 语义尚未形成真实采集链；
- 本轮（2026-10-27）的 `/system` 跳过策略、legacy openat 路径回填与探针计数已在 4.19 真机复测；5.10 真机回归已通过（70,102 事件、0 缺口、13/13 探针、SIGINT 清理干净）。uprobe 定义现挂在每次会话随机的 `gt_xxxxxx` 组下，不再有固定的 `geektrace/*` tracefs 特征；启动时按同一模式清理历史残留定义，外来组名不动。
  完整用法与故障排查见 [docs/USAGE.md](docs/USAGE.md)。


## 核心原则

1. **仅 root 设备**：不做非 root 兼容；ADB 只是传输通道，root 是观测前提。
2. **观测优先**：默认不注入、不 patch 目标 App、不修改返回值、不伪造检测结果。
3. **无 UI/无浮窗**：工具本身不安装桌面 App、不申请悬浮窗/无障碍；避免被“有其他 App 浮层/UI 工具”这类检测命中。输出是 JSONL + Markdown/JSON 摘要，交给 AI 或命令行分析。
4. **无痕是目标进程内的无痕**：没有 agent、没有新线程、没有 TracerPid；但 root、eBPF uprobe、KernelPatch 在系统层仍然可能有痕迹，文档会如实标注。
5. **最小足迹**：只在目标真正用到的库上挂 uprobe，只读取被明确允许的字节数，栈默认关闭。观测的“安静”优先于“全覆盖”。
6. **覆盖分层**：便宜的覆盖做全量（bitmap/聚合），昂贵的 payload 只在高价值事件上开启。
7. **后端可插拔**：eBPF 为默认观测后端；KPM、QBDI、外部抓包/静态分析工具作为可选后端或数据源。
8. **先 Android + 先自建测试 App**：iOS 只预留接口；v0.1 不直接分析真实第三方 App。

## 现实边界

- 通用第三方 App 观测必须 root。`adb shell` 读不到其他 App 的 `/proc/<pid>/maps`、`mem`、`fd`，SELinux 禁止 ptrace。
- “全 App 每一条 if/else/while 都执行到”不能以可接受的性能开销实现。geektrace 提供 native 静态 CFG + 基本块/分支 bitmap 的引导覆盖，Java 分支级覆盖需要注入式深度模式或外部工具，默认不承诺。
- 加固/RASP 可能检测 root、eBPF、代码页完整性或时序异常。geektrace 会记录检测行为，但不内置绕过；隐藏环境属于外部工具和授权测试环境的一部分。
- 绝对无痕不存在。目标是**目标 App 进程内低侵入、避免使用 Frida/Xposed/浮窗等高频特征**，不是承诺骗过所有 RASP。

## 授权使用

仅用于**已获授权的**应用安全评估、恶意样本分析、CTF、兼容性研究和自有 App 调试。不要用它绕过 DRM、窃取第三方数据或规避生产环境的安全控制。

---

日志与文档中的运行标记统一使用 `geekbyter===>`，便于过滤。
