# DriverTrapper — 驱动捕获器

Windows 内核驱动加载取证工具。`dt.exe` 是管理员权限运行的 Win32 窗口程序；`kdt.sys` 监视内核映像加载，`sdfilter.sys` 是按需启动的文件系统 minifilter，用于在已识别的内核映像文件被删除或破坏前保存证据。

本项目面向隔离测试机。请在加载测试样本前启动工具，并使用可恢复的虚拟机快照。过滤器 altitude 是本地实验值，不能用于正式分发。

## 项目结构

| 路径 | 说明 |
| --- | --- |
| `dt/` | 用户态窗口程序。查找同目录的 `kdt.sys`、`sdfilter.sys`，显示加载事件、捕获结果和 minifilter 状态。 |
| `kdt/` | 映像加载通知驱动，维护用户态事件队列并尝试复制映像文件。 |
| `sdfilter/` | 独立 x64 minifilter 和用户态通信协议。 |
| `driver-trapper.slnx` | Visual Studio 解决方案，包含以上三个项目。 |

## 启动与监控

1. 以管理员身份启动 `dt.exe`。首次目录为 `C:\DriverDump`；目录保存在 `%LOCALAPPDATA%\DriverTrapper\settings.ini`。如果新设置文件不存在，程序会读取旧版 `%LOCALAPPDATA%\DriverTarpper\settings.ini` 中的目录，并在下次保存时迁移到新路径。仅接受本机磁盘或挂载卷上的绝对路径，不接受 UNC 路径。
2. 点击“开始监控”后，程序先检查 altitude 冲突，再在注册表中临时创建 `dtself` 驱动服务和 minifilter 默认实例配置，然后按需加载过滤器、连接 Filter Manager 通信端口并提交当前转储目录，再启动或复用 `kdt`。正常停止时卸载过滤器并删除临时服务注册；崩溃后遗留的同名服务会在下次启动时复用并清理。
3. minifilter 准备失败时，窗口会持续显示红色“自删除捕获不可用”状态，`kdt` 映像加载监控仍会继续。该状态表示工具只保留原有的映像加载和异步文件复制能力。
4. 过滤器记录正常映射的内核映像候选，并关联规范化文件路径和卷路径。候选最多保留 256 个，空闲 15 分钟后可被清理。它检查候选文件的删除、改名、删除时关闭、创建覆盖/替换、截断、分配大小调整和写入操作。
5. 命中候选后，过滤器暂挂原文件操作，并为该次操作保存当时配置的转储目录；在该目录下的 `SelfDeleteSnapshots` 子目录创建唯一命名的 `.bin` 快照、SHA-256 哈希和 UTF-8 `.json` 元数据。元数据记录映像加载时间、破坏性操作时间、操作类型、源路径、卷路径、文件大小、哈希和结果。快照、哈希和元数据都成功保存后才放行原操作；保存失败会进行一次初始尝试和最多三次重试，仍失败则拒绝该文件操作并记录原因。
6. 点击“应用”会同时更新 `kdt` 和 minifilter。每次破坏性文件操作使用该操作到达过滤器时的目录；切换目录前已排队的操作仍使用旧目录，切换后到达的操作使用新目录。任一驱动更新失败时，程序尝试恢复另一端；恢复失败会停止监控并显示错误。过滤器捕获事件、快照路径和哈希显示在事件列表中。
7. 正常停止或确认关闭时，程序先停止由自己管理的 `kdt` 服务，再关闭过滤器通信、等待挂起捕获结束、卸载 minifilter 并清理 `dtself` 服务配置。可通过其他服务管理的 `kdt` 会被复用，程序不会停止或卸载它。

窗口标题为“DriverTrapper — 驱动捕获器”，使用 Windows 当前的系统消息字体，并启用 Per-Monitor V2 DPI 感知。跨不同缩放比例的显示器移动窗口时，字体和控件布局会随 DPI 调整。

## 取证边界

映像加载通知在映像映射之后、驱动入口执行之前调用；Windows 还可能通过 `IMAGE_INFO_EX` 提供映像后备文件对象。这让过滤器有机会在驱动入口删除自身文件之前登记候选映像。[`PLOAD_IMAGE_NOTIFY_ROUTINE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pload_image_notify_routine)、[`IMAGE_INFO_EX`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_image_info_ex)

本工具无法追回启动过滤器前已经删除的文件。手动映射、绕过文件系统的写入、分页 I/O 写入、未能关联到映像候选的文件操作以及过滤器未附加的卷也不保证捕获。遇到这些情况，应先保全磁盘并采集内存；受感染系统上的用户态信息可能被 rootkit 篡改。[NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final)

运行时注册使用 `FSFilter Activity Monitor` 组和实验 altitude `385201`，启动前会检查当前已加载过滤器是否占用该值。它只适用于本地隔离测试；正式分发前必须向 Microsoft 申请分配的唯一 altitude，并完成驱动签名。[加载组与 altitude](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)

## 构建

需要 Visual Studio C++ 桌面开发工具、Windows SDK 和 WDK。项目以 x64 为运行目标，构建 `dt` 会构建 `kdt` 和 `sdfilter`。完整输出在解决方案根目录的 `x64/Release/`；部署时将 `dt.exe`、`kdt.sys` 和 `sdfilter.sys` 放在同一目录即可，不需要 INF/CAT 包或 Driver Store 安装。

驱动项目配置为 KMDF，但 `kdt` 源码有意采用 WDM 风格实现（`DriverEntry`、IRP 派发和 `IoCreateDevice`）；这是设计选择。`sdfilter` 则是独立的 WDM minifilter。

两个驱动都使用 `/INTEGRITYCHECK`，该选项要求映像加载时验证数字签名；它不负责签名，目标系统仍须接受驱动签名。实际加载还受目标系统的签名策略约束，不能仅凭成功构建判断可运行。

## 运行要求与风险

- 只在隔离测试机中运行，并在样本加载前启动监控。此过滤器不是启动早期捕获方案。
- 自删除失败时过滤器会拒绝对应的文件操作。这可能改变测试样本行为；使用快照回滚并保留控制台外的虚拟机恢复手段。
- 窗口目录需要可写。快照会写入 `SelfDeleteSnapshots`，原 `kdt` 文件复制仍是异步尝试，并可能因同名文件冲突而覆盖。
- 程序需要管理员权限来临时创建驱动服务和实例注册表。正常退出会清理这些条目；断电或进程崩溃可能留下 `dtself` 服务项，下一次启动会识别并清理。
- 加载和卸载 minifilter 时，程序会临时启用令牌中已分配的 `SeLoadDriverPrivilege`，操作后恢复原状态；若账户令牌没有被分配此权限，窗口会报告权限错误。
- `/INTEGRITYCHECK` 只要求加载时检查映像签名，不会绕过目标系统的驱动签名和加载策略。

