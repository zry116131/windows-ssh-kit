# Windows SSH Kit

Windows x64 / ARM64 离线 SSH 启用、诊断和修复工具。支持从 U 盘运行，日志直接写入 U 盘，结束后自动生成诊断 ZIP。

**下载：[最新 Release](https://github.com/zry116131/windows-ssh-kit/releases/latest)**，选择 `Windows-SSH-Kit-*-x64-ARM64.zip`。GitHub 自动生成的 Source code ZIP 不含离线安装文件。

## 快速开始：生成密钥 → 带公钥到目标机 → 启用 SSH

**连接端**是以后发起 SSH 连接的电脑；**目标端**是要开启 SSH 的 Windows。先在连接端生成配套密钥，私钥留在连接端，U 盘只携带自动配好的公钥。

1. 在连接端将 Release ZIP **完整解压到 U 盘**，保留 `payloads` 目录。
2. 在连接端运行 **00-Generate-Client-Key**：Windows 双击 `.cmd`；Mac 双击 `.command`。按提示设置私钥口令，也可按两次回车不设口令。Mac 如无法双击，可在终端输入 `bash ` 后拖入 `.command` 文件并回车。
3. 工具将新密钥保存在连接端用户目录的 `.ssh/windows-ssh-kit-唯一标识/`，自动把公钥写入 U 盘的 `windows-admin.pub`。同时生成 `CLIENT-CONNECTION.txt`，包含配套私钥路径和连接命令，不包含私钥内容。
4. 将 U 盘拿到目标 Windows，双击 **01-Enable-SSH.cmd** 并同意 UAC。已有 SSH 故障可以使用 **04-Repair-SSH.cmd**。无需再选择或粘贴公钥。SSH 账号是 UAC 提权后实际执行脚本的本地管理员。
5. 记下窗口显示的 `SSH login name`、Windows IP 和主机公钥指纹。回到连接端，按 `CLIENT-CONNECTION.txt` 中的命令填写登录名和 IP 后连接，并核对首次显示的主机指纹。

生成器会保留已有密钥；工具目录已包含公钥或连接说明时会停止，不会静默换钥。需要配对另一台连接端时，使用一份全新解压的包。连接端生成器不需要管理员权限。

**不要在目标机上生成登录密钥后只把公钥带回连接端**：发起 SSH 的电脑需要私钥。已配对的同一份 U 盘包可用于多台目标 Windows，它们会信任同一把连接端公钥。服务器自己的主机密钥由安装流程另行处理。

已有自己的 Ed25519 密钥时，可以跳过生成器，在目标 Windows 上双击可选入口 **05-Import-Public-Key.cmd** 选择 `.pub`；也可以直接复制并重命名为 `windows-admin.pub`。未配对的公开发行包不含默认密钥。

Windows 连接端优先使用系统 `ssh-keygen`；系统没有安装 SSH 客户端时，从固定哈希的离线载荷中临时提取对应 x64／ARM64 的工具，生成后清理临时程序。Mac 使用系统 `ssh-keygen`。生成过程不上传密钥。

## 操作入口

| 文件 | 用途 |
|---|---|
| `00-Generate-Client-Key.cmd` / `.command` | 在连接端生成专用密钥，自动将公钥配入安装包 |
| `05-Import-Public-Key.cmd` | 可选：使用已有 Ed25519 公钥 |
| `01-Enable-SSH.cmd` | 离线安装／复用已有服务，配置公钥并启动 |
| `02-Check-SSH.cmd` | 收集诊断、检查配置和服务，不自动修复 |
| `03-Revoke-Key.cmd` | 删除本工具的公钥、Match 配置、状态文件和防火墙规则 |
| `04-Repair-SSH.cmd` | 检查并修复本工具支持的 SSH 安装 |
| `Verify-Admin.ps1` | 在 SSH 会话内验证实际管理员令牌 |

检查／撤销不需要工具目录中的公钥文件。安装／修复需要公钥；缺失或格式错误会在服务安装和配置更改前停止。

## U 盘日志

例如将工具解压到 `E:\Windows-SSH-Kit`，日志会写入：

```text
E:\Windows-SSH-Kit\Logs\电脑名_时间_随机标识\
E:\Windows-SSH-Kit\Logs\电脑名_时间_随机标识.zip
```

优先查看 `SUMMARY.txt`、`summary.json`、`error.txt`、`repairs.txt` 和 `progress.json`。每次执行独立保存，记录 UAC 前后运行过程、原生命令输出／退出码／超时、修复前后快照和近期 SSH 事件。

U 盘不可写时，会提示并回退到 `%TEMP%\Windows-SSH-Logs`，需要手动复制回来。运行时不要拔盘；断电或进程被强制结束时，最终 ZIP 可能没有生成，已写好的日志目录仍可保留。

日志包含用户名、IP、文件路径、SSH 配置和事件记录，**请先检查和脱敏，再公开到 GitHub Issue**。工具不复制登录私钥或主机私钥；不要将自己配对后的工具目录、`CLIENT-CONNECTION.txt`、日志或密钥目录直接提交到仓库。

## 自动修复范围

- 校验固定版本的官方离线 ZIP 哈希和 PE 架构；对本工具安装目录逐文件比对，补回缺失或损坏的程序。替换前备份原文件。
- 修复 `ProgramData\ssh`、日志、配置、公钥和主机私钥 ACL；不修改已有主机私钥内容，只生成缺失的主机密钥。
- 规范标准 sshd 服务路径引号、必需的服务权限和自动启动。
- 检查 sshd 配置语法、目标用户有效公钥路径、TCP 22 占用及服务监听。首次启动失败保存现场，刷新权限后重试一次。
- 失败时尝试恢复本次配置、公钥、状态、原服务启动方式和本次修改的防火墙规则；新建服务失败后禁用。

这是有限修复，不是完整系统回滚。已经完成的程序修复、ACL 和标准服务权限修复、生成的主机密钥及防护注册表设置会保留，并记录到日志。

程序备份留在目标 Windows 的安装目录下 `repair-backups`，不会放进诊断 ZIP。端口被其它进程占用时停止，不强杀进程；自定义服务路径／身份、`Include`、非 22 端口、额外认证因素等复杂配置需要人工处理。

## 权限与安装行为

- 只配置启用的本地管理员账号。域账号和 Entra-only 账号不在本工具自动配置范围内。
- 用 `Match User` 将导入的公钥限定到目标账号，同时列入 Windows 管理员默认公钥路径及 `.ssh/authorized_keys`。自定义认证配置请先审核适配。
- 不关闭 UAC、不修改默认 SSH shell、系统 PATH 或已有 ssh-agent，不关闭防火墙，不改变现有密码认证设置。
- sshd 以 LocalSystem 运行；远程会话使用登录账号的权限，不能把服务身份当作会话身份。
- 本工具新增规则仅允许 `LocalSubnet` 访问 TCP 22，适用所有网络配置文件；已有其它规则保持原样，既有更广范围的放行仍然有效。
- 优先复用现有标准 Windows OpenSSH 服务或本工具安装的服务。没有服务时使用随包离线程序，不访问 Windows Update。
- 安装／修复会重启 sshd，可能打断现有 SSH 连接，建议在本地桌面或 U 盘运行。
- 为兼容早期版本，管理标识保留为 `WindowsSSH-20261012`。专用公钥存放于 `%ProgramData%\ssh\WindowsSSH-20261012.authorized_keys`。
- 独立版程序路径为原生 `%ProgramFiles%\WindowsSSH-20261012\OpenSSH-Win64` 或 `OpenSSH-ARM64`，只有管理员与 SYSTEM 可写。

`03-Revoke-Key.cmd` 不卸载 OpenSSH、不删除其它密钥，也不会撤销已经建立的 SSH 会话。若需要完全停止远程服务，在管理员 PowerShell 中运行：

```powershell
Stop-Service sshd
Set-Service sshd -StartupType Disabled
```

## 验证实际登录权限

通过 SSH 登录后，在远程执行（替换解压路径）：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\Windows-SSH-Kit\Verify-Admin.ps1"
```

只有 `AdministratorToken : True` 且 `SSHConnection` 非空，才确认当前 SSH 会话具有管理员令牌。本地脚本成功仅代表本地检查通过。服务配置为自动启动后，还应在允许重启时重新连接验证。

## 兼容和版本

目标系统：Windows 10 1809／Windows 11 x64，以及 Windows 11 ARM64；需要 Windows PowerShell 5.1。x86、Linux、macOS 不作为被安装的服务端；它们可以作为 SSH 连接端（需有 SSH 客户端）。实际验证范围见 [VALIDATION.md](VALIDATION.md)。

离线载荷固定为 Microsoft / PowerShell 官方 [Win32-OpenSSH 10.0.0.0p2-Preview](https://github.com/PowerShell/Win32-OpenSSH/releases/tag/10.0.0.0p2-Preview)。**上游明确标记为 Preview、非生产就绪**。本工具会复用已有系统版本；对稳定发布渠道有要求时，应先通过 Windows 可选功能安装系统 OpenSSH Server。

固定载荷来源和 SHA-256 见 [SOURCE.json](SOURCE.json)。原始 ZIP 未改动，保留上游 LICENSE／NOTICE；独立版不会自动更新。本工具版本号与 OpenSSH 版本号相互独立。

官方参考：[Windows 公钥认证](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)、[OpenSSH 启动与目录权限故障](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-1053-1067-7034-after-update-openssh-doesnt-start)。

## 从源码构建

构建端需要 Python 3.9+，测试需要 PowerShell。仓库不存放二进制载荷；下面命令在构建端获取固定官方版本并检查哈希，之后生成可离线使用的 ZIP：

```sh
python tools/build_release.py --download-payloads
pwsh -NoProfile -File tests/Test-Repair-Package.ps1
pwsh -NoProfile -File tests/Test-PublicKey.ps1
python tests/test_client_pairing.py
```

在 macOS／Linux 上额外运行模拟 Windows 接口的诊断与修复测试：

```sh
pwsh -NoProfile -File tests/Test-Repair-Diagnostics.ps1
```

输出在 `dist/`。打包程序采用明确的文件清单，即使目录里已有个人 `windows-admin.pub`、`Logs` 或 `CLIENT-CONNECTION.txt`，也不会被打包。Release 同时提供整个 ZIP 的 `.sha256`；包内 `SHA256SUMS.txt` 校验各交付文件。CI 在 Linux／Windows 检查，Windows 额外用 PowerShell 5.1 验证。
