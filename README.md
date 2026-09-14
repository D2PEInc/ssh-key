# SSH Security Installer

一个面向 Linux VPS 的交互式 SSH 加固脚本，用于管理公钥、SSH 登录方式、SSH 端口和 Fail2Ban。

脚本默认管理当前登录用户；通过 `sudo` 运行时默认管理 `SUDO_USER`。它不会输出私钥，也不会自动上传服务器数据。

## 支持的系统

- Debian、Ubuntu、Linux Mint、Kali
- RHEL、CentOS、Fedora、Rocky Linux、AlmaLinux、Oracle Linux、Amazon Linux
- Alpine Linux
- Arch Linux、Manjaro、EndeavourOS
- openSUSE、SLES

要求：

- Linux
- Bash 4 或更新版本
- root 权限或可用的 `sudo`
- 已安装并正常运行的 OpenSSH Server

## 安装

```bash
git clone https://github.com/D2PEInc/ssh-security-installer.git
cd ssh-security-installer
chmod +x key.sh
./key.sh
```

建议先阅读脚本并从 VPS 控制台保留一个恢复入口。不要在未经检查的情况下使用 `curl | bash`。

## 建议的安全操作顺序

1. 导入公钥。
2. 保留当前 SSH 会话，打开一个新终端测试公钥登录。
3. 如果需要换端口，先在云厂商安全组中开放新端口。
4. 修改 SSH 端口，再用新端口建立一条新连接。
5. 确认新连接正常后，单独关闭密码登录。
6. 最后检查 Fail2Ban 的 `sshd` jail 是否正在运行。

不要在同一次执行中导入新公钥、修改端口并关闭密码登录。脚本会阻止最危险的组合，但真实的新连接测试仍必须由你完成。

## 交互模式

直接运行：

```bash
./key.sh
```

菜单提供以下功能：

- 从 GitHub 或 HTTPS URL 导入公钥
- 在 VPS 上临时生成 ED25519 密钥
- 查看和删除 `authorized_keys` 中的公钥
- 启用或关闭公钥登录
- 启用或关闭密码及键盘交互认证
- 安装、配置、启动或卸载 Fail2Ban
- 修改 SSH 监听端口

推荐在自己的电脑或硬件密钥上生成私钥。只有明确确认后，脚本才会在 VPS 上生成临时私钥；脚本拒绝空口令私钥，也不会把私钥打印到终端。生成后仍需通过 SFTP 下载并及时删除服务器副本。

## 命令行模式

```text
-g <用户名>    从 GitHub 用户的 .keys 地址导入公钥
-u <URL>       从 HTTPS URL 导入公钥
-f <文件>      从本地文件导入公钥
-p <端口>      修改 SSH 端口，允许 22 或 1024–65535
-d             关闭密码和键盘交互认证，必须配合 -c
-c             确认已使用目标用户和公钥完成新的 SSH 登录测试
-o             覆盖 authorized_keys；会先验证来源并创建备份
-h, --help     显示帮助
```

示例：

```bash
# 从 GitHub 导入公钥；预期指纹必须来自可信渠道
KEY_SH_EXPECTED_FINGERPRINTS='SHA256:可信指纹' ./key.sh -g github-user

# 从本地公钥文件导入
./key.sh -f ~/.ssh/id_ed25519.pub

# 修改端口；请先开放云安全组
./key.sh -p 2222

# 完成新的公钥登录测试后，单独关闭密码登录
./key.sh -d -c
```

覆盖现有有效公钥前，必须先测试密码备用连接：

```bash
KEY_SH_CONFIRMED_PASSWORD_LOGIN=1 ./key.sh -o -f ~/.ssh/authorized_keys.new
```

`-o` 不能与 `-p` 同时使用。覆盖操作会备份原 `authorized_keys`，但仍建议先追加新公钥、测试成功，再删除旧公钥。

## 环境变量

| 变量 | 用途 |
| --- | --- |
| `KEY_SH_TARGET_USER` | 指定要管理的系统用户 |
| `KEY_SH_ALLOW_UNMANAGED_FW=1` | CLI 模式下，确认已经自行处理原生 iptables/nftables 规则 |
| `KEY_SH_FIREWALLD_ZONE` | 多个 firewalld 活动区域且脚本无法识别入站接口时，明确指定区域 |
| `KEY_SH_CONFIRMED_PASSWORD_LOGIN=1` | 覆盖现有有效公钥前，确认已经测试密码备用连接 |
| `KEY_SH_EXPECTED_FINGERPRINTS` | CLI 从 GitHub/URL 导入时必须提供的预期 SHA256 指纹；多个用空格或逗号分隔 |
| `KEY_SH_F2B_TRUST_CURRENT_IP=1` | 明确要求把当前 SSH 客户端 IP 永久加入 Fail2Ban 白名单；共享 NAT/VPN 环境慎用 |
| `KEY_SH_LIB_ONLY=1` | 仅加载函数，供自动化测试使用 |

例如管理 `deploy` 用户：

```bash
sudo KEY_SH_TARGET_USER=deploy ./key.sh -f /tmp/deploy.pub
```

## 安全设计

- 公钥写入前使用 `ssh-keygen` 校验，只接受裸公钥，拒绝私钥和授权选项前缀。
- HTTPS 下载限制协议、重定向次数、时间和文件大小，并拒绝 URL 中的认证信息。
- `authorized_keys` 使用文件锁、同目录临时文件和原子替换，并在覆盖或删除前备份。
- 写入和关闭密码登录前检查 home、`.ssh`、`authorized_keys` 的所有者和权限是否满足 OpenSSH `StrictModes`。
- 管理其他用户的密钥文件时，会降权为目标用户执行文件操作。
- SSH 配置修改前保存快照，使用 `sshd -t` 和 `sshd -T` 验证，服务重载失败时自动恢复。
- 修改端口前检查端口占用、systemd socket、SELinux、UFW、firewalld 和原生防火墙规则。
- firewalld 分别跟踪 runtime 与 permanent 规则；未提交的防火墙和 SELinux 修改会在失败或中断时回滚。
- 修改端口前确认 Fail2Ban 的 `sshd` jail 可由脚本安全同步；修改后验证实际监听状态，再提交 Fail2Ban 配置。
- 删除最后一把有效公钥或关闭公钥登录前，要求确认可用的密码备用连接。

SSH 配置事务锁位于：

```text
/var/lib/key-sh/sshd-transaction
```

如果脚本报告事务锁或回滚失败，请保留当前连接，从 VPS 控制台检查 SSH 配置和监听状态。不要在未确认快照内容和服务状态时直接删除锁目录。

## 已知限制

- 脚本不能修改云厂商安全组、上游硬件防火墙或 NAT 端口映射。
- `Match Host` 和 `Match RDomain` 无法被脚本可靠重放；遇到这类配置时，高风险认证切换会停止。
- 全局 SSH 登录设置仍可能被现有 `Match` 块覆盖，应使用 `sshd -T -C ...` 检查具体连接上下文。
- 脚本可以强制比较远程公钥指纹，但无法判断“预期指纹”的来源是否可信；不要照抄脚本刚显示的实际指纹作为预期值。
- 不同发行版、定制 OpenSSH unit 和第三方防火墙配置可能需要人工处理。生产环境使用前应保留控制台访问并先做备份。

## 查看公钥指纹

```bash
ssh-keygen -lf ~/.ssh/id_ed25519.pub
```

导入远程公钥前，请将这里显示的 `SHA256:` 指纹与可信来源提供的指纹进行比较。
