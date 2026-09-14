#!/bin/bash
#=============================================================
# SSH Security Installer (key.sh)
# Multi-distro: Debian/Ubuntu, RHEL/CentOS/Fedora/Rocky/Alma,
#               Alpine, Arch/Manjaro, openSUSE
#=============================================================
# Hardened revision: 2026-09-14. Bash >= 4, Linux; no private-key output.
# fixes: lockout guards, effective Port verification, firewall/config rollback
set +x
umask 077
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH
unset BASH_ENV ENV CDPATH
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    printf '%s\n' '需要 Bash 4 或更新版本。' >&2; exit 1
fi

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"
PURPLE="\033[35m"; CYAN="\033[36m"
GRAY="\033[90m"; BOLD="\033[1m"; RESET="\033[0m"

INFO="${GREEN}[INFO]${RESET}"; WARN="${YELLOW}[WARN]${RESET}"; ERROR="${RED}[ERROR]${RESET}"

JAIL_CONF="/etc/fail2ban/jail.local"
LOG_FILE="/var/log/fail2ban.log"
TARGET_JAIL="sshd"

SSHD_MAIN="/etc/ssh/sshd_config"
SSHD_CONF_DIR="/etc/ssh/sshd_config.d"
SSHD_CUSTOM="/etc/ssh/key-sh.conf"
SSHD_LEGACY="${SSHD_CONF_DIR}/99-key.sh.conf"
SSHD_MANAGED_BEGIN="# BEGIN key.sh managed include"
SSHD_MANAGED_END="# END key.sh managed include"

[ "$EUID" -ne 0 ] && SUDO="sudo" || SUDO=""

PKG_MGR=""; INIT_SYS=""; SSH_LOG=""; OS_ID=""; OS_VER=""; OS_SHORT=""
SSHD_TXN_DIR=""

# 使用 sudo 运行时，默认管理原登录用户，而不是误写 /root/.ssh。
# 如需管理其他用户，可在运行前设置 KEY_SH_TARGET_USER。
resolve_target_user() {
    if [ -n "${KEY_SH_TARGET_USER:-}" ]; then
        TARGET_USER="$KEY_SH_TARGET_USER"
    elif [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        TARGET_USER="$SUDO_USER"
    else
        TARGET_USER="$(id -un)"
    fi

    if ! id "$TARGET_USER" >/dev/null 2>&1; then
        echo -e "${ERROR} 目标用户不存在: ${TARGET_USER}"
        exit 1
    fi

    TARGET_UID="$(id -u "$TARGET_USER")"
    if command -v getent >/dev/null 2>&1; then
        TARGET_HOME="$(getent passwd "$TARGET_USER" 2>/dev/null | awk -F: 'NR==1 {print $6}')"
    else
        TARGET_HOME="$(awk -F: -v u="$TARGET_USER" '$1 == u {print $6; exit}' /etc/passwd 2>/dev/null)"
    fi
    if [ -z "$TARGET_HOME" ]; then
        case "$(uname -s)" in
            MINGW*|MSYS*|CYGWIN*) TARGET_HOME="${HOME}" ;;
            *) printf '%s\n' '无法确定目标用户的真实家目录，已停止。' >&2; exit 1 ;;
        esac
    fi
    case "$TARGET_HOME" in
        /*) ;;
        *) printf '%s\n' '目标用户的家目录不是绝对路径，已停止。' >&2; exit 1 ;;
    esac
    if [ "$TARGET_HOME" = / ] || [ ! -d "$TARGET_HOME" ] ||
       [[ "$TARGET_HOME" == *$'\n'* || "$TARGET_HOME" == *$'\r'* ]]; then
        printf '%s\n' '目标用户的家目录无效或不安全，已停止。' >&2
        exit 1
    fi
    if [ "$EUID" -ne 0 ] && [ "$EUID" -ne "$TARGET_UID" ]; then
        printf '%s\n' '管理其他用户需要 root；普通用户只能管理本人。' >&2; exit 1
    fi
    SSH_DIR="${TARGET_HOME}/.ssh"
    AUTHORIZED_KEYS="${SSH_DIR}/authorized_keys"
}

resolve_target_user

# ============ 命令行帮助 ============
case "${1:-}" in
    -h|--help)
        cat <<HELP
SSH Security Installer

用法:
  $0 [选项]

交互模式:
  直接运行 $0 进入交互式菜单

命令行模式:
  -g <用户名>    从 GitHub 拉取公钥
  -u <URL>       从自定义 URL 拉取公钥
  -f <文件>      从本地文件导入公钥
  -p <端口>      修改 SSH 端口
  -d             全局禁用密码登录（须配合 -c，并与导入公钥/改端口分开执行）
  -c             确认已使用目标用户和公钥完成新的 SSH 登录测试（仅可与 -d 同用）
  -o             覆盖模式（先验证所有来源，再一次性替换并备份）

公钥输入只接受裸公钥，不接受 command= 等授权选项。URL 不允许携带令牌。

环境变量:
  KEY_SH_TARGET_USER=用户名   指定要管理的用户
  KEY_SH_ALLOW_UNMANAGED_FW=1  在无 ufw/firewalld 且检测到限制性 iptables/nft 时仍允许改端口（CLI）
  KEY_SH_FIREWALLD_ZONE=区域   多个 firewalld 活动区域且无法识别入站接口时，明确指定区域
  KEY_SH_CONFIRMED_PASSWORD_LOGIN=1  使用 -o 替换现有有效公钥前，确认已测试密码备用连接
  KEY_SH_EXPECTED_FINGERPRINTS="SHA256:..."  CLI 导入远程公钥时必须提供的预期指纹（多个用空格或逗号分隔）
  KEY_SH_F2B_TRUST_CURRENT_IP=1  明确要求把当前 SSH 客户端 IP 加入 Fail2Ban 永久白名单

其他:
  -h, --help     显示帮助

目标用户:
  默认操作当前登录用户；通过 sudo 运行时默认操作 SUDO_USER。
  如需指定其他用户：KEY_SH_TARGET_USER=用户名 $0 ...
HELP
        exit 0 ;;
esac

# ============ 能力检测 ============
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"; OS_VER="${VERSION_ID:-}"
    else
        OS_VER=$(uname -r); OS_ID="unknown"
    fi
    case "$OS_ID" in
        debian) OS_SHORT="Debian" ;;
        ubuntu) OS_SHORT="Ubuntu" ;;
        linuxmint) OS_SHORT="Linux Mint" ;;
        kali) OS_SHORT="Kali" ;;
        rhel) OS_SHORT="RHEL" ;;
        centos) OS_SHORT="CentOS" ;;
        fedora) OS_SHORT="Fedora" ;;
        rocky) OS_SHORT="Rocky" ;;
        almalinux) OS_SHORT="AlmaLinux" ;;
        ol) OS_SHORT="Oracle Linux" ;;
        amzn) OS_SHORT="Amazon Linux" ;;
        alpine) OS_SHORT="Alpine" ;;
        arch) OS_SHORT="Arch" ;;
        manjaro) OS_SHORT="Manjaro" ;;
        endeavouros) OS_SHORT="EndeavourOS" ;;
        opensuse*) OS_SHORT="openSUSE" ;;
        sles) OS_SHORT="SLES" ;;
        *)
            local first="${OS_ID:0:1}"
            OS_SHORT="$(echo "$first" | tr '[:lower:]' '[:upper:]')${OS_ID:1}"
            ;;
    esac
}

detect_pkg_mgr() {
    for pm in apt dnf yum zypper pacman apk; do
        command -v "$pm" &>/dev/null && { PKG_MGR="$pm"; return; }
    done
    PKG_MGR="unknown"
}

detect_init() {
    if [ -d /run/systemd/system ]; then INIT_SYS="systemd"
    elif [ -d /run/openrc ]; then INIT_SYS="openrc"
    elif [ -x /sbin/init ]; then INIT_SYS="sysvinit"
    else INIT_SYS="unknown"; fi
}

detect_ssh_log() {
    case "$OS_ID" in
        debian|ubuntu|linuxmint|kali) SSH_LOG="/var/log/auth.log" ;;
        rhel|centos|fedora|rocky|almalinux|ol|amzn) SSH_LOG="/var/log/secure" ;;
        alpine) SSH_LOG="/var/log/messages" ;;
        arch|manjaro|endeavouros) SSH_LOG="/var/log/auth.log" ;;
        opensuse*|sles) SSH_LOG="/var/log/messages" ;;
        *) SSH_LOG="/var/log/auth.log" ;;
    esac
}

# ============ 服务管理抽象 ============
svc_start()  { case "$INIT_SYS" in systemd) $SUDO systemctl start "$1" 2>/dev/null;; openrc) $SUDO rc-service "$1" start 2>/dev/null;; sysvinit) $SUDO service "$1" start 2>/dev/null;; *) return 1;; esac; }
svc_stop()   { case "$INIT_SYS" in systemd) $SUDO systemctl stop "$1" 2>/dev/null;; openrc) $SUDO rc-service "$1" stop 2>/dev/null;; sysvinit) $SUDO service "$1" stop 2>/dev/null;; *) return 1;; esac; }
svc_restart(){ case "$INIT_SYS" in systemd) $SUDO systemctl restart "$1" 2>/dev/null;; openrc) $SUDO rc-service "$1" restart 2>/dev/null;; sysvinit) $SUDO service "$1" restart 2>/dev/null;; *) return 1;; esac; }
svc_enable() { case "$INIT_SYS" in systemd) $SUDO systemctl enable "$1" 2>/dev/null;; openrc) $SUDO rc-update add "$1" default 2>/dev/null;; sysvinit) $SUDO update-rc.d "$1" defaults 2>/dev/null || chkconfig "$1" on 2>/dev/null;; *) return 1;; esac; }
svc_disable(){ case "$INIT_SYS" in systemd) $SUDO systemctl disable "$1" 2>/dev/null;; openrc) $SUDO rc-update del "$1" default 2>/dev/null;; sysvinit) $SUDO update-rc.d -f "$1" remove 2>/dev/null || chkconfig "$1" off 2>/dev/null;; *) return 1;; esac; }

# ============ 包管理抽象 ============
pkg_install() {
    case "$PKG_MGR" in
        apt) $SUDO apt-get update -qq && $SUDO apt-get install -y "$@" ;;
        dnf) $SUDO dnf install -y "$@" ;;
        yum) $SUDO yum install -y "$@" ;;
        zypper) $SUDO zypper --non-interactive install "$@" ;;
        pacman) $SUDO pacman -S --needed --noconfirm "$@" ;;
        apk) $SUDO apk add --no-cache "$@" ;;
        *) echo -e "${ERROR} 未知包管理器"; return 1 ;;
    esac
}
pkg_remove() {
    case "$PKG_MGR" in
        apt) $SUDO apt-get remove -y "$@" ;;
        dnf) $SUDO dnf remove -y "$@" ;;
        yum) $SUDO yum remove -y "$@" ;;
        zypper) $SUDO zypper --non-interactive remove "$@" ;;
        pacman) $SUDO pacman -R --noconfirm "$@" ;;
        apk) $SUDO apk del "$@" ;;
        *) return 1 ;;
    esac
}

pkg_purge() {
    case "$PKG_MGR" in
        apt) $SUDO apt-get purge -y "$@" ;;
        *) pkg_remove "$@" ;;
    esac
}

# 检测 EOL 系统（仅用于提示，不自动修改配置）
check_eol_system() {
    case "$OS_ID" in
        debian)
            case "$OS_VER" in
                8|9|10|11)
                    echo -e "\n${YELLOW}${BOLD}[提示] 检测到 Debian ${OS_VER}，该系统已停止官方支持。${RESET}"
                    echo -e "${YELLOW}apt 源可能已失效，导致无法正常安装软件。${RESET}"
                    echo -e "${YELLOW}如果安装失败，可将 /etc/apt/sources.list 改为 archive 源：${RESET}\n"
                    local codename=""
                    case "$OS_VER" in
                        8) codename="jessie" ;;
                        9) codename="stretch" ;;
                        10) codename="buster" ;;
                        11) codename="bullseye" ;;
                    esac
                    if [ -n "$codename" ]; then
                        echo -e "${CYAN}示例：${RESET}"
                        echo -e "  deb http://archive.debian.org/debian ${codename} main contrib non-free"
                        echo -e "  deb http://archive.debian.org/debian ${codename}-updates main contrib non-free"
                        echo -e "\n${CYAN}修改后执行：sudo apt update${RESET}"
                    fi
                    echo ""
                    ;;
            esac
            ;;
        ubuntu)
            case "$OS_VER" in
                14.04|16.04|18.04|20.04|21.04|21.10|22.10)
                    echo -e "\n${YELLOW}${BOLD}[提示] 检测到 Ubuntu ${OS_VER}，该系统已停止官方支持。${RESET}"
                    echo -e "${YELLOW}apt 源可能已失效，建议升级到 LTS 版本。${RESET}\n"
                    ;;
            esac
            ;;
    esac
}

# ============ SSH 配置管理 ============
declare -A SSHD_EXPECTED=()

get_sshd_bin() {
    command -v sshd 2>/dev/null || {
        [ -x /usr/sbin/sshd ] && echo /usr/sbin/sshd
    }
}

# 让 OpenSSH 自己解析 Include、默认值和 Match，而不是用 grep 猜测。
sshd_effective_dump() {
    local context_port="${1:-}" sshd_bin criteria remote_ip="" local_ip="" local_port="" remote_host=""
    sshd_bin="$(get_sshd_bin)"
    [ -n "$sshd_bin" ] || return 1

    if [ -n "${SSH_CONNECTION:-}" ]; then
        read -r remote_ip _ local_ip local_port <<< "$SSH_CONNECTION"
        [ -z "$context_port" ] || local_port="$context_port"
        # 无法可靠重放 sshd 的反向 DNS 结果；用远端地址，避免把服务端主机名误当 Match Host。
        remote_host="$remote_ip"
        criteria="user=${TARGET_USER},host=${remote_host},addr=${remote_ip},laddr=${local_ip},lport=${local_port}"
        $SUDO "$sshd_bin" -T -C "$criteria" 2>/dev/null
    elif [ -n "$context_port" ]; then
        $SUDO "$sshd_bin" -T -C "user=${TARGET_USER},host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=${context_port}" 2>/dev/null
    else
        $SUDO "$sshd_bin" -T -C "user=${TARGET_USER},host=localhost,addr=127.0.0.1" 2>/dev/null
    fi
}

# dump 失败时返回非零且不输出默认值；仅当 dump 成功但键缺失时才用 default_val。
get_sshd_config_val() {
    local key="${1,,}" default_val="$2" context_port="${3:-}" val="" dump
    dump="$(sshd_effective_dump "$context_port")" || return 1
    if [ "$key" = port ]; then
        val="$(awk 'tolower($1)=="port" {print $2}' <<< "$dump" | sort -nu | paste -sd, -)"
    else
        val="$(awk -v k="$key" 'tolower($1) == k {print $2; exit}' <<< "$dump")"
    fi
    if [ -n "$val" ]; then
        printf '%s\n' "$val"
    else
        printf '%s\n' "$default_val"
    fi
}

# 读取失败则打印中文错误并返回 1（供锁死检查等安全路径 fail-closed）。
require_sshd_val() {
    local key="$1" default_val="$2" context_port="${3:-}" val
    if ! val="$(get_sshd_config_val "$key" "$default_val" "$context_port")"; then
        printf '%b 无法读取 sshd 有效配置 (%s)，已停止以防误操作。\n' "$ERROR" "$key" >&2
        return 1
    fi
    printf '%s\n' "$val"
}

port_list_contains() {
    local list="$1" want="$2"
    [[ ",${list}," == *",${want},"* ]]
}

# sshd -T -C 无法可靠重放反向 DNS 主机名或路由域；高风险认证切换遇到这类 Match 时停止。
sshd_has_unverifiable_match() {
    local file
    for file in "$SSHD_MAIN" "$SSHD_CUSTOM" "$SSHD_LEGACY"; do
        if $SUDO test -f "$file" &&
           $SUDO grep -qiE '^[[:space:]]*Match[[:space:]].*[[:space:]](Host|RDomain)[[:space:]]' -- "$file" 2>/dev/null; then
            return 0
        fi
    done
    if $SUDO test -d "$SSHD_CONF_DIR"; then
        while IFS= read -r -d '' file; do
            if $SUDO grep -qiE '^[[:space:]]*Match[[:space:]].*[[:space:]](Host|RDomain)[[:space:]]' -- "$file" 2>/dev/null; then
                return 0
            fi
        done < <($SUDO find "$SSHD_CONF_DIR" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null)
    fi
    return 1
}

# 持久目录同时存放事务锁与完整快照，掉电或重启后仍可人工恢复。
SSHD_STATE_DIR="/var/lib/key-sh"
SSHD_LOCK_DIR="${SSHD_STATE_DIR}/sshd-transaction"

remove_sshd_snapshot() {
    local dir="$1"
    [[ "$dir" == "${SSHD_LOCK_DIR}/snapshot."* && "${dir#"${SSHD_LOCK_DIR}/"}" != */* ]] || return 1
    $SUDO rm -f -- "$dir/sshd_config" "$dir/custom.conf" "$dir/legacy.conf" \
        "$dir/main.exists" "$dir/main.absent" "$dir/custom.exists" "$dir/custom.absent" \
        "$dir/legacy.exists" "$dir/legacy.absent" "$dir/complete" || return 1
    $SUDO rmdir -- "$dir"
}

begin_sshd_transaction() {
    local dir='' name path backup ok=1
    if [ -n "$SSHD_TXN_DIR" ]; then
        $SUDO test -f "$SSHD_TXN_DIR/complete"; return
    fi
    if $SUDO test -L "$SSHD_STATE_DIR" ||
       { $SUDO test -e "$SSHD_STATE_DIR" && ! $SUDO test -d "$SSHD_STATE_DIR"; }; then
        printf '%b SSH 事务状态路径不安全：%s\n' "$ERROR" "$SSHD_STATE_DIR" >&2
        return 1
    fi
    if ! $SUDO install -d -o root -g root -m 700 -- "$SSHD_STATE_DIR" ||
       [ "$($SUDO stat -c '%u:%a' -- "$SSHD_STATE_DIR" 2>/dev/null)" != '0:700' ]; then
        printf '%b 无法创建安全的 SSH 事务状态目录：%s\n' "$ERROR" "$SSHD_STATE_DIR" >&2
        return 1
    fi
    if ! $SUDO mkdir -m 700 -- "$SSHD_LOCK_DIR" 2>/dev/null; then
        printf '%b SSH 配置锁已存在；请先确认其他实例或待恢复事务的状态：%s\n' "$ERROR" "$SSHD_LOCK_DIR" >&2
        return 1
    fi
    dir="$($SUDO mktemp -d "${SSHD_LOCK_DIR}/snapshot.XXXXXX")" || {
        $SUDO rmdir -- "$SSHD_LOCK_DIR"; return 1;
    }
    for name in main custom legacy; do
        case "$name" in
            main) path="$SSHD_MAIN"; backup=sshd_config ;;
            custom) path="$SSHD_CUSTOM"; backup=custom.conf ;;
            legacy) path="$SSHD_LEGACY"; backup=legacy.conf ;;
        esac
        if $SUDO test -L "$path"; then ok=0; break; fi
        if $SUDO test -e "$path"; then
            if ! $SUDO test -f "$path" || ! $SUDO cp -a -- "$path" "$dir/$backup" ||
               ! $SUDO touch -- "$dir/$name.exists"; then ok=0; break; fi
        else
            $SUDO touch -- "$dir/$name.absent" || { ok=0; break; }
        fi
    done
    if [ "$ok" -eq 0 ] || ! $SUDO touch -- "$dir/complete"; then
        remove_sshd_snapshot "$dir" && $SUDO rmdir -- "$SSHD_LOCK_DIR"
        printf '%b 无法完成 SSH 配置备份，尚未开始修改。\n' "$ERROR" >&2
        return 1
    fi
    SSHD_TXN_DIR="$dir"
    return 0
}

clear_sshd_transaction() {
    [ -n "$SSHD_TXN_DIR" ] || { SSHD_EXPECTED=(); return 0; }
    if ! remove_sshd_snapshot "$SSHD_TXN_DIR" || ! $SUDO rmdir -- "$SSHD_LOCK_DIR"; then
        printf '%b 无法清理事务目录，请检查 %s。\n' "$ERROR" "$SSHD_LOCK_DIR" >&2
        return 1
    fi
    SSHD_TXN_DIR=''; SSHD_EXPECTED=()
    return 0
}

rollback_sshd_transaction() {
    local quiet="${1:-0}" name path backup failed=0
    [ -n "$SSHD_TXN_DIR" ] || return 0
    if ! $SUDO test -f "$SSHD_TXN_DIR/complete"; then
        printf '%b 备份不完整，拒绝推测原文件状态；保留目录 %s。\n' "$ERROR" "$SSHD_TXN_DIR" >&2; return 1
    fi
    [ "$quiet" -eq 1 ] || printf '%b 正在恢复原 SSH 配置。\n' "$WARN"
    for name in main custom legacy; do
        case "$name" in
            main) path="$SSHD_MAIN"; backup=sshd_config ;;
            custom) path="$SSHD_CUSTOM"; backup=custom.conf ;;
            legacy) path="$SSHD_LEGACY"; backup=legacy.conf ;;
        esac
        if $SUDO test -f "$SSHD_TXN_DIR/$name.exists"; then
            if ! $SUDO test -f "$SSHD_TXN_DIR/$backup" || ! $SUDO test ! -L "$path" ||
               ! $SUDO cp -a -- "$SSHD_TXN_DIR/$backup" "$path"; then failed=1; fi
        elif $SUDO test -f "$SSHD_TXN_DIR/$name.absent"; then
            $SUDO rm -f -- "$path" || failed=1
        else failed=1; fi
    done
    if [ "$failed" -ne 0 ]; then
        printf '%b 回滚未完成，已保留备份与锁：%s。请从控制台检查。\n' "$ERROR" "$SSHD_TXN_DIR" >&2; return 1
    fi
    clear_sshd_transaction
}

# 探测 mv -T（GNU）；BusyBox 无 -T 时回退为对常规文件的 mv -f。
_MV_HAS_T=""
_mv_supports_T() {
    if [ -n "$_MV_HAS_T" ]; then
        [ "$_MV_HAS_T" = 1 ]; return
    fi
    # 用 --help 探测 GNU -T；BusyBox 通常无此选项
    if mv --help 2>&1 | grep -qE -- '(^|[[:space:]])-T([[:space:],]|$)'; then
        _MV_HAS_T=1; return 0
    fi
    _MV_HAS_T=0; return 1
}

atomic_replace_file() {
    local stage="$1" destination="$2" use_sudo="${3:-0}"
    local S=""
    [ "$use_sudo" = 1 ] && S="$SUDO"
    $S test ! -L "$destination" || return 1
    if _mv_supports_T; then
        $S mv -fT -- "$stage" "$destination"
        return
    fi
    # BusyBox：禁止把文件 mv 进目录；目标若是目录则拒绝
    if $S test -d "$destination"; then
        printf '%b 目标是目录，拒绝非原子替换: %s\n' "$ERROR" "$destination" >&2
        return 1
    fi
    $S mv -f -- "$stage" "$destination"
}

atomic_root_config() {
    local source="$1" destination="$2" stage
    $SUDO test ! -L "$destination" || return 1
    stage="$($SUDO mktemp "${destination}.key-sh.XXXXXX")" || return 1
    if ! $SUDO install -o root -g root -m 600 -- "$source" "$stage" ||
       ! atomic_replace_file "$stage" "$destination" 1; then
        $SUDO rm -f -- "$stage"; return 1
    fi
}

# 扫描 sshd_config.d 中非受管文件的活动 Port 行；发现则失败（不编辑那些 drop-in）。
sshd_dropins_have_active_port() {
    local f base
    $SUDO test -d "$SSHD_CONF_DIR" || return 1
    while IFS= read -r -d '' f; do
        base="$(basename -- "$f")"
        [ "$base" = "99-key.sh.conf" ] && continue
        if $SUDO grep -qiE '^[[:space:]]*Port[[:space:]]+' -- "$f" 2>/dev/null; then
            printf '%s\n' "$f"
            return 0
        fi
    done < <($SUDO find "$SSHD_CONF_DIR" -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null)
    return 1
}

# comment_ports=1 时在主文件 body 中注释活动 Port，并拒绝其他 drop-in 中的 Port。
ensure_sshd_managed_config() {
    local work comment_ports="${1:-0}" conflict
    begin_sshd_transaction || return 1
    $SUDO test -f "$SSHD_MAIN" || return 1
    $SUDO mkdir -p -- "$(dirname -- "$SSHD_CUSTOM")" || return 1
    if [ "$comment_ports" = 1 ]; then
        if conflict="$(sshd_dropins_have_active_port)"; then
            printf '%b 发现其他 sshd drop-in 含有活动 Port 指令：%s\n' "$ERROR" "$conflict" >&2
            printf '%b 请先手动移走或注释该 Port，然后再改端口（脚本不会改写用户 drop-in）。\n' "$ERROR" >&2
            return 1
        fi
    fi
    work="$(mktemp -d)" || return 1
    (
        trap 'rm -f -- "$work/main" "$work/body" "$work/body2" "$work/new" "$work/custom"; rmdir -- "$work"' EXIT
        if $SUDO test -f "$SSHD_LEGACY"; then
            if ! $SUDO test -f "$SSHD_CUSTOM"; then
                $SUDO cp -a -- "$SSHD_LEGACY" "$SSHD_CUSTOM" || return 1
            fi
            $SUDO rm -f -- "$SSHD_LEGACY" || return 1
        fi
        if $SUDO test -f "$SSHD_CUSTOM"; then
            $SUDO cat -- "$SSHD_CUSTOM" > "$work/custom" || return 1
        else printf '%s\n' '# Managed by key.sh.' > "$work/custom" || return 1; fi
        grep -qiE '^[[:space:]]*(Match|Include)[[:space:]]' "$work/custom" && {
            printf '%b 受管文件不能包含 Match 块或 Include 指令。\n' "$ERROR" >&2; return 1;
        }
        $SUDO cat -- "$SSHD_MAIN" > "$work/main" || return 1
        awk -v b="$SSHD_MANAGED_BEGIN" -v e="$SSHD_MANAGED_END" '
            $0==b {if(skip) exit 1; skip=1; next}
            $0==e {if(!skip) exit 1; skip=0; next}
            !skip {print}
            END {if(skip) exit 1}
        ' "$work/main" > "$work/body" || return 1
        if [ "$comment_ports" = 1 ]; then
            awk '
                {
                    line=$0
                    raw=line
                    sub(/^[[:space:]]*/, "", line)
                    if (line ~ /^Port[[:space:]]+/ || line ~ /^Port=/) {
                        print "# key.sh: " raw
                        next
                    }
                    print
                }
            ' "$work/body" > "$work/body2" || return 1
            mv -f -- "$work/body2" "$work/body" || return 1
        fi
        {
            printf '%s\nInclude %s\n%s\n' "$SSHD_MANAGED_BEGIN" "$SSHD_CUSTOM" "$SSHD_MANAGED_END"
            cat "$work/body"
        } > "$work/new" || return 1
        atomic_root_config "$work/custom" "$SSHD_CUSTOM" && atomic_root_config "$work/new" "$SSHD_MAIN"
    )
}





cleanup_pending_changes() {
    local failed=0
    if [ -n "$SSHD_TXN_DIR" ]; then
        rollback_sshd_transaction 1 || failed=1
    fi
    if declare -F rollback_port_fw_changes >/dev/null 2>&1; then
        rollback_port_fw_changes || failed=1
    fi
    return "$failed"
}
trap cleanup_pending_changes EXIT
trap 'cleanup_pending_changes; exit 130' INT
trap 'cleanup_pending_changes; exit 143' TERM

# 仅维护 key.sh 自己的文件与主文件中的受管 Include；改 Port 时会注释主文件 body 中的活动 Port。
# 不会改写用户 sshd_config.d drop-in，也不会碰 Match 块。
# 在主文件顶部放置受管 Include，确保标量参数遵循 OpenSSH 的 first-value-wins。


set_sshd_config() {
    local param="$1" value="$2" tmpf sourcef comment_ports=0 socket_unit=""
    [[ "$param" =~ ^[A-Za-z][A-Za-z0-9]+$ ]] || return 1
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
    if [ "${param,,}" = port ]; then
        comment_ports=1
        if socket_unit="$(ssh_socket_activation_unit)"; then
            printf '%b %s 正在活动或已启用，端口由 systemd socket 管理；已拒绝修改。\n' "$ERROR" "$socket_unit" >&2
            return 1
        fi
    fi
    if ! ensure_sshd_managed_config "$comment_ports"; then
        rollback_sshd_transaction
        return 1
    fi

    sourcef="$(mktemp)" || { rollback_sshd_transaction; return 1; }
    tmpf="$(mktemp)" || { rm -f "$sourcef"; rollback_sshd_transaction; return 1; }
    if ! $SUDO cat "$SSHD_CUSTOM" > "$sourcef"; then
        rm -f "$sourcef" "$tmpf"; rollback_sshd_transaction; return 1
    fi
    awk -v p="$param" -v v="$value" '
        {
            line=$0
            sub(/^[[:space:]]*/, "", line)
            split(line, fields, /[[:space:]=]+/)
            if (tolower(fields[1]) == tolower(p)) {
                if (!done) print p " " v
                done=1
                next
            }
            print
        }
        END {if (!done) print p " " v}
    ' "$sourcef" > "$tmpf" || {
        rm -f "$sourcef" "$tmpf"; rollback_sshd_transaction; return 1;
    }
    atomic_root_config "$tmpf" "$SSHD_CUSTOM" || {
        rm -f "$sourcef" "$tmpf"; rollback_sshd_transaction; return 1;
    }
    rm -f "$sourcef" "$tmpf"
    SSHD_EXPECTED["${param,,}"]="$value"
}

verify_sshd_expected_values() {
    local dump key effective_key actual expected bad_listeners
    dump="$(sshd_effective_dump "${SSHD_EXPECTED[port]:-}")" || return 1
    for key in "${!SSHD_EXPECTED[@]}"; do
        effective_key="$key"
        [ "$key" = "challengeresponseauthentication" ] && effective_key="kbdinteractiveauthentication"
        if [ "$key" = port ]; then
            actual="$(awk 'tolower($1)=="port" {print $2}' <<< "$dump" | sort -nu | paste -sd, -)"
        else
            actual="$(awk -v k="$effective_key" 'tolower($1) == k {print $2; exit}' <<< "$dump")"
        fi
        expected="${SSHD_EXPECTED[$key]}"
        if [ -z "$actual" ] || [ "${actual,,}" != "${expected,,}" ]; then
            echo -e "${ERROR} ${key} 预期为 ${expected}，但 sshd -T 显示为 ${actual:-未知}。"
            return 1
        fi
        if [ "$key" = port ]; then
            bad_listeners="$(awk -v p="$expected" '
                tolower($1)=="listenaddress" {
                    original=$2; address=$2; listen_port=""
                    if (address ~ /^\[/ && address ~ /\]:[0-9]+$/) {
                        sub(/^.*\]:/, "", address); listen_port=address
                    } else if (address ~ /:[0-9]+$/) {
                        sub(/^.*:/, "", address); listen_port=address
                    }
                    seen=1
                    if (listen_port != p) print original
                }
                END {if (!seen) print "<none>"}
            ' <<< "$dump")"
            if [ -n "$bad_listeners" ]; then
                printf '%b ListenAddress 未全部指向目标端口 %s：%s\n' "$ERROR" "$expected" "$(tr '\n' ' ' <<< "$bad_listeners")" >&2
                return 1
            fi
        fi
    done
}

restart_sshd() {
    local sshd_bin restart_ok=1 ssh_unit="" socket_active=0 socket_unit="" candidate=""
    local listen_rc recovery_ok=1 recovery_port="" remote_ip="" local_ip=""
    if [ -n "${SSH_CONNECTION:-}" ]; then
        read -r remote_ip _ local_ip recovery_port <<< "$SSH_CONNECTION"
    fi
    sshd_bin="$(get_sshd_bin)"
    echo -e "${INFO} 正在检测 SSH 配置语法和实际生效值..."
    if [ -z "$sshd_bin" ] || ! $SUDO "$sshd_bin" -t || ! verify_sshd_expected_values; then
        echo -e "${ERROR} SSH 配置检查失败，未重启服务。"
        rollback_sshd_transaction
        return 1
    fi

    echo -e "${INFO} 正在安全重载 SSH 服务..."
    if [ "$INIT_SYS" = "systemd" ]; then
        $SUDO systemctl daemon-reload &>/dev/null
        for candidate in ssh.socket sshd.socket; do
            if $SUDO systemctl is-active --quiet "$candidate" 2>/dev/null; then
                socket_active=1; socket_unit="$candidate"; break
            fi
        done
        if [ "$socket_active" -eq 1 ]; then
            if [ -n "${SSHD_EXPECTED[port]:-}" ]; then
                printf '%b 当前由 %s 管理端口，请在控制台配置并验证 socket 监听后再修改。已取消本次 SSH 配置更改。\n' "$ERROR" "$socket_unit" >&2
                rollback_sshd_transaction
                return 1
            fi
            ssh_unit="${socket_unit%.socket}"
            $SUDO systemctl reload-or-restart "${ssh_unit}.service" && restart_ok=0
        else
            if $SUDO systemctl list-unit-files 2>/dev/null | grep -q '^ssh.service'; then
                ssh_unit="ssh"
            elif $SUDO systemctl list-unit-files 2>/dev/null | grep -q '^sshd.service'; then
                ssh_unit="sshd"
            fi
            [ -n "$ssh_unit" ] && svc_restart "$ssh_unit" && restart_ok=0
        fi
    elif [ "$INIT_SYS" = "openrc" ]; then
        svc_restart sshd && restart_ok=0
    else
        svc_restart sshd 2>/dev/null && restart_ok=0
        [ "$restart_ok" -ne 0 ] && svc_restart ssh 2>/dev/null && restart_ok=0
    fi

    if [ "$restart_ok" -eq 0 ] && [ -n "${SSHD_EXPECTED[port]:-}" ]; then
        restart_ok=1
        for _ in {1..5}; do
            port_is_listening "${SSHD_EXPECTED[port]}"; listen_rc=$?
            if [ "$listen_rc" -eq 0 ]; then restart_ok=0; break; fi
            [ "$listen_rc" -eq 2 ] && break
            sleep 1
        done
        [ "$restart_ok" -eq 0 ] || printf '%b SSH 服务重载后没有监听目标端口，正在回滚。\n' "$ERROR" >&2
    fi

    if [ "$restart_ok" -eq 0 ]; then
        if ! clear_sshd_transaction; then
            # 服务与磁盘配置已经提交成功；此时再由 EXIT 恢复文件会造成运行态/磁盘态不一致。
            printf '%b SSH 配置已生效，但事务锁清理失败；请从控制台检查并删除 %s 后再运行。\n' "$WARN" "$SSHD_LOCK_DIR" >&2
            SSHD_TXN_DIR=''; SSHD_EXPECTED=()
        fi
        echo -e "${INFO} ${GREEN}SSH 服务重载成功！${RESET}"
        return 0
    fi

    echo -e "${ERROR} SSH 服务重载失败，正在自动回滚！"
    rollback_sshd_transaction || return 1
    if [ "$INIT_SYS" = "systemd" ]; then
        $SUDO systemctl daemon-reload &>/dev/null
        if [ "$socket_active" -eq 1 ]; then
            $SUDO systemctl reload-or-restart "${ssh_unit}.service" &>/dev/null && recovery_ok=0
        elif [ -n "$ssh_unit" ]; then
            svc_restart "$ssh_unit" && recovery_ok=0
        fi
    else
        svc_restart sshd 2>/dev/null && recovery_ok=0
        [ "$recovery_ok" -eq 0 ] || { svc_restart ssh 2>/dev/null && recovery_ok=0; }
    fi
    if [ -n "$recovery_port" ]; then
        port_is_listening "$recovery_port"; listen_rc=$?
        [ "$listen_rc" -eq 0 ] && recovery_ok=0 || recovery_ok=1
    fi
    if [ "$recovery_ok" -ne 0 ]; then
        printf '%b 原配置已恢复到磁盘，但无法确认 SSH 服务恢复监听；请保持当前会话并立即使用控制台检查。\n' "$ERROR" >&2
    fi
    return 1
}

# ============ 依赖安装 ============
check_dependencies() {
    local pkgs=()
    for dep in curl ssh-keygen awk flock; do
        command -v "$dep" &>/dev/null && continue
        case "$dep" in
            curl) pkgs+=("curl") ;;
            flock) case "$PKG_MGR" in apk) pkgs+=("util-linux");; *) pkgs+=("util-linux");; esac ;;
            ssh-keygen) case "$PKG_MGR" in apt) pkgs+=("openssh-client");; dnf|yum) pkgs+=("openssh-clients");; apk) pkgs+=("openssh-client");; pacman) pkgs+=("openssh");; zypper) pkgs+=("openssh");; esac ;;
            awk) command -v gawk &>/dev/null && continue; pkgs+=("gawk") ;;
        esac
    done
    if [ ${#pkgs[@]} -gt 0 ]; then
        echo -e "${WARN} 正在安装依赖: ${pkgs[*]}"
        pkg_install "${pkgs[@]}" || return 1
    fi
    for dep in curl ssh-keygen awk flock install mktemp stat; do
        command -v "$dep" >/dev/null 2>&1 || { printf '%b 缺少必要命令: %s\n' "$ERROR" "$dep" >&2; return 1; }
    done
    return 0
}

# 所有其他用户的密钥文件操作必须先降权；参数通过 stdin 传递，避免进入进程参数。
run_as_target() {
    if [ "$EUID" -eq "$TARGET_UID" ]; then "$@"
    elif [ "$EUID" -eq 0 ] && command -v runuser >/dev/null 2>&1; then
        runuser -u "$TARGET_USER" -- "$@"
    elif [ "$EUID" -eq 0 ] && command -v sudo >/dev/null 2>&1; then
        sudo -u "$TARGET_USER" -- "$@"
    else
        printf '%s\n' '无法安全切换目标用户，请用目标用户直接运行，或安装 runuser/sudo。' >&2
        return 1
    fi
}

target_key_worker() {
    local operation="$1" name; shift
    case "$operation" in
        init_ssh_dir|read_authorized_keys|append_key_with_meta|append_keys_with_meta_batch|remove_authorized_key|count_authorized_keys|generated_key_files) ;;
        *) return 1 ;;
    esac
    {
        printf 'set +x; umask 077\n'
        for name in TARGET_USER TARGET_UID TARGET_HOME SSH_DIR AUTHORIZED_KEYS INFO WARN ERROR GREEN RESET; do
            printf '%s=%q\n' "$name" "${!name}"
        done
        declare -f run_as_target target_key_worker safe_key_paths secure_key_path verify_home_path_security \
            verify_key_path_security init_ssh_dir read_authorized_keys \
            validate_public_key_content key_fingerprint _mv_supports_T commit_authorized_keys append_key_with_meta \
            append_keys_with_meta_batch \
            remove_authorized_key count_authorized_keys generated_key_files
        printf '%q ' "$operation" "$@"; printf '\n'
    } | run_as_target env -u BASH_ENV -u ENV bash --noprofile --norc -s
}

safe_key_paths() {
    local path="$SSH_DIR"
    while [ "$path" != / ] && [ "$path" != . ]; do
        if [ -L "$path" ] || { [ -e "$path" ] && [ ! -d "$path" ]; }; then
            printf '%b 密钥目录不能包含符号链接或非常规目录。\n' "$ERROR" >&2; return 1
        fi
        path="$(dirname -- "$path")"
    done
    if [ -L "$AUTHORIZED_KEYS" ] || { [ -e "$AUTHORIZED_KEYS" ] && [ ! -f "$AUTHORIZED_KEYS" ]; }; then
        printf '%b authorized_keys 必须是常规文件，不能是符号链接。\n' "$ERROR" >&2; return 1
    fi
}

# OpenSSH StrictModes 要求 home/.ssh/authorized_keys 只能由目标用户或 root 所有，
# 且不能被组或其他用户写入。只修正脚本创建的密钥文件权限，不静默修改 home。
secure_key_path() {
    local path="$1" kind="$2" label="$3" uid mode
    [ ! -L "$path" ] || { printf '%b %s 不能是符号链接：%s\n' "$ERROR" "$label" "$path" >&2; return 1; }
    case "$kind" in
        dir) [ -d "$path" ] ;;
        file) [ -f "$path" ] ;;
        *) return 1 ;;
    esac || { printf '%b %s 类型不正确：%s\n' "$ERROR" "$label" "$path" >&2; return 1; }
    uid="$(stat -c '%u' -- "$path" 2>/dev/null)" || return 1
    mode="$(stat -c '%a' -- "$path" 2>/dev/null)" || return 1
    [[ "$uid" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    if [ "$uid" -ne "$TARGET_UID" ] && [ "$uid" -ne 0 ]; then
        printf '%b %s 必须由目标用户或 root 所有：%s\n' "$ERROR" "$label" "$path" >&2
        return 1
    fi
    if (( (8#$mode & 8#22) != 0 )); then
        printf '%b %s 不能允许组或其他用户写入：%s (mode %s)\n' "$ERROR" "$label" "$path" "$mode" >&2
        return 1
    fi
}

verify_home_path_security() {
    secure_key_path "$TARGET_HOME" dir '目标用户家目录'
}

verify_key_path_security() {
    safe_key_paths || return 1
    verify_home_path_security || return 1
    secure_key_path "$SSH_DIR" dir '.ssh 目录' || return 1
    secure_key_path "$AUTHORIZED_KEYS" file 'authorized_keys' || return 1
}

init_ssh_dir() {
    if [ "$EUID" -ne "$TARGET_UID" ]; then target_key_worker init_ssh_dir; return; fi
    safe_key_paths || return 1
    verify_home_path_security || return 1
    ( umask 077; mkdir -p -- "$SSH_DIR" ) || return 1
    chmod 700 -- "$SSH_DIR" || return 1
    if [ ! -e "$AUTHORIZED_KEYS" ]; then
        ( umask 077; set -o noclobber; : > "$AUTHORIZED_KEYS" ) || return 1
    fi
    chmod 600 -- "$AUTHORIZED_KEYS" || return 1
    verify_key_path_security
}

read_authorized_keys() {
    if [ "$EUID" -ne "$TARGET_UID" ]; then target_key_worker read_authorized_keys; return; fi
    safe_key_paths || return 1
    [ -e "$AUTHORIZED_KEYS" ] || return 0
    cat -- "$AUTHORIZED_KEYS"
}

# 普通导入只接受裸公钥；保留已有 authorized_keys 的选项，不静默放宽限制。
validate_public_key_content() (
    set +x
    local content="$1" line file count=0 line_no=0
    local key_pattern='^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)[[:blank:]]+[A-Za-z0-9+/]+={0,2}([[:blank:]].*)?$'
    [ "${#content}" -le 1048576 ] || { printf '%b 公钥内容超过 1 MiB。\n' "$ERROR" >&2; return 1; }
    file="$(mktemp)" || return 1
    trap 'rm -f -- "$file"' EXIT
    while IFS= read -r line; do
        ((line_no+=1)); line="${line%$'\r'}"
        if LC_ALL=C grep -q '[[:cntrl:]]' <<< "${line//$'\t'/}"; then
            printf '%b 第 %s 行包含控制字符，已拒绝。\n' "$ERROR" "$line_no" >&2; return 1
        fi
        [[ "$line" =~ ^[[:blank:]]*$ || "$line" =~ ^[[:blank:]]*# ]] && continue
        if [ "${#line}" -gt 16384 ] || [[ ! "$line" =~ $key_pattern ]]; then
            printf '%b 第 %s 行不是支持的裸 SSH 公钥；不接受私钥或授权选项前缀。\n' "$ERROR" "$line_no" >&2; return 1
        fi
        printf '%s\n' "$line" > "$file" || return 1
        ssh-keygen -l -f "$file" >/dev/null 2>&1 || {
            printf '%b 第 %s 行公钥校验失败。\n' "$ERROR" "$line_no" >&2; return 1;
        }
        ((count+=1))
    done <<< "$content"
    [ "$count" -gt 0 ] || { printf '%b 来源中没有有效公钥。\n' "$ERROR" >&2; return 1; }
    return 0
)

key_fingerprint() {
    ssh-keygen -l -f "$1" 2>/dev/null | awk 'NR==1 {print $2}'
}

public_key_fingerprints() (
    local content="$1" file
    file="$(mktemp)" || return 1
    trap 'rm -f -- "$file"' EXIT
    printf '%s\n' "$content" > "$file" || return 1
    ssh-keygen -l -f "$file" 2>/dev/null | awk '$2 ~ /^SHA256:/ {print $2}' | LC_ALL=C sort -u
)

normalize_expected_fingerprints() {
    local raw="${1//,/ }" fp normalized=''
    local -a values=()
    read -r -a values <<< "$raw"
    [ "${#values[@]}" -gt 0 ] || return 1
    for fp in "${values[@]}"; do
        [[ "$fp" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || {
            printf '%b 指纹格式无效：%s\n' "$ERROR" "$fp" >&2; return 1;
        }
        normalized+="${fp}"$'\n'
    done
    printf '%s' "$normalized" | LC_ALL=C sort -u
}

verify_public_key_fingerprints() {
    local content="$1" expected="$2" actual normalized
    actual="$(public_key_fingerprints "$content")" || return 1
    [ -n "$actual" ] || { printf '%b 无法提取公钥 SHA256 指纹。\n' "$ERROR" >&2; return 1; }
    normalized="$(normalize_expected_fingerprints "$expected")" || return 1
    if [ "$actual" != "$normalized" ]; then
        printf '%b 远程公钥指纹与预期不一致，已拒绝导入。\n' "$ERROR" >&2
        printf '实际指纹：\n%s\n预期指纹：\n%s\n' "$actual" "$normalized" >&2
        return 1
    fi
}

confirm_remote_key_fingerprints() {
    local content="$1" label="$2" actual expected
    actual="$(public_key_fingerprints "$content")" || return 1
    [ -n "$actual" ] || return 1
    printf '%b %s 返回的公钥指纹：\n%s\n' "$INFO" "$label" "$actual"
    read -rp '请输入通过可信渠道获得的预期 SHA256 指纹（多个用空格分隔，留空取消）: ' expected || return 1
    [ -n "$expected" ] && verify_public_key_fingerprints "$content" "$expected"
}

# 调用方持有 .key-sh.lock；stage 与目标在同一目录，install 失败绝不提交。
commit_authorized_keys() (
    local candidate="$1" stage='' backup=''
    trap '[ -z "$stage" ] || rm -f -- "$stage"' EXIT
    safe_key_paths || return 1
    stage="$(mktemp "${SSH_DIR}/.authorized_keys.key-sh.XXXXXX")" || return 1
    install -m 600 -- "$candidate" "$stage" || return 1
    cmp -s -- "$candidate" "$stage" || return 1
    if [ -s "$AUTHORIZED_KEYS" ]; then
        backup="$(mktemp "${AUTHORIZED_KEYS}.bak.$(date +%Y%m%d-%H%M%S).XXXXXX")" || return 1
        if ! cp -- "$AUTHORIZED_KEYS" "$backup" || ! chmod 600 -- "$backup"; then
            rm -f -- "$backup"; return 1
        fi
    fi
    # 不允许 mv 将文件移入被意外替换成目录的 authorized_keys（兼容 BusyBox）。
    if _mv_supports_T; then
        mv -fT -- "$stage" "$AUTHORIZED_KEYS" || return 1
    else
        [ ! -d "$AUTHORIZED_KEYS" ] || return 1
        mv -f -- "$stage" "$AUTHORIZED_KEYS" || return 1
    fi
    stage=''
    [ -z "$backup" ] || printf '%b 原公钥备份: %s\n' "$INFO" "$backup"
    return 0
)

append_key_with_meta() {
    append_keys_with_meta_batch "${3:-0}" "$1" "$2"
}

# 参数为 overwrite content tag [content tag ...]；所有来源共用一把锁并只提交一次。
append_keys_with_meta_batch() {
    local overwrite="${1:-}"; shift || return 1
    local original_args=("$@") content tag
    [[ "$overwrite" == 0 || "$overwrite" == 1 ]] || return 1
    [ "$#" -ge 2 ] && [ $(( $# % 2 )) -eq 0 ] || return 1
    while [ "$#" -gt 0 ]; do
        validate_public_key_content "$1" || return 1
        shift 2
    done
    set -- "${original_args[@]}"
    if [ "$EUID" -ne "$TARGET_UID" ]; then target_key_worker append_keys_with_meta_batch "$overwrite" "$@"; return; fi
    (
        umask 077
        local work='' lock_fd line fp existing_fp existing type blob rest
        local count=0 source_count=0 found restricted
        init_ssh_dir || return 1
        [ ! -L "${SSH_DIR}/.key-sh.lock" ] || return 1
        exec {lock_fd}>>"${SSH_DIR}/.key-sh.lock" || return 1
        flock -x -w 15 "$lock_fd" || { printf '%b 其他密钥操作正在进行，请稍后重试。\n' "$ERROR" >&2; return 1; }
        work="$(mktemp -d "${SSH_DIR}/.key-sh.work.XXXXXX")" || return 1
        trap 'rm -f -- "$work/candidate" "$work/check" "$work/fingerprints"; rmdir -- "$work"' EXIT
        : > "$work/candidate"; : > "$work/fingerprints"
        if [ "$overwrite" -eq 0 ]; then
            cat -- "$AUTHORIZED_KEYS" > "$work/candidate" || return 1
            # awk 对有内容但没有末尾换行的最后一条记录补齐换行。
            awk '{print}' "$work/candidate" > "$work/check" || return 1
            cat "$work/check" > "$work/candidate" || return 1
        fi
        while [ "$#" -gt 0 ]; do
            content="$1"; tag="$2"; shift 2; ((source_count+=1))
            tag="${tag//$'\n'/ }"; tag="${tag//$'\r'/ }"
            LC_ALL=C grep -q '[[:cntrl:]]' <<< "$tag" && return 1
            while IFS= read -r line; do
                line="${line%$'\r'}"
                [[ "$line" =~ ^[[:blank:]]*$ || "$line" =~ ^[[:blank:]]*# ]] && continue
                printf '%s\n' "$line" > "$work/check" || return 1
                fp="$(key_fingerprint "$work/check")"; [ -n "$fp" ] || return 1
                found=0; restricted=0
                while IFS= read -r existing; do
                    [[ "$existing" =~ ^[[:blank:]]*$ || "$existing" =~ ^[[:blank:]]*# ]] && continue
                    printf '%s\n' "$existing" > "$work/check" || return 1
                    existing_fp="$(key_fingerprint "$work/check")"
                    if [ "$existing_fp" = "$fp" ]; then
                        found=1
                        read -r type blob rest <<< "$line"
                        [[ "$existing" == "$type $blob" || "$existing" == "$type $blob "* || "$existing" == "$type"$'\t'"$blob"* ]] || restricted=1
                    fi
                done < "$work/candidate"
                if [ "$restricted" -eq 1 ]; then
                    printf '%b 相同指纹已有带选项的授权记录，请手动核对；未更改限制。\n' "$ERROR" >&2; return 1
                fi
                if [ "$found" -eq 1 ]; then printf '%b 已跳过重复公钥。\n' "$WARN"; continue; fi
                printf '%s [%s|%s]\n' "$line" "$(date '+%Y-%m-%d %H:%M:%S')" "$tag" >> "$work/candidate" || return 1
                printf '%s\n' "$fp" >> "$work/fingerprints" || return 1
                ((count+=1))
            done <<< "$content"
        done
        [ "$count" -gt 0 ] || return 0
        ssh-keygen -l -f "$work/candidate" > "$work/check" 2>/dev/null || return 1
        while IFS= read -r fp; do
            awk -v fp="$fp" '$2 == fp {found=1} END {exit !found}' "$work/check" || return 1
        done < "$work/fingerprints"
        commit_authorized_keys "$work/candidate" || return 1
        printf '%b 已一次性写入 %s 把公钥（%s 个来源）。\n' "$INFO" "$count" "$source_count"
        return 0
    )
}

remove_authorized_key() {
    if [ "$EUID" -ne "$TARGET_UID" ]; then target_key_worker remove_authorized_key "$@"; return; fi
    (
        umask 077
        local action="$1" expected="$2" actual work='' lock_fd
        init_ssh_dir || return 1
        [ ! -L "${SSH_DIR}/.key-sh.lock" ] || return 1
        exec {lock_fd}>>"${SSH_DIR}/.key-sh.lock" || return 1
        flock -x -w 15 "$lock_fd" || return 1
        actual="$(read_authorized_keys)" || return 1
        [ "$actual" = "$expected" ] || { printf '%b 公钥文件已被其他操作更改，请刷新后重试。\n' "$ERROR" >&2; return 1; }
        work="$(mktemp -d "${SSH_DIR}/.key-sh.work.XXXXXX")" || return 1
        trap 'rm -f -- "$work/candidate"; rmdir -- "$work"' EXIT
        if [ "$action" = all ]; then : > "$work/candidate"
        elif [[ "$action" =~ ^[1-9][0-9]*$ ]]; then
            awk -v n="$action" 'NR != n {print}' "$AUTHORIZED_KEYS" > "$work/candidate" || return 1
        else return 1; fi
        commit_authorized_keys "$work/candidate"
    )
}

count_authorized_keys() {
    if [ "$EUID" -ne "$TARGET_UID" ]; then target_key_worker count_authorized_keys; return; fi
    safe_key_paths || { echo 0; return 1; }
    if [ -f "$AUTHORIZED_KEYS" ]; then
        ssh-keygen -l -f "$AUTHORIZED_KEYS" 2>/dev/null | awk 'END {print NR+0}'
    else echo 0; fi
}

authorized_key_line_is_valid() (
    local line="$1" file
    file="$(mktemp)" || return 1
    trap 'rm -f -- "$file"' EXIT
    printf '%s\n' "$line" > "$file" || return 1
    ssh-keygen -l -f "$file" >/dev/null 2>&1
)

# 在独立的私有目录生成密钥，所有读取和删除也在目标用户权限下完成。
generated_key_files() {
    if [ "$EUID" -ne "$TARGET_UID" ]; then target_key_worker generated_key_files "$@"; return; fi
    local action="$1" dir="${2:-}"
    init_ssh_dir || return 1
    if [ "$action" = create ]; then mktemp -d "${SSH_DIR}/key-sh-generated.XXXXXX"; return; fi
    [[ "$dir" == "${SSH_DIR}/key-sh-generated."* && "${dir#"${SSH_DIR}/"}" != */* ]] || return 1
    [ -d "$dir" ] && [ ! -L "$dir" ] || return 1
    [ ! -L "$dir/PrivateKey" ] && [ ! -L "$dir/PrivateKey.pub" ] || return 1
    case "$action" in
        read) cat -- "$dir/PrivateKey.pub" ;;
        delete) rm -f -- "$dir/PrivateKey" "$dir/PrivateKey.pub" && rmdir -- "$dir" ;;
        *) return 1 ;;
    esac
}

fetch_public_keys() (
    set +x
    local url="$1" tmp=''
    [[ "$url" == https://* ]] && ! LC_ALL=C grep -q '[[:cntrl:][:space:]]' <<< "$url" || {
        printf '%b 公钥地址必须是有效的 HTTPS URL。\n' "$ERROR" >&2; return 1;
    }
    # 普通公钥无需令牌；拒绝用户名密码、查询参数和 fragment，减少日志泄露。
    [[ "${url#https://}" != *@* && "$url" != *\?* && "$url" != *\#* ]] || {
        printf '%b 请使用不含认证信息、查询参数或片段的公钥地址。\n' "$ERROR" >&2; return 1;
    }
    tmp="$(mktemp)" || return 1
    trap 'rm -f -- "$tmp"' EXIT
    if ! curl -q --globoff --proto '=https' --proto-redir '=https' --connect-timeout 10 \
        --max-time 30 --max-redirs 3 --max-filesize 1048576 -fsSL -- "$url" > "$tmp" 2>/dev/null; then
        printf '%b 下载公钥失败或超出限制，已丢弃结果。\n' "$ERROR" >&2; return 1
    fi
    [ "$(wc -c < "$tmp")" -le 1048576 ] || return 1
    validate_public_key_content "$(cat "$tmp")" || return 1
    cat -- "$tmp"
)

has_valid_authorized_key() {
    [ "$(count_authorized_keys)" -gt 0 ]
}

# ============ Fail2Ban ============
# 用 awk 精确解析 INI 块，避免 sed 范围瞬间闭合的 bug
get_f2b_conf() {
    local key=$1 content
    [ -f "$JAIL_CONF" ] || return
    content="$($SUDO cat -- "$JAIL_CONF")" || return 1
    awk -v t="$TARGET_JAIL" -v k="$key" '
        BEGIN { in_block=0; result="" }
        $0 ~ "^[[:space:]]*\\[" t "\\][[:space:]]*$" { in_block=1; next }
        /^[[:space:]]*\[/ { in_block=0 }
        in_block {
            check=$0; sub(/^[[:space:]]*/, "", check)
            split(check, parts, /[[:space:]]*=/)
            if(parts[1] != k) next
            value=$0
            sub(/^[[:space:]]*[^=]+=[[:space:]]*/, "", value)
            sub(/[[:space:]]+$/, "", value)
            result = value
        }
        END { if (result != "") print result }
    ' <<< "$content"
}


set_f2b_conf() {
    local key="$1" val="$2" work
    [[ "$key" =~ ^[a-zA-Z][a-zA-Z0-9.]*$ ]] || return 1
    ! LC_ALL=C grep -q '[[:cntrl:]]' <<< "$val" || return 1
    [[ "$val" != *$'\n'* && "$val" != *$'\r'* ]] || return 1
    work="$(mktemp -d)" || return 1
    (
        local existed=0 retain_work=0
        trap 'if [ "$retain_work" -eq 0 ]; then rm -f -- "$work/old" "$work/new"; rmdir -- "$work"; fi' EXIT
        if $SUDO test -e "$JAIL_CONF"; then
            existed=1
            $SUDO test ! -L "$JAIL_CONF" && $SUDO cat -- "$JAIL_CONF" > "$work/old" || return 1
        else : > "$work/old"; fi
        awk -v t="$TARGET_JAIL" -v k="$key" -v v="$val" '
            function flush() {if(inblock && !done) {print k " = " v; done=1}}
            /^[[:space:]]*\[/ {
                flush(); block=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", block)
                inblock=(block==t); if(inblock) found=1
            }
            {line=$0; sub(/^[[:space:]]*/, "", line); split(line,a,/[[:space:]]*=/)
             if(inblock && a[1]==k) {if(!done) print k " = " v; done=1; next}
             print}
            END {flush(); if(!found) print "\n[" t "]\n" k " = " v}
        ' "$work/old" > "$work/new" || return 1
        atomic_root_config "$work/new" "$JAIL_CONF" || return 1
        if command -v fail2ban-client >/dev/null 2>&1 && ! $SUDO fail2ban-client -t >/dev/null 2>&1; then
            if [ "$existed" -eq 1 ]; then
                atomic_root_config "$work/old" "$JAIL_CONF" || retain_work=1
            else
                $SUDO rm -f -- "$JAIL_CONF" || retain_work=1
            fi
            printf '%b Fail2Ban 不接受新配置，已尝试恢复原文件。\n' "$ERROR" >&2
            [ "$retain_work" -eq 0 ] || printf '%b 恢复失败，备份保留于 %s/old。\n' "$ERROR" "$work" >&2
            return 1
        fi
        return 0
    )
}

f2b_jail_is_active() {
    command -v fail2ban-client >/dev/null 2>&1 &&
        $SUDO fail2ban-client ping >/dev/null 2>&1 &&
        $SUDO fail2ban-client status "$TARGET_JAIL" >/dev/null 2>&1
}

restart_f2b() {
    echo -e "${INFO} 正在重载 Fail2Ban 配置..."
    $SUDO fail2ban-client -t >/dev/null 2>&1 || { printf '%b Fail2Ban 配置检查失败，未重启。\n' "$ERROR" >&2; return 1; }
    svc_restart fail2ban || return 1
    for _ in {1..5}; do
        if f2b_jail_is_active; then
            echo -e "${INFO} ${GREEN}成功！配置已生效。${RESET}"; return 0
        fi; sleep 1
    done
    echo -e "${ERROR} Fail2Ban 重启超时或失败。"
    echo -e "${YELLOW}请手动运行 'journalctl -u fail2ban -n 50' 排查错误。${RESET}"
    return 1
}

sync_f2b_port_after_ssh_change() {
    local new_port="$1" work retain_work=0
    if ! $SUDO test -f "$JAIL_CONF" ||
       ! $SUDO grep -qE "^[[:space:]]*\\[${TARGET_JAIL}\\][[:space:]]*$" "$JAIL_CONF"; then
        if f2b_jail_is_active; then
            printf '%b sshd jail 来自其他配置文件，无法保证其端口同步为 %s。\n' "$ERROR" "$new_port" >&2
            return 1
        fi
        return 0
    fi
    work="$(mktemp -d)" || return 1
    (
        trap 'if [ "$retain_work" -eq 0 ]; then rm -f -- "$work/old"; rmdir -- "$work"; fi' EXIT
        $SUDO test ! -L "$JAIL_CONF" && $SUDO cat -- "$JAIL_CONF" > "$work/old" || return 1
        set_f2b_conf port "$new_port" || return 1
        if $SUDO fail2ban-client ping >/dev/null 2>&1; then
            if restart_f2b; then return 0; fi
            printf '%b 新 Fail2Ban 端口未能生效，正在恢复原 jail.local。\n' "$ERROR" >&2
            if ! atomic_root_config "$work/old" "$JAIL_CONF"; then
                retain_work=1
                printf '%b Fail2Ban 配置恢复失败，备份保留于 %s/old。\n' "$ERROR" "$work" >&2
                return 1
            fi
            restart_f2b || printf '%b 原 Fail2Ban 配置已恢复，但服务仍未正常运行。\n' "$ERROR" >&2
            return 1
        fi
        printf '%b Fail2Ban 当前未运行；已校验并保存新端口 %s，将在下次启动时使用。\n' "$WARN" "$new_port" >&2
        return 0
    )
}

# Fail2Ban 已安装时，只允许脚本修改自己能够原子备份和验证的 [sshd] 配置。
# 端口变更前先检查，避免 SSH 已换端口后才发现 jail 无法同步。
f2b_port_sync_preflight() {
    command -v fail2ban-client >/dev/null 2>&1 || return 0
    if ! $SUDO test -f "$JAIL_CONF" || $SUDO test -L "$JAIL_CONF" ||
       ! $SUDO grep -qE "^[[:space:]]*\\[${TARGET_JAIL}\\][[:space:]]*$" "$JAIL_CONF"; then
        printf '%b 已安装 Fail2Ban，但脚本无法安全管理 %s 中的 [sshd] jail。\n' "$ERROR" "$JAIL_CONF" >&2
        printf '%b 请先把 sshd jail 迁入该文件并确认没有后续覆盖，再修改 SSH 端口。\n' "$ERROR" >&2
        return 1
    fi
}

get_fail2ban_status() {
    if f2b_jail_is_active; then
        local count
        count=$($SUDO fail2ban-client status "$TARGET_JAIL" 2>/dev/null | grep -i "Currently banned" | awk '{print $NF}')
        echo -e "${GREEN}防护中 (已封禁${count:-0} IP)${RESET}"
    elif command -v fail2ban-client >/dev/null 2>&1 && $SUDO fail2ban-client ping >/dev/null 2>&1; then
        echo -e "${YELLOW}服务运行 / sshd jail 未启用${RESET}"
    elif command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "${YELLOW}已安装 / 已停止${RESET}"
    else
        echo -e "${YELLOW}未安装${RESET}"
    fi
}

fmt_f2b_unit() {
    local val=$1 type=$2
    if [[ "$val" =~ ^[0-9]+$ ]]; then
        [ "$type" == "time" ] && echo "${val}秒" || { [ "$type" == "factor" ] && echo "${val}倍" || echo "$val"; }
    else echo "$val"; fi
}

validate_time() { [[ "$1" =~ ^[0-9]+[smhdw]?$ ]]; }
validate_int() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }
validate_factor() { [[ "$1" =~ ^([0-9]+)(\.[0-9]+)?$ ]] && awk -v n="$1" 'BEGIN {exit !(n>0)}'; }

# 校验 IP/CIDR（与白名单路径一致）
validate_ip_or_cidr() {
    local ip="$1"
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -c 'import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$ip" >/dev/null 2>&1
}

f2b_session_client_ip() {
    local ip=""
    if [ -n "${SSH_CLIENT:-}" ]; then
        ip="$(awk '{print $1}' <<< "$SSH_CLIENT")"
    elif [ -n "${SSH_CONNECTION:-}" ]; then
        ip="$(awk '{print $1}' <<< "$SSH_CONNECTION")"
    fi
    if [ -n "$ip" ] && validate_ip_or_cidr "$ip"; then
        printf '%s\n' "$ip"
    fi
}

# systemd 环境默认走 journal，不写死 logpath（避免 WARN）
generate_default_jail_conf() {
    local backend="auto" ssh_ports ignoreip client_ip
    if ! ssh_ports="$(get_sshd_config_val "Port" "22")"; then
        printf '%b 无法读取 SSH Port，拒绝生成 Fail2Ban jail（避免写入错误端口）。\n' "$ERROR" >&2
        return 1
    fi
    [[ "$ssh_ports" =~ ^[0-9]+(,[0-9]+)*$ ]] || return 1
    local logpath_line="logpath = ${SSH_LOG}"
    if [ "$INIT_SYS" = "systemd" ]; then
        backend="systemd"
        logpath_line=""
    fi
    local ssh_filter="sshd"
    [ "$OS_ID" = "alpine" ] && ssh_filter="alpine-sshd"
    local banaction="iptables-multiport"
    if ! command -v iptables &>/dev/null && command -v nft &>/dev/null; then
        banaction="nftables-multiport"
    fi
    ignoreip="127.0.0.1/8 ::1"
    if [ "${KEY_SH_F2B_TRUST_CURRENT_IP:-0}" = 1 ]; then
        client_ip="$(f2b_session_client_ip || true)"
        if [ -n "$client_ip" ]; then
            ignoreip="${ignoreip} ${client_ip}"
            printf '%b 已按明确设置把当前 SSH 客户端 IP 永久加入 Fail2Ban 白名单：%s\n' "$WARN" "$client_ip" >&2
        fi
    fi
    cat <<EOF2
[${TARGET_JAIL}]
enabled = true
port = ${ssh_ports}
filter = ${ssh_filter}
backend = ${backend}
${logpath_line}
maxretry = 5
bantime = 600
findtime = 3600
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 7d
banaction = ${banaction}
ignoreip = ${ignoreip}
EOF2
}

# 原子写入 jail.local（首次创建）；校验失败则恢复/删除。
write_f2b_jail_from_generator() {
    local work existed=0 retain_work=0
    work="$(mktemp -d)" || return 1
    (
        trap 'if [ "$retain_work" -eq 0 ]; then rm -f -- "$work/old" "$work/new"; rmdir -- "$work"; fi' EXIT
        if $SUDO test -e "$JAIL_CONF"; then
            existed=1
            $SUDO test ! -L "$JAIL_CONF" && $SUDO cat -- "$JAIL_CONF" > "$work/old" || return 1
        fi
        generate_default_jail_conf > "$work/new" || return 1
        atomic_root_config "$work/new" "$JAIL_CONF" || return 1
        if command -v fail2ban-client >/dev/null 2>&1 && ! $SUDO fail2ban-client -t >/dev/null 2>&1; then
            if [ "$existed" -eq 1 ]; then
                atomic_root_config "$work/old" "$JAIL_CONF" || retain_work=1
            else
                $SUDO rm -f -- "$JAIL_CONF" || retain_work=1
            fi
            printf '%b Fail2Ban 不接受新配置，已尝试恢复。\n' "$ERROR" >&2
            [ "$retain_work" -eq 0 ] || printf '%b 恢复失败，备份保留于 %s/old。\n' "$ERROR" "$work" >&2
            return 1
        fi
        return 0
    )
}

check_f2b_install() {
    local newly_installed=0 config_changed=0 install_confirm work
    local -a f2b_pkgs=()
    hash -r 2>/dev/null
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "${WARN} 未检测到 Fail2Ban 服务。"
        read -rp "是否立即安装 Fail2Ban？(y/N): " install_confirm
        [[ "$install_confirm" =~ ^[Yy]$ ]] || { echo -e "${WARN} 已取消安装。"; return 1; }
        case "$PKG_MGR" in
            apt) f2b_pkgs=(fail2ban python3-systemd rsyslog) ;;
            dnf|yum|zypper) f2b_pkgs=(fail2ban rsyslog) ;;
            pacman|apk) f2b_pkgs=(fail2ban) ;;
            *) printf '%b 无法为未知包管理器安装 Fail2Ban。\n' "$ERROR" >&2; return 1 ;;
        esac
        echo -e "${INFO} 正在安装 Fail2Ban 及相关依赖..."
        if ! pkg_install "${f2b_pkgs[@]}"; then
            printf '%b Fail2Ban 软件包安装失败。\n' "$ERROR" >&2; check_eol_system; return 1
        fi
        hash -r 2>/dev/null
        command -v fail2ban-client >/dev/null 2>&1 || { printf '%b 安装后仍找不到 fail2ban-client。\n' "$ERROR" >&2; return 1; }
        newly_installed=1
    fi

    [ -d /etc/fail2ban ] || { printf '%b /etc/fail2ban 目录不存在，安装不完整。\n' "$ERROR" >&2; return 1; }
    if [ "$INIT_SYS" != systemd ] && [ ! -f "$SSH_LOG" ]; then
        $SUDO touch "$SSH_LOG" || return 1
        svc_enable rsyslog 2>/dev/null || true; svc_start rsyslog 2>/dev/null || true
    fi

    if [ ! -f "$JAIL_CONF" ]; then
        write_f2b_jail_from_generator || return 1
        config_changed=1
    elif ! $SUDO grep -qE "^[[:space:]]*\\[${TARGET_JAIL}\\][[:space:]]*$" "$JAIL_CONF"; then
        work="$(mktemp -d)" || return 1
        (
            trap 'rm -f -- "$work/old" "$work/new" "$work/frag"; rmdir -- "$work"' EXIT
            $SUDO test ! -L "$JAIL_CONF" && $SUDO cat -- "$JAIL_CONF" > "$work/old" || return 1
            generate_default_jail_conf > "$work/frag" || return 1
            [ -s "$work/frag" ] || return 1
            { cat "$work/old"; printf '\n'; cat "$work/frag"; } > "$work/new" || return 1
            atomic_root_config "$work/new" "$JAIL_CONF" || return 1
            if ! $SUDO fail2ban-client -t >/dev/null 2>&1; then
                atomic_root_config "$work/old" "$JAIL_CONF" || true
                printf '%b 追加 sshd jail 后校验失败，已恢复。\n' "$ERROR" >&2
                return 1
            fi
        ) || return 1
        config_changed=1
    fi
    $SUDO fail2ban-client -t >/dev/null 2>&1 || { printf '%b Fail2Ban 配置校验失败。\n' "$ERROR" >&2; return 1; }

    if [ "$newly_installed" -eq 1 ]; then
        [ "$INIT_SYS" = systemd ] && $SUDO systemctl unmask fail2ban &>/dev/null || true
        svc_enable fail2ban || { printf '%b 无法启用 Fail2Ban 开机启动。\n' "$ERROR" >&2; return 1; }
        svc_start fail2ban || { printf '%b 无法启动 Fail2Ban。\n' "$ERROR" >&2; return 1; }
        for _ in {1..5}; do f2b_jail_is_active && { echo -e "${INFO} ${GREEN}Fail2Ban 安装并启动完成！${RESET}"; return 0; }; sleep 1; done
        printf '%b Fail2Ban 已安装，但 sshd jail 未成功启动。\n' "$ERROR" >&2; return 1
    fi
    if [ "$config_changed" -eq 1 ] && $SUDO fail2ban-client ping >/dev/null 2>&1; then
        restart_f2b || return 1
    fi
    return 0
}

uninstall_f2b() {
    echo -e "\n${RED}${BOLD}警告：即将卸载 Fail2Ban 及其配置！${RESET}"
    read -rp "确认卸载吗？(y/N): " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { echo -e "${INFO} 已取消卸载。"; read -rp "按回车键继续..."; return; }
    read -rp "是否同时删除配置目录 /etc/fail2ban ？(y/N): " del_conf
    svc_stop fail2ban || true; svc_disable fail2ban || true
    if [[ "$del_conf" =~ ^[Yy]$ ]]; then
        pkg_purge fail2ban || { printf '%b Fail2Ban 软件包卸载失败。\n' "$ERROR" >&2; return 1; }
        if $SUDO test -e /etc/fail2ban || $SUDO test -L /etc/fail2ban; then
            $SUDO rm -rf -- /etc/fail2ban || { printf '%b 删除 /etc/fail2ban 失败。\n' "$ERROR" >&2; return 1; }
        fi
        echo -e "${INFO} 已删除 /etc/fail2ban"
    else
        pkg_remove fail2ban || { printf '%b Fail2Ban 软件包卸载失败，配置未主动删除。\n' "$ERROR" >&2; return 1; }
    fi
    echo -e "${INFO} ${GREEN}Fail2Ban 卸载完成。${RESET}"; read -rp "按回车键继续..."
}

change_f2b_param() {
    local name=$1 key=$2 type=$3
    local current; current=$(get_f2b_conf "$key")
    echo -e "\n${INFO} 正在修改: ${CYAN}${name}${RESET}"
    echo -e "当前值: ${GREEN}$(fmt_f2b_unit "$current" "$type")${RESET}"
    [ "$type" == "time" ] && echo -e "${GRAY}(支持后缀: s=秒, m=分, h=小时, d=天)${RESET}"
    while true; do
        read -rp "请输入新值 (留空取消): " new_val
        [ -z "$new_val" ] && return
        if [ "$type" == "time" ] && validate_time "$new_val"; then break; fi
        if [ "$type" == "int" ] && validate_int "$new_val"; then break; fi
        if [ "$type" == "factor" ] && validate_factor "$new_val"; then break; fi
        echo -e "${ERROR} 格式错误，请重试。"
    done
    set_f2b_conf "$key" "$new_val" && restart_f2b
}

toggle_f2b_service() {
    echo -e "\n${CYAN}------------------- 服务开关 -------------------${RESET}"
    if f2b_jail_is_active; then
        read -rp "是否停止并禁用 Fail2Ban? (y/N): " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] && { svc_stop fail2ban; svc_disable fail2ban; echo -e "${WARN} 服务已停止。${RESET}"; }
    elif $SUDO fail2ban-client ping >/dev/null 2>&1; then
        read -rp "服务正在运行但 sshd jail 未启用；是否重启并应用配置？(y/N): " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] && restart_f2b
    else
        read -rp "是否启用并启动 Fail2Ban? (y/N): " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            svc_enable fail2ban; svc_start fail2ban
            for _ in {1..5}; do
                if f2b_jail_is_active; then echo -e "${INFO} ${GREEN}服务及 sshd jail 已成功启动。${RESET}"; read -rp "按回车键继续..."; return; fi; sleep 1
            done
            echo -e "${ERROR} 启动失败或超时。"
        fi
    fi
    read -rp "按回车键继续..."
}

unban_f2b_ip() {
    echo -e "\n${CYAN}------------------ 手动解封 IP ------------------${RESET}"
    local banned_list
    banned_list=$($SUDO fail2ban-client status "$TARGET_JAIL" 2>/dev/null | grep "Banned IP list" | awk -F':' '{print $2}' | sed 's/^[ \t]*//')
    [ -z "$banned_list" ] && banned_list="无"
    echo -e "当前被封禁列表: ${YELLOW}${banned_list}${RESET}"
    read -rp "输入要解封的 IP (留空取消): " target_ip; [ -z "$target_ip" ] && return
    if ! validate_ip_or_cidr "$target_ip"; then
        printf '%b IP/CIDR 无效，或缺少 Python 3 地址校验器。\n' "$ERROR" >&2
        read -rp "按回车键继续..."; return 1
    fi
    if $SUDO fail2ban-client set "$TARGET_JAIL" unbanip "$target_ip"; then
        echo -e "${INFO} ${GREEN}解封成功: $target_ip${RESET}"
    else
        echo -e "${ERROR} 操作失败。"
    fi
    read -rp "按回车键继续..."
}

get_f2b_effective_ignoreip() {
    local local_list raw parsed
    local_list="$(get_f2b_conf ignoreip)" || return 1
    if f2b_jail_is_active; then
        raw="$($SUDO fail2ban-client get "$TARGET_JAIL" ignoreip 2>/dev/null)" || return 1
        parsed="$(python3 - "$raw" <<'PY'
import ipaddress
import re
import sys

seen = set()
for token in re.split(r"[\s,\[\](){}'\"|`]+", sys.argv[1]):
    token = token.strip()
    if not token or ('.' not in token and ':' not in token):
        continue
    try:
        value = str(ipaddress.ip_network(token, strict=False))
    except ValueError:
        continue
    if value not in seen:
        seen.add(value)
        print(value)
PY
)" || return 1
        tr '\n' ' ' <<< "$parsed" | sed 's/[[:space:]]*$//'
        return 0
    fi
    if [ -n "$local_list" ]; then
        printf '%s\n' "$local_list"; return 0
    fi
    printf '%b sshd jail 未运行且本地 [sshd] 没有 ignoreip；无法安全合并继承的白名单。\n' "$ERROR" >&2
    return 1
}

add_f2b_whitelist() {
    echo -e "\n${CYAN}------------------ 白名单管理 ------------------${RESET}"
    local current_list
    current_list="$(get_f2b_effective_ignoreip)" || return 1
    echo -e "当前有效白名单: ${YELLOW}${current_list:-无}${RESET}"
    local current_ip; current_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
    read -rp "输入要放行的 IP (回车默认当前连接 IP: ${current_ip:-无}): " input_ip
    [ -z "$input_ip" ] && input_ip="$current_ip"
    [ -z "$input_ip" ] && echo -e "${ERROR} 无法获取 IP。" && return
    if ! validate_ip_or_cidr "$input_ip"; then
        printf '%b IP/CIDR 无效，或缺少 Python 3 地址校验器。\n' "$ERROR" >&2; return 1
    fi
    if printf '%s\n' "$current_list" | tr ' ' '\n' | grep -Fxq -- "$input_ip"; then
        echo -e "${WARN} 该 IP 已在白名单中。"
    else
        if [ -z "$current_list" ]; then set_f2b_conf "ignoreip" "$input_ip"
        else set_f2b_conf "ignoreip" "$current_list $input_ip"; fi
        restart_f2b
    fi
    read -rp "按回车键继续..."
}

view_f2b_logs() {
    clear
    echo -e "${CYAN}============================================================${RESET}"
    echo -e "${BOLD}${PURPLE}                 Fail2Ban 审计日志 (最近 20 条)${RESET}"
    echo -e "${CYAN}============================================================${RESET}"
    if ! $SUDO test -f "$LOG_FILE"; then
        echo -e "${WARN} 日志文件不存在: $LOG_FILE"
    else
        local out
        out=$($SUDO grep -E '(Ban|Unban)' "$LOG_FILE" 2>/dev/null | tail -n 20)
        if [ -z "$out" ]; then
            echo -e "${WARN} 暂无封禁/解封记录${RESET}"
        else
            # 先占位保护 Unban，再染 Ban，最后还原 Unban，避免子串误染
            echo "$out" | awk '{
                gsub(/Unban/, "@@UNBAN@@")
                gsub(/Ban/, "\033[31mBan\033[0m")
                gsub(/@@UNBAN@@/, "\033[32mUnban\033[0m")
                print
            }'
        fi
    fi
    echo -e "${CYAN}============================================================${RESET}"
    read -rp "按回车键返回..."
}

menu_f2b_exponential() {
    while true; do
        clear
        local inc fac max
        inc=$(get_f2b_conf "bantime.increment")
        fac=$(get_f2b_conf "bantime.factor")
        max=$(get_f2b_conf "bantime.maxtime")
        local S_INC; [ "$inc" == "true" ] && S_INC="${GREEN}启用${RESET}" || S_INC="${YELLOW}禁用${RESET}"
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "${BOLD}${PURPLE}            高级: 指数封禁设置 (针对 sshd)${RESET}"
        echo -e "${CYAN}============================================================${RESET}"
        echo -e " 说明: 对重复犯错的恶意 IP，封禁时间按设定系数成倍递增"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"
        echo -e "  ${GREEN}1.${RESET} 递增模式开关   [${S_INC}]"
        echo -e "  ${GREEN}2.${RESET} 增长系数       [${YELLOW}$(fmt_f2b_unit "${fac:-未设置}" "factor")${RESET}]"
        echo -e "  ${GREEN}3.${RESET} 封禁上限       [${YELLOW}$(fmt_f2b_unit "${max:-未设置}" "time")${RESET}]"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"
        echo -e "  ${GREEN}0.${RESET} 返回上级"
        echo -e "${CYAN}============================================================${RESET}"
        read -rp "请选择 [0-3]: " sc
        case "$sc" in
            1) [ "$inc" == "true" ] && ns="false" || ns="true"; set_f2b_conf "bantime.increment" "$ns"; restart_f2b ;;
            2) change_f2b_param "增长系数 (倍数)" "bantime.factor" "factor" ;;
            3) change_f2b_param "封禁上限 (时间)" "bantime.maxtime" "time" ;;
            0) return ;;
            *) echo -e "${ERROR} 无效选项！"; sleep 1 ;;
        esac
    done
}

manage_fail2ban_menu() {
    if ! check_f2b_install; then read -rp "按回车键返回主菜单..."; return; fi
    while true; do
        clear
        VAL_MAX=$(get_f2b_conf "maxretry"); VAL_BAN=$(get_f2b_conf "bantime"); VAL_FIND=$(get_f2b_conf "findtime")
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "${BOLD}${PURPLE}                     Fail2Ban 防护管理${RESET}"
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "  服务状态: $(get_fail2ban_status)"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"
        echo -e "  ${GREEN}1.${RESET} 最大重试次数     [${YELLOW}${VAL_MAX:-默认}${RESET}]"
        echo -e "  ${GREEN}2.${RESET} 初始封禁时长     [${YELLOW}$(fmt_f2b_unit "${VAL_BAN:-默认}" "time")${RESET}]"
        echo -e "  ${GREEN}3.${RESET} 监测时间窗口     [${YELLOW}$(fmt_f2b_unit "${VAL_FIND:-默认}" "time")${RESET}]"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"
        echo -e "  ${GREEN}4.${RESET} 手动解封 IP"
        echo -e "  ${GREEN}5.${RESET} 添加 IP 白名单"
        echo -e "  ${GREEN}6.${RESET} 查看封禁日志 (最近20条)"
        echo -e "  ${GREEN}7.${RESET} 指数递增封禁设置 ->"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"
        echo -e "  ${GREEN}8.${RESET} 启用 / 停止 服务"
        echo -e "  ${GREEN}9.${RESET} 卸载 Fail2Ban"
        echo -e "  ${GREEN}0.${RESET} 返回主菜单"
        echo -e "${CYAN}============================================================${RESET}"
        read -rp "请选择 [0-9]: " choice
        case "$choice" in
            1) change_f2b_param "最大重试次数" "maxretry" "int" ;;
            2) change_f2b_param "初始封禁时长" "bantime" "time" ;;
            3) change_f2b_param "监测时间窗口" "findtime" "time" ;;
            4) unban_f2b_ip ;;
            5) add_f2b_whitelist ;;
            6) view_f2b_logs ;;
            7) menu_f2b_exponential ;;
            8) toggle_f2b_service ;;
            9) uninstall_f2b ;;
            0) return ;;
            *) echo -e "${ERROR} 无效选项！"; sleep 1 ;;
        esac
    done
}

# ============ 状态面板 ============
show_status() {
    local port pwd_auth pubkey_auth
    port="$(get_sshd_config_val "Port" "22")" || port="未知"
    pwd_auth="$(get_sshd_config_val "PasswordAuthentication" "yes")" || pwd_auth="未知"
    pubkey_auth="$(get_sshd_config_val "PubkeyAuthentication" "yes")" || pubkey_auth="未知"
    local f2b_stat; f2b_stat=$(get_fail2ban_status)
    local key_count; key_count=$(count_authorized_keys)

    echo -e "${CYAN}============================================================${RESET}"
    echo -e "${BOLD}${PURPLE}                     SSH 安全配置工具${RESET}"
    echo -e "${CYAN}============================================================${RESET}"
    echo -e " 系统架构 : ${GREEN}${OS_SHORT} ${OS_VER}${RESET}"
    if [[ "${pubkey_auth,,}" == "yes" ]]; then
        if [ "$key_count" -gt 0 ]; then
            echo -e " 密钥登录 : ${GREEN}已启用 (${key_count} 把公钥)${RESET}"
        else
            echo -e " 密钥登录 : ${YELLOW}已启用 (但无公钥，无法密钥登录)${RESET}"
        fi
    elif [[ "${pubkey_auth}" == "未知" ]]; then
        echo -e " 密钥登录 : ${YELLOW}未知（无法读取 sshd 配置）${RESET}"
    else
        echo -e " 密钥登录 : ${YELLOW}已禁用${RESET}"
    fi
    if [[ "${pwd_auth,,}" == "no" ]]; then
        echo -e " 密码登录 : ${GREEN}已禁用 (PasswordAuthentication no)${RESET}"
    elif [[ "${pwd_auth}" == "未知" ]]; then
        echo -e " 密码登录 : ${YELLOW}未知（无法读取 sshd 配置）${RESET}"
    else
        echo -e " 密码登录 : ${YELLOW}已启用 (推荐配置密钥后禁用)${RESET}"
    fi
    echo -e " Fail2Ban : ${f2b_stat}"
    echo -e " SSH 端口 : ${CYAN}${port}${RESET}"
    echo -e "${CYAN}============================================================${RESET}"
}

# ============ 密钥生成 ============

generate_vps_keypair() {
    echo -e "${WARN} 推荐在本人电脑或硬件密钥上生成私钥，VPS 只保存公钥。"
    read -rp "仍要在 VPS 上生成临时 ED25519 私钥吗？(y/N): " generate_confirm || return 1
    [[ "$generate_confirm" =~ ^[Yy]$ ]] || return 1
    local dir pub_content rm_confirm
    dir="$(generated_key_files create)" || return 1
    printf '%b 私钥暂存目录: %s；请设置私钥口令。\n' "$INFO" "$dir"
    if ! run_as_target ssh-keygen -t ed25519 -C '' -f "$dir/PrivateKey"; then
        printf '%b 生成失败。可能的暂存文件保留于 %s，请检查并清理。\n' "$ERROR" "$dir" >&2; return 1
    fi
    if run_as_target ssh-keygen -y -P '' -f "$dir/PrivateKey" >/dev/null 2>&1; then
        printf '%b 检测到空口令私钥，已拒绝并删除；请重新生成并设置非空口令。\n' "$ERROR" >&2
        generated_key_files delete "$dir" || printf '%b 删除未完成，请检查 %s。\n' "$ERROR" "$dir" >&2
        return 1
    fi
    pub_content="$(generated_key_files read "$dir")" || return 1
    if ! append_key_with_meta "$pub_content" 'VPS本地生成'; then
        printf '%b 公钥导入失败，暂存密钥仍在 %s，请保存后清理。\n' "$ERROR" "$dir" >&2; return 1
    fi
    printf '%b 密钥已生成。请使用 SFTP 下载 %s/PrivateKey。\n' "$INFO" "$dir"
    printf '公钥（可以公开）：\n%s\n' "$pub_content"
    read -rp "已下载私钥并保存口令，立即删除 VPS 暂存文件吗？(y/N): " rm_confirm || rm_confirm=n
    if [[ "$rm_confirm" =~ ^[Yy]$ ]]; then
        generated_key_files delete "$dir" || { printf '%b 删除未完成，请检查 %s。\n' "$ERROR" "$dir" >&2; return 1; }
        printf '%b 已删除当前文件；备份或快照中的副本需另行管理。\n' "$INFO"
    else printf '%b 暂存私钥仍在 %s，请妥善保存后清理。\n' "$WARN" "$dir"; fi
    return 0
}

# ============ 密钥登录开关 ============
toggle_pubkey_login() {
    local current
    if ! current="$(require_sshd_val "PubkeyAuthentication" "yes")"; then
        read -rp "按回车键继续..."; return 1
    fi

    if [[ "${current,,}" == "no" ]]; then
        echo -e "\n当前密钥登录已${GREEN}禁用${RESET}。"
        local key_count; key_count=$(count_authorized_keys)
        if [ "$key_count" -eq 0 ]; then
            echo -e "${YELLOW}[提示] 当前 authorized_keys 中还没有公钥，启用后仍需先添加公钥才能通过密钥登录。${RESET}"
        fi
        read -rp "是否要启用密钥登录？(y/N): " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            if set_sshd_config "PubkeyAuthentication" "yes" && restart_sshd; then
                echo -e "${INFO} ${GREEN}密钥登录已成功启用。${RESET}"
            fi
        fi
    else
        echo -e "\n${YELLOW}${BOLD}[警告] 禁用密钥登录后，如果密码登录也已禁用，你将无法登录 VPS！${RESET}"
        if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
            echo -e "${CYAN}${BOLD}[提示] 检测到您正在使用 SSH 远程会话，修改后切勿关闭当前窗口！${RESET}"
        fi

        if ! confirm_password_fallback "禁用密钥登录"; then
            printf '%b 未确认可用的密码备用连接，已保留密钥登录。\n' "$ERROR" >&2
            read -rp "按回车键继续..."; return 1
        fi

        if set_sshd_config "PubkeyAuthentication" "no" && restart_sshd; then
            echo -e "${INFO} ${GREEN}密钥登录已禁用，现在只能通过密码登录。${RESET}"
        fi
    fi
    read -rp "按回车键继续..."
}

# ============ 密钥配置菜单 ============
install_key_menu() {
    while true; do
        clear
        init_ssh_dir || return 1

        # 动态统计当前公钥数量
        local key_count
        key_count=$(count_authorized_keys)
        local key_count_label
        if [ "$key_count" -gt 0 ]; then
            key_count_label=" (${GREEN}${key_count} 把公钥${RESET})"
        else
            key_count_label=" (${YELLOW}无公钥${RESET})"
        fi

        # 动态显示当前密钥登录开关状态，避免新人困惑
        local pubkey_status
        pubkey_status="$(get_sshd_config_val "PubkeyAuthentication" "yes")" || pubkey_status="未知"
        local pubkey_label
        if [[ "${pubkey_status,,}" == "yes" ]]; then
            pubkey_label="[${GREEN}已启用${RESET}]"
        else
            pubkey_label="[${YELLOW}已禁用${RESET}]"
        fi

        echo -e "${CYAN}============================================================${RESET}"
        echo -e "${BOLD}${PURPLE}                     SSH 密钥登录管理${RESET}"
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "${BOLD}请选择 SSH 密钥配置方式：${RESET}"
        echo -e "  ${GREEN}1.${RESET} 从 GitHub 获取公钥 (${CYAN}适合：已将公钥上传至 GitHub 的用户${RESET})"
        echo -e "  ${GREEN}2.${RESET} 在 VPS 上全新生成密钥 (${CYAN}适合：本地没有密钥的新手，生成后可传 GitHub${RESET})"
        echo -e "  ${GREEN}3.${RESET} 从自定义 URL 获取公钥 (${CYAN}适合：有公钥直链的用户${RESET})"
        echo -e "  ${GREEN}4.${RESET} 管理已存公钥${key_count_label}"
        echo -e "  ${GREEN}5.${RESET} 密钥登录开关 ${pubkey_label}"
        echo -e "  ${GREEN}0.${RESET} 返回主菜单"
        echo -e "${CYAN}============================================================${RESET}"
        read -rp "请输入选项 [0-5]: " key_opt || return

        local test_hint=""
        local do_restart=0

        case "$key_opt" in
            1)
                echo -e "\n${YELLOW}${BOLD}[使用前提]${RESET}"
                echo -e "需先将本地公钥上传至 GitHub: ${CYAN}https://github.com/settings/keys${RESET}\n"
                read -rp "请输入您的 GitHub 用户名: " gh_user
                if [ -z "$gh_user" ]; then
                    echo -e "${ERROR} 输入不能为空！"
                    read -rp "按回车键继续..."
                    continue
                fi
                if [[ ! "$gh_user" =~ ^[A-Za-z0-9-]+$ ]]; then
                    echo -e "${ERROR} GitHub 用户名格式不正确。"
                    read -rp "按回车键继续..."
                    continue
                fi
                echo -e "${INFO} 正在从 GitHub 拉取公钥..."
                local pub_key
                if ! pub_key="$(fetch_public_keys "https://github.com/${gh_user}.keys")"; then
                    echo -e "\n${ERROR} 获取公钥失败！可能是用户名不正确，或该 GitHub 账号未配置公钥。"
                    echo -e "${CYAN}------------------------------------------------------------${RESET}"
                    read -rp "是否要在 VPS 上全新生成密钥 (选项 2)？(y/N): " switch_opt2
                    if [[ "$switch_opt2" =~ ^[Yy]$ ]]; then
                        if generate_vps_keypair; then
                            test_hint="请将已保存的私钥导入本地 SSH 客户端，新建终端测试连接。"
                            do_restart=1
                        fi
                    else
                        read -rp "按回车键继续..."
                        continue
                    fi
                else
                    if ! confirm_remote_key_fingerprints "$pub_key" "GitHub 用户 ${gh_user}"; then
                        printf '%b 未完成可信指纹核对，已取消导入。\n' "$ERROR" >&2
                        read -rp "按回车键继续..."
                        continue
                    fi
                    if append_key_with_meta "$pub_key" "GitHub: ${gh_user}"; then
                        test_hint="请使用该 GitHub 公钥对应的本地私钥，新建终端测试连接。"
                        do_restart=1
                    fi
                fi
                ;;
            2)
                if generate_vps_keypair; then
                    test_hint="请将已保存的私钥导入本地 SSH 客户端，新建终端测试连接。"
                    do_restart=1
                fi
                ;;
            3)
                read -rp "请输入公钥 URL: " key_url
                if [ -z "$key_url" ]; then
                    echo -e "${ERROR} URL 不能为空！"
                    read -rp "按回车键继续..."
                    continue
                fi
                if [[ ! "$key_url" =~ ^https:// ]]; then
                    echo -e "${ERROR} 为防止读取本地文件，只允许 https:// 公钥地址。"
                    read -rp "按回车键继续..."
                    continue
                fi
                local pub_key
                if ! pub_key="$(fetch_public_keys "$key_url")"; then
                    echo -e "${ERROR} 从 URL 获取公钥失败！"
                    read -rp "按回车键继续..."
                    continue
                fi
                if ! confirm_remote_key_fingerprints "$pub_key" '自定义 URL'; then
                    printf '%b 未完成可信指纹核对，已取消导入。\n' "$ERROR" >&2
                    read -rp "按回车键继续..."
                    continue
                fi
                if append_key_with_meta "$pub_key" "自定义URL"; then
                    test_hint="请使用该公钥对应的本地私钥，新建终端测试连接。"
                    do_restart=1
                fi
                ;;
            4)
                manage_keys_menu
                continue
                ;;
            5)
                toggle_pubkey_login
                continue
                ;;
            0) return ;;
            *)
                echo -e "${ERROR} 无效选项！"
                sleep 1
                continue
                ;;
        esac

        if [ "$do_restart" == "1" ]; then
            if set_sshd_config "PubkeyAuthentication" "yes" && restart_sshd; then
                echo -e "\n${CYAN}------------------------------------------------------------${RESET}"
                echo -e "${YELLOW}${BOLD}[重点测试]${RESET} ${test_hint}"
                echo -e "测试成功后，再返回主菜单【禁用密码登录】！"
                echo -e "${CYAN}------------------------------------------------------------${RESET}"
            fi
            read -rp "按回车键返回密钥管理子菜单..."
        fi
    done
}

# ============ 已存公钥管理 ============
manage_keys_menu() {
    init_ssh_dir || return 1
    local auth_file="$AUTHORIZED_KEYS" key_snapshot

    while true; do
        clear
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "${BOLD}${PURPLE}                     SSH 已存公钥管理${RESET}"
        echo -e "${CYAN}============================================================${RESET}"

        local key_lines=()
        local key_contents=()
        local line_num=0

        key_snapshot="$(read_authorized_keys)" || return 1
        if [ -n "$key_snapshot" ]; then
            while IFS= read -r line || [ -n "$line" ]; do
                ((line_num++))
                if [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]]; then
                    continue
                fi
                key_lines+=("$line_num")
                key_contents+=("$line")
            done <<< "$key_snapshot"
        fi

        if [ ${#key_contents[@]} -eq 0 ]; then
            echo -e "\n${WARN} 当前 ${auth_file} 中没有找到任何有效公钥！"
            echo -e "${CYAN}============================================================${RESET}"
            read -rp "按回车键返回..."
            return
        fi

        printf " %-4s | %-19s | %-8s | %-16s\n" "序号" "      添加时间" "公钥类型" "    备注来源"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"

        local idx=1
        for key in "${key_contents[@]}"; do
            local add_time="历史存量/未标记"
            local key_tag="未知/手动导入"

            if [[ "$key" =~ \[([0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2})\|([^\]]+)\] ]]; then
                add_time="${BASH_REMATCH[1]}"
                key_tag="${BASH_REMATCH[2]}"
            fi

            # 修正：带选项前缀的公钥也能正确显示密钥类型
            local key_type
            key_type=$(echo "$key" | awk '{
                for(i=1;i<=NF;i++){
                    if($i ~ /^(ssh-|ecdsa-|sk-)/){ print $i; exit }
                }
                print "未知"
            }')

            printf " ${GREEN}[%2d]${RESET} | ${YELLOW}%19s${RESET} | ${CYAN}%-8s${RESET} | ${PURPLE}%-16s${RESET}\n" "$idx" "$add_time" "$key_type" "$(printf '%s' "$key_tag" | LC_ALL=C tr -d '\000-\037\177')"
            ((idx++))
        done

        echo -e "${CYAN}============================================================${RESET}"
        echo -e " 输入 ${RED}[序号]${RESET} : 删除指定公钥"
        echo -e " 输入 ${RED}[all]${RESET}  : 清空全部公钥"
        echo -e " 输入 ${GREEN}[0]${RESET}    : 返回上级菜单"
        echo -e "${CYAN}============================================================${RESET}"
        read -rp "请输入操作指令: " key_action || return

        if [ "$key_action" == "0" ]; then
            return
        elif [ "$key_action" == "all" ]; then
            local valid_key_count confirm_all
            valid_key_count="$(count_authorized_keys)"
            if [ "$valid_key_count" -gt 0 ]; then
                if confirm_password_fallback "清空全部有效公钥"; then confirm_all=y
                else
                    printf '%b 未确认可用的密码备用连接，已取消清空。\n' "$ERROR" >&2
                    read -rp "按回车继续..." || return; continue
                fi
            else
                read -rp "文件中没有可解析的有效公钥；确认清空其余记录吗？(y/N): " confirm_all
            fi
            if [[ "$confirm_all" =~ ^[Yy]$ ]]; then
                remove_authorized_key all "$key_snapshot" || { read -rp "删除失败，按回车刷新..."; continue; }
                echo -e "${INFO} 已清空所有公钥，原文件已备份。"
                sleep 1
                continue
            fi
        elif [[ "$key_action" =~ ^[0-9]+$ ]] && [ "$key_action" -ge 1 ] && [ "$key_action" -le "${#key_contents[@]}" ]; then
            local target_idx=$((10#$key_action - 1))
            local target_line_num="${key_lines[$target_idx]}"

            local valid_key_count confirm_del
            valid_key_count="$(count_authorized_keys)"
            if [ "$valid_key_count" -le 1 ] && authorized_key_line_is_valid "${key_contents[$target_idx]}"; then
                if confirm_password_fallback "删除最后一把有效公钥"; then confirm_del=y
                else
                    printf '%b 未确认可用的密码备用连接，已取消删除。\n' "$ERROR" >&2
                    read -rp "按回车继续..." || return; continue
                fi
            else
                read -rp "确认删除序号 [${key_action}] 的公钥吗？(y/N): " confirm_del
            fi
            if [[ "$confirm_del" =~ ^[Yy]$ ]]; then
                remove_authorized_key "$target_line_num" "$key_snapshot" || { read -rp "删除失败，按回车刷新..."; continue; }
                echo -e "${INFO} ${GREEN}序号 [${key_action}] 的公钥已成功删除！${RESET}"
                sleep 1
                continue
            fi
        else
            echo -e "${ERROR} 输入无效，请重新输入！"
            sleep 1
            continue
        fi
    done
}

# ============ 密码登录开关 ============
# 防误锁检查是保守的静态检查；-c/交互确认仍需用户完成真实新连接。
password_login_ready() {
    local context_port="${1:-}" dump method permit_root
    if sshd_has_unverifiable_match; then
        printf '%b 检测到 Match Host/RDomain，无法可靠重放该连接上下文；已拒绝关闭公钥登录。\n' "$ERROR" >&2
        return 1
    fi
    dump="$(sshd_effective_dump "$context_port")" || {
        printf '%b 无法解析 sshd 配置，不能确认密码备用登录。\n' "$ERROR" >&2; return 1;
    }
    [ "$(awk '$1=="passwordauthentication" {print $2; exit}' <<< "$dump")" = yes ] || {
        printf '%b PasswordAuthentication 未明确启用。\n' "$ERROR" >&2; return 1;
    }
    method="$(awk '$1=="authenticationmethods" {$1=""; sub(/^ /, ""); print; exit}' <<< "$dump")"
    case " $method " in *' any '*|*' password '*) ;;
        *) printf '%b AuthenticationMethods 不允许单独使用密码登录。\n' "$ERROR" >&2; return 1 ;;
    esac
    if [ "$TARGET_UID" -eq 0 ]; then
        permit_root="$(awk '$1=="permitrootlogin" {print $2; exit}' <<< "$dump")"
        [ "$permit_root" = yes ] || {
            printf '%b root 的 PermitRootLogin=%s，不允许用密码作为备用登录。\n' "$ERROR" "${permit_root:-未知}" >&2
            return 1
        }
    fi
    return 0
}

confirm_password_fallback() {
    local purpose="$1"
    password_login_ready "" || return 1
    printf '%b 请保留当前会话，先用目标用户 %s 和密码建立一条新的 SSH 连接。\n' "$WARN" "$TARGET_USER"
    local confirm
    read -rp "已成功测试密码备用连接，继续${purpose}吗？(y/N): " confirm || return 1
    [[ "$confirm" =~ ^[Yy]$ ]]
}

publickey_login_ready() {
    local context_port="${1:-}" dump files file matched=0 content line method
    if sshd_has_unverifiable_match; then
        printf '%b 检测到 Match Host/RDomain，无法可靠重放该连接上下文；已拒绝关闭密码登录。\n' "$ERROR" >&2
        return 1
    fi
    dump="$(sshd_effective_dump "$context_port")" || { printf '%b 无法解析 sshd 配置，拒绝关闭密码登录。\n' "$ERROR" >&2; return 1; }
    [ "$(awk '$1=="pubkeyauthentication" {print $2; exit}' <<< "$dump")" = yes ] || return 1
    method="$(awk '$1=="authenticationmethods" {$1=""; sub(/^ /, ""); print; exit}' <<< "$dump")"
    case " $method " in *' any '*|*' publickey '*) ;; *)
        printf '%b AuthenticationMethods 未提供单独公钥登录方式，拒绝关闭密码登录。\n' "$ERROR" >&2; return 1 ;;
    esac
    if [ "$TARGET_UID" -eq 0 ]; then
        case "$(awk '$1=="permitrootlogin" {print $2; exit}' <<< "$dump")" in yes|prohibit-password|without-password) ;; *) return 1;; esac
    fi
    files="$(awk '$1=="authorizedkeysfile" {$1=""; print; exit}' <<< "$dump")"
    for file in $files; do
        file="${file//%h/$TARGET_HOME}"; file="${file//%u/$TARGET_USER}"; file="${file//%U/$TARGET_UID}"
        [[ "$file" != *%* ]] || continue
        [[ "$file" == /* ]] || file="$TARGET_HOME/$file"
        [ "$file" = "$AUTHORIZED_KEYS" ] && matched=1
    done
    [ "$matched" -eq 1 ] || {
        printf '%b sshd 没有从脚本管理的 authorized_keys 路径读取公钥，拒绝关闭密码登录。\n' "$ERROR" >&2; return 1;
    }
    verify_key_path_security || {
        printf '%b 密钥路径的所有者或权限不满足 OpenSSH StrictModes，拒绝关闭密码登录。\n' "$ERROR" >&2
        return 1
    }
    content="$(read_authorized_keys)" || return 1
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:blank:]]*$ || "$line" =~ ^[[:blank:]]*# ]] && continue
        validate_public_key_content "$line" >/dev/null 2>&1 && return 0
    done <<< "$content"
    printf '%b 没有可确认的裸公钥记录；带选项的授权需人工核对。\n' "$ERROR" >&2
    return 1
}

# 列出除 TARGET_USER 外、可能用密码登录的账户（uid>=1000 或 root，shell 非 nologin/false）。
list_other_login_users() {
    awk -F: -v me="$TARGET_USER" '
        $1 == me { next }
        ($3 >= 1000 || $1 == "root") && $7 !~ /(nologin|false)$/ { print $1 }
    ' /etc/passwd 2>/dev/null
}

warn_global_password_disable() {
    local mode="$1" others
    printf '%b 即将写入全局默认 PasswordAuthentication no；已有 Match 块可能对特定连接另行覆盖。\n' "$WARN" >&2
    printf '%b 未被 Match 覆盖的其他仅密码登录账户也将无法再使用密码登录。\n' "$WARN" >&2
    others="$(list_other_login_users | tr '\n' ' ')"
    others="${others%" "}"
    if [ -n "$others" ]; then
        printf '%b 检测到其他可登录用户: %s\n' "$WARN" "$others" >&2
    fi
    if [ "$mode" = interactive ] && [ -n "$others" ]; then
        local confirm
        read -rp "确认对整机禁用密码登录吗？(y/N): " confirm || return 1
        [[ "$confirm" =~ ^[Yy]$ ]] || return 1
    fi
    return 0
}

toggle_password_login() {
    local current confirm pwd_confirm
    if ! current="$(get_sshd_config_val PasswordAuthentication unknown)"; then
        printf '%b 无法读取 PasswordAuthentication，已停止。\n' "$ERROR" >&2
        return 1
    fi
    if [ "$current" = no ]; then
        read -rp "启用密码登录吗？(y/N): " confirm || return 1
        [[ "$confirm" =~ ^[Yy]$ ]] || return 0
        set_sshd_config PasswordAuthentication yes && restart_sshd || return 1
        read -rp "为目标用户设置新密码吗？(y/N): " pwd_confirm || return 0
        [[ "$pwd_confirm" =~ ^[Yy]$ ]] && $SUDO passwd "$TARGET_USER"
    elif [ "$current" = yes ]; then
        publickey_login_ready "" || { printf '%b 未通过防误锁检查，保留密码登录。\n' "$ERROR" >&2; return 1; }
        printf '%b 请保留当前会话，并用目标用户和本地私钥建立一条新的 SSH 连接。\n' "$WARN"
        read -rp "已成功建立新连接，现在禁用密码登录吗？(y/N): " confirm || return 1
        [[ "$confirm" =~ ^[Yy]$ ]] || return 0
        warn_global_password_disable interactive || { echo -e "${INFO} 已取消操作。"; return 0; }
        set_sshd_config PasswordAuthentication no &&
            set_sshd_config ChallengeResponseAuthentication no &&
            set_sshd_config KbdInteractiveAuthentication no && restart_sshd || return 1
        printf '%b 已关闭密码和键盘交互认证。\n' "$INFO"
    else printf '%b 无法判断当前认证配置，已停止。\n' "$ERROR" >&2; return 1; fi
    return 0
}

# ============ 修改 SSH 端口 ============
# 本轮新加的防火墙/SELinux 放行记录（失败时仅回滚本轮新增）
PORT_FW_UFW_ADDED=""
PORT_FW_FIREWALLD_PORT=""
PORT_FW_FIREWALLD_ZONE=""
PORT_FW_FIREWALLD_RUNTIME_ADDED=""
PORT_FW_FIREWALLD_PERMANENT_ADDED=""
PORT_FW_SELINUX_ADDED=""

reset_port_fw_tracking() {
    PORT_FW_UFW_ADDED=""
    PORT_FW_FIREWALLD_PORT=""; PORT_FW_FIREWALLD_ZONE=""
    PORT_FW_FIREWALLD_RUNTIME_ADDED=""; PORT_FW_FIREWALLD_PERMANENT_ADDED=""
    PORT_FW_SELINUX_ADDED=""
}

port_fw_tracking_pending() {
    [ -n "$PORT_FW_UFW_ADDED" ] || [ -n "$PORT_FW_FIREWALLD_RUNTIME_ADDED" ] ||
        [ -n "$PORT_FW_FIREWALLD_PERMANENT_ADDED" ] || [ -n "$PORT_FW_SELINUX_ADDED" ]
}

begin_port_fw_tracking() {
    if port_fw_tracking_pending; then
        printf '%b 上一次端口放行尚未完成回滚，已拒绝覆盖跟踪状态；请先从控制台处理。\n' "$ERROR" >&2
        return 1
    fi
    reset_port_fw_tracking
}

rollback_port_fw_changes() {
    local p zone failed=0
    if [ -n "$PORT_FW_UFW_ADDED" ]; then
        p="$PORT_FW_UFW_ADDED"
        echo -e "${WARN} 回滚 ufw 规则: ${p}/tcp"
        if $SUDO env LC_ALL=C ufw --force delete allow "$p"/tcp >/dev/null 2>&1; then
            PORT_FW_UFW_ADDED=""
        else
            printf '%b ufw 回滚失败，请从控制台删除 %s/tcp。\n' "$ERROR" "$p" >&2; failed=1
        fi
    fi
    p="$PORT_FW_FIREWALLD_PORT"; zone="$PORT_FW_FIREWALLD_ZONE"
    if [ -n "$p" ] && [ -n "$zone" ] && [ -n "$PORT_FW_FIREWALLD_RUNTIME_ADDED" ]; then
        echo -e "${WARN} 回滚 firewalld runtime 端口: ${zone} ${p}/tcp"
        if $SUDO firewall-cmd --zone="$zone" --remove-port="${p}/tcp" >/dev/null 2>&1; then
            PORT_FW_FIREWALLD_RUNTIME_ADDED=""
        else
            printf '%b firewalld runtime 回滚失败：%s %s/tcp。\n' "$ERROR" "$zone" "$p" >&2; failed=1
        fi
    fi
    if [ -n "$p" ] && [ -n "$zone" ] && [ -n "$PORT_FW_FIREWALLD_PERMANENT_ADDED" ]; then
        echo -e "${WARN} 回滚 firewalld permanent 端口: ${zone} ${p}/tcp"
        if $SUDO firewall-cmd --permanent --zone="$zone" --remove-port="${p}/tcp" >/dev/null 2>&1; then
            PORT_FW_FIREWALLD_PERMANENT_ADDED=""
        else
            printf '%b firewalld permanent 回滚失败：%s %s/tcp。\n' "$ERROR" "$zone" "$p" >&2; failed=1
        fi
    fi
    if [ -z "$PORT_FW_FIREWALLD_RUNTIME_ADDED" ] && [ -z "$PORT_FW_FIREWALLD_PERMANENT_ADDED" ]; then
        PORT_FW_FIREWALLD_PORT=""; PORT_FW_FIREWALLD_ZONE=""
    fi
    if [ -n "$PORT_FW_SELINUX_ADDED" ]; then
        p="$PORT_FW_SELINUX_ADDED"
        echo -e "${WARN} 回滚 SELinux ssh_port_t: ${p}"
        if $SUDO semanage port -d -t ssh_port_t -p tcp "$p" >/dev/null 2>&1; then
            PORT_FW_SELINUX_ADDED=""
        else
            printf '%b SELinux 端口回滚失败：%s。\n' "$ERROR" "$p" >&2; failed=1
        fi
    fi
    return "$failed"
}

ufw_is_active() {
    command -v ufw >/dev/null 2>&1 &&
        $SUDO env LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active$'
}

firewalld_is_active() {
    command -v firewall-cmd >/dev/null 2>&1 &&
        $SUDO firewall-cmd --state 2>/dev/null | grep -qx running
}

# 无 ufw/firewalld 时，只要 INPUT 链存在自定义规则就要求人工确认，避免启发式漏判。
unmanaged_fw_looks_restrictive() {
    local out tool
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null 2>&1 || continue
        out="$($SUDO "$tool" -S 2>/dev/null)" || return 0
        grep -qE '^-P INPUT (DROP|REJECT)|^-A INPUT ' <<< "$out" && return 0
    done
    if command -v nft >/dev/null 2>&1; then
        out="$($SUDO nft list ruleset 2>/dev/null)" || return 0
        grep -qiE 'hook[[:space:]]+input|policy[[:space:]]+(drop|reject)|[[:space:]](drop|reject)([[:space:];]|$)' <<< "$out" && return 0
    fi
    return 1
}

warn_or_abort_unmanaged_fw() {
    local mode="$1"  # interactive|cli
    local ufw_active=0 fwd_active=0
    if ufw_is_active; then
        ufw_active=1
    fi
    if firewalld_is_active; then
        fwd_active=1
    fi
    [ "$ufw_active" -eq 0 ] && [ "$fwd_active" -eq 0 ] || return 0
    unmanaged_fw_looks_restrictive || return 0
    echo -e "${RED}${BOLD}[警告] 未检测到活动的 ufw/firewalld，但 iptables/nft 似乎存在限制性规则。${RESET}"
    echo -e "${YELLOW}本脚本不会改写原始 iptables/nft；改端口前请自行放行新端口，否则可能锁死远程访问。${RESET}"
    if [ "$mode" = cli ]; then
        if [ "${KEY_SH_ALLOW_UNMANAGED_FW:-0}" = 1 ]; then
            echo -e "${WARN} 已设置 KEY_SH_ALLOW_UNMANAGED_FW=1，继续改端口。" >&2
            return 0
        fi
        printf '%b 已中止。若确认已自行放行，可设置 KEY_SH_ALLOW_UNMANAGED_FW=1 后重试。\n' "$ERROR" >&2
        return 1
    fi
    local confirm
    read -rp "确认你将自行开放新端口并继续？(y/N): " confirm || return 1
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo -e "${INFO} 已取消。"; return 1; }
    return 0
}

resolve_firewalld_zone() {
    local requested="${KEY_SH_FIREWALLD_ZONE:-}" local_ip="" iface="" zone=""
    local -a zones=()
    if [ -n "$requested" ]; then
        [[ "$requested" =~ ^[A-Za-z0-9_.-]+$ ]] || {
            printf '%b KEY_SH_FIREWALLD_ZONE 格式无效。\n' "$ERROR" >&2; return 1;
        }
        if ! $SUDO firewall-cmd --get-zones 2>/dev/null | tr ' ' '\n' | grep -Fxq -- "$requested"; then
            printf '%b firewalld 区域不存在：%s。\n' "$ERROR" "$requested" >&2; return 1
        fi
        printf '%s\n' "$requested"; return 0
    fi
    if [ -n "${SSH_CONNECTION:-}" ] && command -v ip >/dev/null 2>&1; then
        read -r _ _ local_ip _ <<< "$SSH_CONNECTION"
        iface="$(ip -o addr show 2>/dev/null | awk -v want="$local_ip" '
            ($3=="inet" || $3=="inet6") {address=$4; sub(/\/.*/, "", address); if(address==want){print $2; exit}}
        ')"
        iface="${iface%%@*}"
        if [ -n "$iface" ]; then
            zone="$($SUDO firewall-cmd --get-zone-of-interface="$iface" 2>/dev/null || true)"
            if [ -n "$zone" ] && [ "$zone" != 'no zone' ]; then printf '%s\n' "$zone"; return 0; fi
        fi
    fi
    mapfile -t zones < <($SUDO firewall-cmd --get-active-zones 2>/dev/null | awk '/^[^[:space:]]/ {print $1}')
    if [ "${#zones[@]}" -eq 1 ]; then printf '%s\n' "${zones[0]}"; return 0; fi
    if [ "${#zones[@]}" -eq 0 ]; then
        zone="$($SUDO firewall-cmd --get-default-zone 2>/dev/null)" || return 1
        [ -n "$zone" ] && { printf '%s\n' "$zone"; return 0; }
    fi
    printf '%b 无法唯一确定 SSH 入站接口所属的 firewalld 区域；请设置 KEY_SH_FIREWALLD_ZONE 后重试。\n' "$ERROR" >&2
    return 1
}

# 为新端口准备 SELinux/防火墙；仅标记本轮新增项。失败返回 1。
prepare_port_access() {
    local new_port="$1" selinux_ports="" fw_zone="" query_rc runtime_present=0 permanent_present=0 ufw_status=""
    begin_port_fw_tracking || return 1
    if command -v getenforce &>/dev/null && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
        echo -e "${INFO} 检测到 SELinux 启用，正在申请放行端口 ${new_port}..."
        if ! command -v semanage &>/dev/null; then
            printf '%b SELinux 已启用但未安装 semanage，已停止端口变更。\n' "$ERROR" >&2
            return 1
        fi
        if ! selinux_ports="$($SUDO semanage port -l 2>/dev/null)"; then
            printf '%b 无法读取 SELinux 端口策略，已停止端口变更。\n' "$ERROR" >&2
            return 1
        fi
        if awk -v p="$new_port" '
            BEGIN { found=0 }
            $1=="ssh_port_t" && $2=="tcp" {
                for (i=3; i<=NF; i++) {
                    n = split($i, parts, /,/)
                    for (j=1; j<=n; j++) {
                        if (parts[j] == p) { found=1; exit }
                        if (split(parts[j], r, /-/) == 2 && r[1]+0 <= p+0 && p+0 <= r[2]+0) { found=1; exit }
                    }
                }
            }
            END { exit !found }
        ' <<< "$selinux_ports"; then
            echo -e "${INFO} SELinux 已允许 ssh_port_t 端口 ${new_port}。"
        else
            if $SUDO semanage port -a -t ssh_port_t -p tcp "$new_port" 2>/dev/null; then
                PORT_FW_SELINUX_ADDED="$new_port"
            else
                printf '%b 添加 SELinux 端口失败；请确认端口类型，脚本不会重分配其他服务的端口。\n' "$ERROR" >&2
                return 1
            fi
        fi
    fi

    if ufw_is_active; then
        ufw_status="$($SUDO env LC_ALL=C ufw status 2>/dev/null)" || { rollback_port_fw_changes; return 1; }
        if grep -qE "^${new_port}/tcp[[:space:]]+ALLOW" <<< "$ufw_status"; then
            echo -e "${INFO} ufw 已允许 ${new_port}/tcp。"
        else
            echo -e "${INFO} 正在向 ufw 防火墙放行端口 ${new_port}/tcp..."
            $SUDO env LC_ALL=C ufw allow "$new_port"/tcp >/dev/null || {
                printf '%b 防火墙放行失败，已停止。\n' "$ERROR" >&2
                rollback_port_fw_changes; return 1
            }
            PORT_FW_UFW_ADDED="$new_port"
        fi
    elif firewalld_is_active; then
        fw_zone="$(resolve_firewalld_zone)" || { rollback_port_fw_changes; return 1; }
        PORT_FW_FIREWALLD_PORT="$new_port"; PORT_FW_FIREWALLD_ZONE="$fw_zone"
        $SUDO firewall-cmd --zone="$fw_zone" --query-port="${new_port}/tcp" >/dev/null 2>&1; query_rc=$?
        case "$query_rc" in 0) runtime_present=1;; 1) :;; *) rollback_port_fw_changes; return 1;; esac
        $SUDO firewall-cmd --permanent --zone="$fw_zone" --query-port="${new_port}/tcp" >/dev/null 2>&1; query_rc=$?
        case "$query_rc" in 0) permanent_present=1;; 1) :;; *) rollback_port_fw_changes; return 1;; esac
        if [ "$runtime_present" -eq 0 ]; then
            echo -e "${INFO} 正在向 firewalld runtime 区域 ${fw_zone} 放行 ${new_port}/tcp..."
            $SUDO firewall-cmd --zone="$fw_zone" --add-port="${new_port}/tcp" >/dev/null || { rollback_port_fw_changes; return 1; }
            PORT_FW_FIREWALLD_RUNTIME_ADDED=1
        fi
        if [ "$permanent_present" -eq 0 ]; then
            echo -e "${INFO} 正在向 firewalld permanent 区域 ${fw_zone} 放行 ${new_port}/tcp..."
            $SUDO firewall-cmd --permanent --zone="$fw_zone" --add-port="${new_port}/tcp" >/dev/null || { rollback_port_fw_changes; return 1; }
            PORT_FW_FIREWALLD_PERMANENT_ADDED=1
        fi
        $SUDO firewall-cmd --zone="$fw_zone" --query-port="${new_port}/tcp" >/dev/null 2>&1 &&
            $SUDO firewall-cmd --permanent --zone="$fw_zone" --query-port="${new_port}/tcp" >/dev/null 2>&1 || {
                printf '%b firewalld 放行结果验证失败。\n' "$ERROR" >&2
                rollback_port_fw_changes; return 1
            }
        echo -e "${INFO} firewalld 区域 ${fw_zone} 已允许 ${new_port}/tcp（runtime + permanent）。"
    fi
    return 0
}

validate_ssh_port() {
    [[ "$1" =~ ^(22|[1-9][0-9]{3,4})$ ]] && { [ "$1" -eq 22 ] || { [ "$1" -ge 1024 ] && [ "$1" -le 65535 ]; }; }
}

port_is_listening() {
    local port="$1" out
    if command -v ss >/dev/null 2>&1; then
        out="$(ss -H -ltn "sport = :${port}" 2>/dev/null)" || return 2
        [ -n "$out" ]; return
    fi
    if command -v netstat >/dev/null 2>&1; then
        out="$(LC_ALL=C netstat -ltn 2>/dev/null)" || return 2
        awk -v p="$port" 'NR>2 {address=$4; sub(/^.*:/, "", address); if(address==p) found=1} END {exit !found}' <<< "$out"
        return
    fi
    return 2
}

port_available_for_sshd() {
    local current_ports="$1" new_port="$2" rc
    port_list_contains "$current_ports" "$new_port" && return 0
    port_is_listening "$new_port"; rc=$?
    case "$rc" in
        0) printf '%b TCP %s 已被其他服务监听。\n' "$ERROR" "$new_port" >&2; return 1 ;;
        1) return 0 ;;
        *) printf '%b 无法可靠检查 TCP %s 是否被占用（需要可用的 ss 或 netstat），已停止。\n' "$ERROR" "$new_port" >&2; return 1 ;;
    esac
}

ssh_socket_activation_unit() {
    local unit
    [ "$INIT_SYS" = systemd ] || return 1
    for unit in ssh.socket sshd.socket; do
        if $SUDO systemctl is-active --quiet "$unit" 2>/dev/null ||
           $SUDO systemctl is-enabled --quiet "$unit" 2>/dev/null; then
            printf '%s\n' "$unit"; return 0
        fi
    done
    return 1
}

change_ssh_port() {
    local current_port new_port
    if ! current_port="$(require_sshd_val "Port" "22")"; then
        read -rp "按回车键返回主菜单..."
        return 1
    fi
    echo -e "\n当前 SSH 端口为: ${CYAN}${current_port}${RESET}"
    if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
        echo -e "${YELLOW}${BOLD}[提示] 检测到您正在使用 SSH 远程会话，修改端口后请勿关闭当前窗口，请先新建终端验证！${RESET}"
    fi
    read -rp "请输入新的 SSH 端口 (22 或 1024-65535): " new_port

    if ! validate_ssh_port "$new_port"; then
        echo -e "${ERROR} 端口格式不正确！"
        read -rp "按回车键返回主菜单..."
        return
    fi
    # 已仅监听该端口则无需修改
    if [ "$current_port" = "$new_port" ]; then
        echo -e "${INFO} SSH 已仅使用端口 ${new_port}，无需修改。"
        read -rp "按回车键返回主菜单..."
        return
    fi
    local socket_unit=""
    if socket_unit="$(ssh_socket_activation_unit)"; then
        printf '%b %s 正在活动或已启用；请先从控制台迁移 socket 的 ListenStream。\n' "$ERROR" "$socket_unit" >&2
        read -rp "按回车键返回主菜单..."
        return 1
    fi
    # 若当前 sshd 已包含目标端口，不把它当成“被其他服务占用”
    if ! port_available_for_sshd "$current_port" "$new_port"; then
        read -rp "按回车键返回主菜单..."
        return 1
    fi
    if ! f2b_port_sync_preflight; then
        read -rp "按回车键返回主菜单..."
        return 1
    fi

    warn_or_abort_unmanaged_fw interactive || {
        read -rp "按回车键返回主菜单..."
        return 1
    }

    if ! prepare_port_access "$new_port"; then
        read -rp "按回车键返回主菜单..."
        return 1
    fi

    if ! set_sshd_config "Port" "$new_port"; then
        echo -e "${ERROR} 写入 SSH 配置失败，原配置未改变。"
        rollback_sshd_transaction
        rollback_port_fw_changes
        read -rp "按回车键返回主菜单..."
        return
    fi

    if restart_sshd; then
        reset_port_fw_tracking
        echo -e "${INFO} ${GREEN}SSH 端口已顺利修改为 ${new_port}${RESET}"

        # SSH 已安全提交后再同步 Fail2Ban；同步失败会恢复原 jail.local，不回退可达的 SSH 端口。
        sync_f2b_port_after_ssh_change "$new_port" || {
            printf '%b SSH 端口已变更，但 Fail2Ban 同步失败；SSH 仍保持可达，请检查防护状态。\n' "$ERROR" >&2
            return 1
        }

        if command -v ss &>/dev/null; then
            echo -e "${INFO} 系统实际监听服务端口状态："
            ss -tulpn | grep ssh || true
        fi
        echo -e "${WARN} 注意：如使用的是阿里云/腾讯云/AWS等，请务必在【云服务器安全组】中开放 TCP ${new_port} 端口！"
    else
        rollback_port_fw_changes
    fi

    read -rp "按回车键返回主菜单..."
}

# 供自动化测试安全加载函数；正常执行不受影响。
if [ "${KEY_SH_LIB_ONLY:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

# ============ 主逻辑 ============
detect_os; detect_pkg_mgr; detect_init; detect_ssh_log

# 非 root 时确认 sudo 可用（不破坏 root 直跑）
if [ "$EUID" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        printf '%s\n' '非 root 运行需要 sudo，但未找到 sudo 命令。' >&2
        exit 1
    fi
    if ! sudo -n true 2>/dev/null && ! sudo true; then
        printf '%s\n' '无法通过 sudo 提权，请确认当前用户具有 sudo 权限。' >&2
        exit 1
    fi
fi

# ============ 命令行参数解析 ============
# 先收集所有参数，循环结束后按依赖顺序统一执行
OVERWRITE=0
CLI_GH_USER=""
CLI_KEY_URL=""
CLI_KEY_FILE=""
CLI_PORT=""
CLI_DISABLE_PWD=0
CLI_CONFIRMED_KEY_LOGIN=0

while getopts "ocg:u:f:p:d" OPT; do
    case $OPT in
        o) OVERWRITE=1 ;;
        g) CLI_GH_USER="$OPTARG" ;;
        u) CLI_KEY_URL="$OPTARG" ;;
        f) CLI_KEY_FILE="$OPTARG" ;;
        p) CLI_PORT="$OPTARG" ;;
        d) CLI_DISABLE_PWD=1 ;;
        c) CLI_CONFIRMED_KEY_LOGIN=1 ;;
        *) exit 1 ;;
    esac
done

shift "$((OPTIND - 1))"
[ "$#" -eq 0 ] || { printf '%b 存在无法识别的位置参数。\n' "$ERROR" >&2; exit 1; }
[ -z "$CLI_PORT" ] || validate_ssh_port "$CLI_PORT" || { printf '%b 端口无效。\n' "$ERROR" >&2; exit 1; }
[ -z "$CLI_GH_USER" ] || [[ "$CLI_GH_USER" =~ ^[A-Za-z0-9-]+$ ]] || exit 1
if [ -n "$CLI_KEY_FILE" ]; then
    [ -f "$CLI_KEY_FILE" ] && [ -r "$CLI_KEY_FILE" ] && [ "$(wc -c < "$CLI_KEY_FILE")" -le 1048576 ] || {
        printf '%b 公钥文件不可读、不是常规文件或超过 1 MiB。\n' "$ERROR" >&2; exit 1;
    }
fi
if [ "$CLI_DISABLE_PWD" -eq 1 ] && [ "$CLI_CONFIRMED_KEY_LOGIN" -ne 1 ]; then
    printf '%b -d 需要同时提供 -c，表示你已使用目标用户和公钥成功建立一条新连接。\n' "$ERROR" >&2
    exit 1
fi
if [ "$CLI_CONFIRMED_KEY_LOGIN" -eq 1 ] && [ "$CLI_DISABLE_PWD" -ne 1 ]; then
    printf '%b -c 只能与 -d 一起使用。\n' "$ERROR" >&2
    exit 1
fi
if [ "$CLI_DISABLE_PWD" -eq 1 ] &&
   { [ -n "$CLI_GH_USER" ] || [ -n "$CLI_KEY_URL" ] || [ -n "$CLI_KEY_FILE" ] || [ -n "$CLI_PORT" ]; }; then
    printf '%b 为确保 -c 对应已经测试过的最终状态，-d 不能与导入公钥或修改端口同轮执行。\n' "$ERROR" >&2
    printf '%b 请先完成公钥/端口变更并新建连接验证，再单独运行 -d -c。\n' "$ERROR" >&2
    exit 1
fi

# -o 必须配合公钥来源使用，否则会误清空 authorized_keys
if [ "$OVERWRITE" -eq 1 ] && [ -z "$CLI_GH_USER" ] && [ -z "$CLI_KEY_URL" ] && [ -z "$CLI_KEY_FILE" ]; then
    echo -e "${ERROR} -o（覆盖模式）必须与 -g、-u 或 -f 一起使用！"
    echo -e "${YELLOW}单独执行 -o 会清空 authorized_keys 中所有公钥，已阻止。${RESET}"
    exit 1
fi
if [ "$OVERWRITE" -eq 1 ] && [ -n "$CLI_PORT" ]; then
    printf '%b -o 覆盖现有公钥和修改端口必须分两次执行并分别测试。\n' "$ERROR" >&2
    exit 1
fi

check_dependencies || exit 1

# 有任意 CLI 参数就进入批量执行模式
if [ -n "$CLI_GH_USER" ] || [ -n "$CLI_KEY_URL" ] || [ -n "$CLI_KEY_FILE" ] || \
   [ -n "$CLI_PORT" ] || [ "$CLI_DISABLE_PWD" -eq 1 ]; then

    need_restart_sshd=0
    need_restart_f2b=0

    if [ "$OVERWRITE" -eq 1 ]; then
        if ! current_key_count="$(count_authorized_keys)"; then exit 1; fi
        if [ "$current_key_count" -gt 0 ]; then
            [ "${KEY_SH_CONFIRMED_PASSWORD_LOGIN:-0}" = 1 ] || {
                printf '%b 覆盖现有有效公钥前，请先测试密码备用连接并设置 KEY_SH_CONFIRMED_PASSWORD_LOGIN=1。\n' "$ERROR" >&2
                exit 1
            }
            password_login_ready "" || {
                printf '%b 无法确认密码备用登录，已拒绝覆盖现有公钥。\n' "$ERROR" >&2; exit 1;
            }
        fi
    fi

    if [ -n "$CLI_PORT" ]; then
        if ! current_port="$(require_sshd_val Port 22)"; then exit 1; fi
        if [ "$current_port" = "$CLI_PORT" ]; then
            : # 已仅使用该端口
        elif cli_socket_unit="$(ssh_socket_activation_unit)"; then
            printf '%b %s 正在活动或已启用，不能由本脚本修改 SSH 端口。\n' "$ERROR" "$cli_socket_unit" >&2; exit 1
        elif ! port_available_for_sshd "$current_port" "$CLI_PORT"; then
            printf '%b 端口预检失败，尚未导入公钥。\n' "$ERROR" >&2; exit 1
        elif ! f2b_port_sync_preflight; then
            printf '%b Fail2Ban 端口同步预检失败，尚未修改 SSH。\n' "$ERROR" >&2; exit 1
        fi
    fi

    # 1. 先下载并验证全部公钥。任何来源失败时，authorized_keys 保持原样。
    declare -a CLI_KEY_CONTENTS=()
    declare -a CLI_KEY_TAGS=()
    declare -a CLI_REMOTE_KEY_CONTENTS=()
    if [ -n "$CLI_GH_USER" ]; then
        [[ "$CLI_GH_USER" =~ ^[A-Za-z0-9-]+$ ]] || {
            echo -e "${ERROR} GitHub 用户名格式不正确"; exit 1;
        }
        if ! PUB_KEY=$(fetch_public_keys "https://github.com/${CLI_GH_USER}.keys"); then
            echo -e "${ERROR} 获取 GitHub 公钥失败"; exit 1
        fi
        CLI_KEY_CONTENTS+=("$PUB_KEY")
        CLI_KEY_TAGS+=("GitHub: ${CLI_GH_USER}")
        CLI_REMOTE_KEY_CONTENTS+=("$PUB_KEY")
    fi

    if [ -n "$CLI_KEY_URL" ]; then
        [[ "$CLI_KEY_URL" =~ ^https:// ]] || {
            echo -e "${ERROR} 公钥 URL 必须使用 https://"; exit 1;
        }
        if ! PUB_KEY=$(fetch_public_keys "${CLI_KEY_URL}"); then
            echo -e "${ERROR} 从 URL 获取公钥失败"; exit 1
        fi
        CLI_KEY_CONTENTS+=("$PUB_KEY")
        CLI_KEY_TAGS+=("自定义URL")
        CLI_REMOTE_KEY_CONTENTS+=("$PUB_KEY")
    fi

    if [ -n "$CLI_KEY_FILE" ]; then
        if [ -f "${CLI_KEY_FILE}" ]; then
            PUB_KEY=$(cat -- "${CLI_KEY_FILE}") || exit 1
            CLI_KEY_CONTENTS+=("$PUB_KEY")
            CLI_KEY_TAGS+=("本地文件导入")
        else
            echo -e "${ERROR} 找不到公钥文件 ${CLI_KEY_FILE}" && exit 1
        fi
    fi

    for PUB_KEY in "${CLI_KEY_CONTENTS[@]}"; do
        validate_public_key_content "$PUB_KEY" || {
            echo -e "${ERROR} 已取消导入，原 authorized_keys 未修改。"; exit 1;
        }
    done
    if [ "${#CLI_REMOTE_KEY_CONTENTS[@]}" -gt 0 ]; then
        CLI_REMOTE_KEY_BLOB="$(printf '%s\n' "${CLI_REMOTE_KEY_CONTENTS[@]}")"
        if ! verify_public_key_fingerprints "$CLI_REMOTE_KEY_BLOB" "${KEY_SH_EXPECTED_FINGERPRINTS:-}"; then
            printf '%b CLI 远程公钥导入必须提供完全匹配的 KEY_SH_EXPECTED_FINGERPRINTS。\n' "$ERROR" >&2
            exit 1
        fi
    fi

    # 2. 先准备端口事务；后续任何失败都会由 EXIT 恢复 SSH 和本轮防火墙变更。
    if [ -n "$CLI_PORT" ]; then
        if ! validate_ssh_port "$CLI_PORT"; then
            echo -e "${ERROR} 端口格式不正确！" && exit 1
        fi
        if ! current_port="$(require_sshd_val "Port" "22")"; then exit 1; fi
        if [ "$current_port" = "$CLI_PORT" ]; then
            echo -e "${INFO} SSH 已仅使用端口 ${CLI_PORT}，跳过端口修改。"
        else
            port_available_for_sshd "$current_port" "$CLI_PORT" || exit 1
            warn_or_abort_unmanaged_fw cli || exit 1
            prepare_port_access "$CLI_PORT" || exit 1
            if ! set_sshd_config "Port" "$CLI_PORT"; then
                rollback_port_fw_changes
                exit 1
            fi
            need_restart_sshd=1
            need_restart_f2b=1
        fi
    fi

    # 3. 所有来源在同一把锁下只提交一次。
    if [ "${#CLI_KEY_CONTENTS[@]}" -gt 0 ]; then
        declare -a CLI_KEY_BATCH=()
        local_i=0
        for local_i in "${!CLI_KEY_CONTENTS[@]}"; do
            CLI_KEY_BATCH+=("${CLI_KEY_CONTENTS[$local_i]}" "${CLI_KEY_TAGS[$local_i]}")
        done
        append_keys_with_meta_batch "$OVERWRITE" "${CLI_KEY_BATCH[@]}" || exit 1
        set_sshd_config "PubkeyAuthentication" "yes" || exit 1
        need_restart_sshd=1
    fi

    # 4. 禁用密码登录（写入全局默认；现有 Match 块仍可能另行覆盖）
    if [ "$CLI_DISABLE_PWD" -eq 1 ]; then
        publickey_login_ready "" || { printf '%b 未通过防误锁检查，拒绝禁用密码登录。\n' "$ERROR" >&2; exit 1; }
        warn_global_password_disable cli || exit 1
        set_sshd_config "PasswordAuthentication" "no" || exit 1
        set_sshd_config "ChallengeResponseAuthentication" "no" || exit 1
        set_sshd_config "KbdInteractiveAuthentication" "no" || exit 1
        need_restart_sshd=1
    fi

    # 统一重启 SSH 服务
    if [ "$need_restart_sshd" -eq 1 ]; then
        if restart_sshd; then
            reset_port_fw_tracking
            if [ -n "$CLI_PORT" ]; then
                if command -v ss &>/dev/null; then
                    echo -e "${INFO} 系统实际监听服务端口状态："
                    ss -tulpn | grep ssh || true
                fi
                echo -e "${WARN} 注意：如使用的是阿里云/腾讯云/AWS等，请务必在【云服务器安全组】中开放 TCP ${CLI_PORT} 端口！"
            fi
        else
            rollback_port_fw_changes
            exit 1
        fi
    fi

    # 仅在 SSH 端口修改成功后同步 Fail2Ban，避免两边配置不一致。
    if [ "$need_restart_f2b" -eq 1 ]; then
        sync_f2b_port_after_ssh_change "$CLI_PORT" || {
            printf '%b SSH 端口已变更，但 Fail2Ban 同步失败；请检查防护状态。\n' "$ERROR" >&2; exit 1;
        }
    fi

    exit 0
fi

# ============ 交互式主菜单 ============
while true; do
    clear
    show_status
    echo -e " ${GREEN}1.${RESET} 密钥登录管理"
    echo -e " ${GREEN}2.${RESET} 密码登录开关"
    echo -e " ${GREEN}3.${RESET} Fail2Ban防护"
    echo -e " ${GREEN}4.${RESET} SSH 端口修改"
    echo -e " ${GREEN}0.${RESET} 退出脚本"
    echo -e "${CYAN}============================================================${RESET}"
    read -rp "请输入选项 [0-4]: " choice || exit 0

    case "$choice" in
        1) install_key_menu ;;
        2) toggle_password_login ;;
        3) manage_fail2ban_menu ;;
        4) change_ssh_port ;;
        0) echo -e "\n感谢使用！"; exit 0 ;;
        *) echo -e "${ERROR} 无效选项，请重新选择！"; sleep 1 ;;
    esac
done
