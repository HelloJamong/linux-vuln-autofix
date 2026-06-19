#!/bin/bash
#===============================================================================
# Rocky Linux 8.10/9.x 보안 취약점 자동 조치 스크립트
#
# 설명: 취약점 점검 결과를 바탕으로 자동으로 보안 조치를 수행합니다.
# 사용법: sudo ./linux_vuln_fix.sh [check_result_file]
# 출력: hostname_YYMMDD_hhmmss_fix_result.txt 형식의 조치 결과 파일
# 버전: 26.05.01
#===============================================================================

# 버전 정보
VERSION="26.05.01"
SCRIPT_NAME="Linux Vulnerability Auto-Fix Script"

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 파일 경로
HOSTNAME=$(hostname)
DATE=$(date +%y%m%d)
TIME=$(date +%H%M%S)
FIX_RESULT_FILE="${HOSTNAME}_${DATE}_${TIME}_fix_result.txt"
CHECK_SCRIPT="./linux_vuln_check.sh"
CHECK_RESULT_FILE=""
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
QUIET=false
NO_COLOR=false
DRY_RUN=false

# OS capability profile
OS_ID="unknown"
OS_VERSION_ID="unknown"
OS_PRETTY_NAME="unknown"
OS_MAJOR_VERSION="unknown"
CAP_SYSTEMCTL="false"
CAP_SYSTEMD_RUNTIME="false"
CAP_AUTHSELECT="false"
CAP_FAILLOCK_CONF="none"
CAP_PAM_AUTH_FILES="none"
CAP_FIREWALL_BACKEND="none"
CAP_PACKAGE_MANAGER="unknown"
CAP_TIME_SYNC="none"
CAP_CRYPTO_POLICIES="false"
CAP_SELINUX="unknown"
CAP_NETWORK_TOOL="unknown"

# 백업 디렉토리
BACKUP_DIR="/var/backup/security_fix_${DATE}_${TIME}"

# 조치 통계
TOTAL_FIXES=0
SUCCESS_FIXES=0
FAILED_FIXES=0
SKIPPED_FIXES=0
PLANNED_FIXES=0
MANUAL_FIXES=0

#===============================================================================
# 기본 함수들
#===============================================================================

# 운영체제 환경 확인
check_os_environment() {
    [ "$QUIET" = true ] || echo -e "${BLUE}Checking operating system environment...${NC}"

    # /etc/os-release 파일 확인
    if [ ! -f /etc/os-release ]; then
        echo -e "${RED}[ERROR] /etc/os-release file not found.${NC}"
        echo -e "${RED}[ERROR] This script is designed for Rocky Linux 8.10 or 9.x.${NC}"
        exit 1
    fi

    # OS 정보 읽기
    source /etc/os-release

    # OS ID 확인 (rhel 또는 rocky)
    if [ "$ID" != "rhel" ] && [ "$ID" != "rocky" ]; then
        echo -e "${RED}[ERROR] Unsupported operating system: $ID${NC}"
        echo -e "${RED}[ERROR] This script is designed for Rocky Linux 8.10 or 9.x.${NC}"
        echo -e "${RED}Current OS: ${NAME:-Unknown}${NC}"
        echo ""
        exit 1
    fi

    # 버전 확인 (Rocky/RHEL 8.10 또는 9.x)
    local major_version=$(echo "$VERSION_ID" | cut -d. -f1)
    OS_ID="${ID:-unknown}"
    OS_VERSION_ID="${VERSION_ID:-unknown}"
    OS_PRETTY_NAME="${PRETTY_NAME:-${NAME:-unknown}}"
    OS_MAJOR_VERSION="$major_version"
    if [ "$major_version" = "8" ] && [ "$VERSION_ID" != "8.10" ]; then
        echo -e "${RED}[ERROR] Unsupported OS version: $VERSION_ID${NC}"
        echo -e "${RED}[ERROR] This script is designed for Rocky Linux 8.10 or 9.x.${NC}"
        echo -e "${RED}Current OS: ${PRETTY_NAME:-Unknown}${NC}"
        echo ""
        exit 1
    elif [ "$major_version" != "8" ] && [ "$major_version" != "9" ]; then
        echo -e "${RED}[ERROR] Unsupported OS version: $VERSION_ID${NC}"
        echo -e "${RED}[ERROR] This script is designed for Rocky Linux 8.10 or 9.x.${NC}"
        echo -e "${RED}Current OS: ${PRETTY_NAME:-Unknown}${NC}"
        echo ""
        exit 1
    fi

    [ "$QUIET" = true ] || echo -e "${GREEN}Operating system check passed: ${PRETTY_NAME:-$NAME $VERSION_ID}${NC}"
}

# OS 기능 감지
detect_os_capabilities() {
    if command -v systemctl >/dev/null 2>&1; then
        CAP_SYSTEMCTL="true"
    fi
    if [ -d /run/systemd/system ]; then
        CAP_SYSTEMD_RUNTIME="true"
    fi
    if command -v authselect >/dev/null 2>&1; then
        CAP_AUTHSELECT="true"
    fi
    if [ -f /etc/security/faillock.conf ]; then
        CAP_FAILLOCK_CONF="/etc/security/faillock.conf"
    fi

    local pam_files=()
    [ -f /etc/pam.d/system-auth ] && pam_files+=("/etc/pam.d/system-auth")
    [ -f /etc/pam.d/password-auth ] && pam_files+=("/etc/pam.d/password-auth")
    if [ ${#pam_files[@]} -gt 0 ]; then
        CAP_PAM_AUTH_FILES=$(IFS=,; echo "${pam_files[*]}")
    fi

    if command -v firewall-cmd >/dev/null 2>&1; then
        CAP_FIREWALL_BACKEND="firewalld"
    elif command -v nft >/dev/null 2>&1; then
        CAP_FIREWALL_BACKEND="nftables"
    elif command -v iptables >/dev/null 2>&1; then
        CAP_FIREWALL_BACKEND="iptables"
    fi

    if command -v dnf >/dev/null 2>&1; then
        CAP_PACKAGE_MANAGER="dnf"
    elif command -v yum >/dev/null 2>&1; then
        CAP_PACKAGE_MANAGER="yum"
    elif command -v rpm >/dev/null 2>&1; then
        CAP_PACKAGE_MANAGER="rpm"
    fi

    local time_services=()
    command -v chronyd >/dev/null 2>&1 || [ -f /usr/sbin/chronyd ] && time_services+=("chronyd")
    command -v ntpd >/dev/null 2>&1 || [ -f /usr/sbin/ntpd ] && time_services+=("ntpd")
    if command -v timedatectl >/dev/null 2>&1; then
        time_services+=("timedatectl")
    fi
    if [ ${#time_services[@]} -gt 0 ]; then
        CAP_TIME_SYNC=$(IFS=,; echo "${time_services[*]}")
    fi

    if command -v update-crypto-policies >/dev/null 2>&1; then
        CAP_CRYPTO_POLICIES="true"
    fi
    if command -v getenforce >/dev/null 2>&1; then
        CAP_SELINUX=$(getenforce 2>/dev/null || echo "unknown")
    fi
    if command -v ss >/dev/null 2>&1; then
        CAP_NETWORK_TOOL="ss"
    elif command -v netstat >/dev/null 2>&1; then
        CAP_NETWORK_TOOL="netstat"
    fi

    if [ "$QUIET" != true ]; then
        echo -e "${BLUE}Capability profile: systemctl=${CAP_SYSTEMCTL}, systemd_runtime=${CAP_SYSTEMD_RUNTIME}, authselect=${CAP_AUTHSELECT}, firewall=${CAP_FIREWALL_BACKEND}, package_manager=${CAP_PACKAGE_MANAGER}${NC}"
    fi
}

# Root 권한 확인
check_root() {
    if [ "$EUID" -ne 0 ]; then
        if [ "$DRY_RUN" = true ]; then
            [ "$QUIET" = true ] || echo -e "${YELLOW}[WARNING] Dry-run mode is running without root privileges.${NC}"
            return
        fi
        echo -e "${RED}[ERROR] This script must be run as root.${NC}"
        exit 1
    fi
}

# 사용법 출력
usage() {
    local exit_code="${1:-0}"
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -f, --file FILE     Use existing check result file (skip new check)
    -o, --output FILE   Write remediation result to FILE
    --dry-run           Show planned remediation without changing the system
    -q, --quiet         Suppress progress output
    --no-color          Disable colored terminal output
    -h, --help          Display this help message
    -v, --version       Show version information

Description:
    This script automatically remediates security vulnerabilities based on
    the vulnerability check results.

Examples:
    # Run new check and fix
    sudo $0

    # Use existing check result
    sudo $0 -f hostname_261127_143022_result.txt

EOF
    exit "$exit_code"
}

# 버전 정보 출력
show_version() {
    echo "$SCRIPT_NAME v$VERSION"
    echo "Rocky Linux 8.10/9.x Security Vulnerability Auto-Remediation"
    echo ""
    echo "For more information, see CHANGELOG.md"
    exit 0
}

# 파라미터 파싱
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--file)
                CHECK_RESULT_FILE="$2"
                shift 2
                ;;
            -o|--output)
                FIX_RESULT_FILE="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            --no-color)
                NO_COLOR=true
                shift
                ;;
            -h|--help)
                usage 0
                ;;
            -v|--version)
                show_version
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                usage 1
                ;;
        esac
    done

    if [ "$NO_COLOR" = true ]; then
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        NC=''
    fi
}

# 백업 디렉토리 생성
create_backup_dir() {
    if [ "$DRY_RUN" = true ]; then
        [ "$QUIET" = true ] || echo -e "${BLUE}[DRY-RUN] Backup directory would be created: $BACKUP_DIR${NC}"
        return
    fi
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        [ "$QUIET" = true ] || echo -e "${BLUE}[INFO] Backup directory created: $BACKUP_DIR${NC}"
    fi
}

# 파일 백업
backup_file() {
    local file="$1"
    if [ "$DRY_RUN" = true ]; then
        [ "$QUIET" = true ] || echo -e "${BLUE}[DRY-RUN] Would back up $file${NC}"
        return
    fi
    if [ -f "$file" ]; then
        cp -p "$file" "$BACKUP_DIR/$(basename "$file").bak"
        [ "$QUIET" = true ] || echo -e "${BLUE}[BACKUP] $file${NC}"
    fi
}

# 결과 파일 초기화
init_fix_result_file() {
    echo "================================================================================" > "$FIX_RESULT_FILE"
    echo "Security Vulnerability Auto-Remediation Report" >> "$FIX_RESULT_FILE"
    echo "================================================================================" >> "$FIX_RESULT_FILE"
    echo "Remediation Date: $(date '+%Y-%m-%d %H:%M:%S')" >> "$FIX_RESULT_FILE"
    echo "Hostname: $HOSTNAME" >> "$FIX_RESULT_FILE"
    echo "OS Version: $(cat /etc/redhat-release 2>/dev/null || echo 'Unknown')" >> "$FIX_RESULT_FILE"
    echo "OS ID: $OS_ID" >> "$FIX_RESULT_FILE"
    echo "OS VERSION_ID: $OS_VERSION_ID" >> "$FIX_RESULT_FILE"
    echo "OS Major Version: $OS_MAJOR_VERSION" >> "$FIX_RESULT_FILE"
    echo "Capability systemctl: $CAP_SYSTEMCTL" >> "$FIX_RESULT_FILE"
    echo "Capability systemd_runtime: $CAP_SYSTEMD_RUNTIME" >> "$FIX_RESULT_FILE"
    echo "Capability authselect: $CAP_AUTHSELECT" >> "$FIX_RESULT_FILE"
    echo "Capability faillock_conf: $CAP_FAILLOCK_CONF" >> "$FIX_RESULT_FILE"
    echo "Capability pam_auth_files: $CAP_PAM_AUTH_FILES" >> "$FIX_RESULT_FILE"
    echo "Capability firewall_backend: $CAP_FIREWALL_BACKEND" >> "$FIX_RESULT_FILE"
    echo "Capability package_manager: $CAP_PACKAGE_MANAGER" >> "$FIX_RESULT_FILE"
    echo "Capability time_sync: $CAP_TIME_SYNC" >> "$FIX_RESULT_FILE"
    echo "Capability crypto_policies: $CAP_CRYPTO_POLICIES" >> "$FIX_RESULT_FILE"
    echo "Capability selinux: $CAP_SELINUX" >> "$FIX_RESULT_FILE"
    echo "Capability network_tool: $CAP_NETWORK_TOOL" >> "$FIX_RESULT_FILE"
    echo "Backup Directory: $BACKUP_DIR" >> "$FIX_RESULT_FILE"
    echo "Mode: $([ "$DRY_RUN" = true ] && echo "DRY-RUN" || echo "APPLY")" >> "$FIX_RESULT_FILE"
    echo "================================================================================" >> "$FIX_RESULT_FILE"
    echo "" >> "$FIX_RESULT_FILE"
}

# 조치 결과 기록
log_fix_result() {
    local check_id="$1"
    local check_name="$2"
    local status="$3"  # SUCCESS, FAILED, SKIPPED
    local detail="$4"

    echo "[${check_id}] ${check_name}" >> "$FIX_RESULT_FILE"
    echo "Status: ${status}" >> "$FIX_RESULT_FILE"
    echo "Detail: ${detail}" >> "$FIX_RESULT_FILE"
    echo "--------------------------------------------------------------------------------" >> "$FIX_RESULT_FILE"

    # 화면 출력
    case "$status" in
        "SUCCESS")
            [ "$QUIET" = true ] || echo -e "${GREEN}[SUCCESS]${NC} [${check_id}] ${check_name}"
            ((SUCCESS_FIXES++))
            ;;
        "FAILED")
            [ "$QUIET" = true ] || echo -e "${RED}[FAILED]${NC} [${check_id}] ${check_name}"
            ((FAILED_FIXES++))
            ;;
        "SKIPPED")
            [ "$QUIET" = true ] || echo -e "${YELLOW}[SKIPPED]${NC} [${check_id}] ${check_name}"
            ((SKIPPED_FIXES++))
            ;;
        "PLANNED")
            [ "$QUIET" = true ] || echo -e "${BLUE}[PLANNED]${NC} [${check_id}] ${check_name}"
            ((PLANNED_FIXES++))
            ;;
        "MANUAL")
            [ "$QUIET" = true ] || echo -e "${YELLOW}[MANUAL]${NC} [${check_id}] ${check_name}"
            ((MANUAL_FIXES++))
            ;;
    esac
    ((TOTAL_FIXES++))
}

# 점검 결과에서 FAIL 항목 확인
is_failed() {
    local check_id="$1"
    if [ -z "$CHECK_RESULT_FILE" ] || [ ! -f "$CHECK_RESULT_FILE" ]; then
        # 점검 결과 파일이 없으면 모든 항목 조치
        return 0
    fi

    grep -A 1 "^\[${check_id}\]" "$CHECK_RESULT_FILE" | grep -q "Status: FAIL"
    return $?
}

#===============================================================================
# 조치 함수들 (U-01 ~ U-72)
#===============================================================================

# U-01: root 계정 원격 접속 제한
fix_u01() {
    local check_id="U-01"
    local check_name="Root Remote Login Restriction"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    local sshd_config="/etc/ssh/sshd_config"
    if [ ! -f "$sshd_config" ]; then
        log_fix_result "$check_id" "$check_name" "FAILED" "sshd_config not found"
        return
    fi

    backup_file "$sshd_config"

    # PermitRootLogin 설정 변경
    if grep -q "^[[:space:]]*PermitRootLogin" "$sshd_config"; then
        sed -i 's/^[[:space:]]*PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
    else
        echo "PermitRootLogin no" >> "$sshd_config"
    fi

    # sshd 재시작
    systemctl restart sshd

    if [ $? -eq 0 ]; then
        log_fix_result "$check_id" "$check_name" "SUCCESS" "PermitRootLogin set to no, sshd restarted"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "Failed to restart sshd"
    fi
}

# U-02: 패스워드 복잡도 설정
fix_u02() {
    local check_id="U-02"
    local check_name="Password Complexity Policy"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    local pwquality_conf="/etc/security/pwquality.conf"
    if [ ! -f "$pwquality_conf" ]; then
        log_fix_result "$check_id" "$check_name" "FAILED" "pwquality.conf not found"
        return
    fi

    backup_file "$pwquality_conf"

    # 패스워드 복잡도 설정
    sed -i '/^[[:space:]]*minlen/d' "$pwquality_conf"
    sed -i '/^[[:space:]]*dcredit/d' "$pwquality_conf"
    sed -i '/^[[:space:]]*ucredit/d' "$pwquality_conf"
    sed -i '/^[[:space:]]*lcredit/d' "$pwquality_conf"
    sed -i '/^[[:space:]]*ocredit/d' "$pwquality_conf"

    cat >> "$pwquality_conf" << 'EOF'

# Password complexity requirements
minlen = 8
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Password complexity policy configured"
}

# U-03: 계정 잠금 임계값 설정
fix_u03() {
    local check_id="U-03"
    local check_name="Account Lockout Policy"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    local faillock_conf="/etc/security/faillock.conf"
    if [ ! -f "$faillock_conf" ]; then
        log_fix_result "$check_id" "$check_name" "FAILED" "faillock.conf not found"
        return
    fi

    backup_file "$faillock_conf"

    # 계정 잠금 설정
    sed -i '/^[[:space:]]*deny/d' "$faillock_conf"
    sed -i '/^[[:space:]]*unlock_time/d' "$faillock_conf"

    cat >> "$faillock_conf" << 'EOF'

# Account lockout policy
deny = 5
unlock_time = 600
EOF

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Account lockout policy configured (5 attempts, 600s unlock time)"
}

# U-04: 패스워드 파일 보호
fix_u04() {
    local check_id="U-04"
    local check_name="Password File Protection"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # /etc/passwd 권한 설정
    chmod 644 /etc/passwd
    chown root:root /etc/passwd

    # /etc/shadow 권한 설정
    if [ -f /etc/shadow ]; then
        chmod 000 /etc/shadow
        chown root:root /etc/shadow
    fi

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Password file permissions set correctly"
}

# U-05: root 외 UID 0 금지
fix_u05() {
    local check_id="U-05"
    local check_name="Root UID Uniqueness"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # UID 0인 계정 찾기 (root 제외)
    local uid0_accounts=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)

    if [ -z "$uid0_accounts" ]; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "No UID 0 accounts found (except root)"
        return
    fi

    # 수동 조치 필요 (자동 삭제는 위험)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. UID 0 accounts found: $uid0_accounts"
}

# U-06: 파일 및 디렉토리 소유자 설정
fix_u06() {
    local check_id="U-06"
    local check_name="File and Directory Ownership"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 소유자가 없는 파일 찾기 및 root로 변경
    local ownerless_files=$(find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -20)

    if [ -z "$ownerless_files" ]; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "No ownerless files found"
        return
    fi

    # 수동 조치 권장 (자동으로 root 소유권 부여는 위험할 수 있음)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Found ownerless files (first 20 shown in check result)"
}

# U-07: /etc/passwd 파일 소유자 및 권한 설정
fix_u07() {
    local check_id="U-07"
    local check_name="/etc/passwd Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    chmod 644 /etc/passwd
    chown root:root /etc/passwd

    log_fix_result "$check_id" "$check_name" "SUCCESS" "/etc/passwd permissions set to 644, owner set to root"
}

# U-08: /etc/shadow 파일 소유자 및 권한 설정
fix_u08() {
    local check_id="U-08"
    local check_name="/etc/shadow Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    if [ -f /etc/shadow ]; then
        chmod 000 /etc/shadow
        chown root:root /etc/shadow
        log_fix_result "$check_id" "$check_name" "SUCCESS" "/etc/shadow permissions set to 000, owner set to root"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "/etc/shadow not found"
    fi
}

# U-09: /etc/hosts 파일 소유자 및 권한 설정
fix_u09() {
    local check_id="U-09"
    local check_name="/etc/hosts Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    chmod 644 /etc/hosts
    chown root:root /etc/hosts

    log_fix_result "$check_id" "$check_name" "SUCCESS" "/etc/hosts permissions set to 644, owner set to root"
}

# U-10: /etc/xinetd.conf 파일 소유자 및 권한 설정
fix_u10() {
    local check_id="U-10"
    local check_name="/etc/xinetd.conf Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    if [ -f /etc/xinetd.conf ]; then
        chmod 644 /etc/xinetd.conf
        chown root:root /etc/xinetd.conf
        log_fix_result "$check_id" "$check_name" "SUCCESS" "/etc/xinetd.conf permissions set to 644, owner set to root"
    else
        log_fix_result "$check_id" "$check_name" "SKIPPED" "/etc/xinetd.conf does not exist"
    fi
}

# U-11: /etc/syslog.conf 파일 소유자 및 권한 설정
fix_u11() {
    local check_id="U-11"
    local check_name="Syslog Config Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    local fixed=0

    if [ -f /etc/rsyslog.conf ]; then
        chmod 644 /etc/rsyslog.conf
        chown root:root /etc/rsyslog.conf
        fixed=1
    fi

    if [ -f /etc/syslog.conf ]; then
        chmod 644 /etc/syslog.conf
        chown root:root /etc/syslog.conf
        fixed=1
    fi

    if [ $fixed -eq 1 ]; then
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Syslog config permissions set to 644, owner set to root"
    else
        log_fix_result "$check_id" "$check_name" "SKIPPED" "No syslog config files found"
    fi
}

# U-12: /etc/services 파일 소유자 및 권한 설정
fix_u12() {
    local check_id="U-12"
    local check_name="/etc/services Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    chmod 644 /etc/services
    chown root:root /etc/services

    log_fix_result "$check_id" "$check_name" "SUCCESS" "/etc/services permissions set to 644, owner set to root"
}

# U-13: SUID, SGID 설정 파일 점검
fix_u13() {
    local check_id="U-13"
    local check_name="SUID/SGID Files Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (SUID/SGID 파일 자동 제거는 위험)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Review SUID/SGID files and remove unnecessary ones"
}

# U-14: 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
fix_u14() {
    local check_id="U-14"
    local check_name="User Startup Files Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # /etc/profile 권한 설정
    if [ -f /etc/profile ]; then
        chmod 644 /etc/profile
        chown root:root /etc/profile
    fi

    # /etc/bashrc 권한 설정
    if [ -f /etc/bashrc ]; then
        chmod 644 /etc/bashrc
        chown root:root /etc/bashrc
    fi

    # /etc/environment 권한 설정
    if [ -f /etc/environment ]; then
        chmod 644 /etc/environment
        chown root:root /etc/environment
    fi

    log_fix_result "$check_id" "$check_name" "SUCCESS" "System startup files permissions set correctly"
}

# U-15: world writable 파일 점검
fix_u15() {
    local check_id="U-15"
    local check_name="World Writable Files Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (world writable 파일 자동 변경은 위험)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Review world writable files and adjust permissions"
}

# U-16: /dev 디렉토리 내 존재하지 않는 device 파일 점검
fix_u16() {
    local check_id="U-16"
    local check_name="Unusual Device Files Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Review unusual device files in /dev"
}

# U-17: $HOME/.rhosts, hosts.equiv 사용 금지
fix_u17() {
    local check_id="U-17"
    local check_name="Rhosts and hosts.equiv Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # /etc/hosts.equiv 삭제
    if [ -f /etc/hosts.equiv ]; then
        backup_file /etc/hosts.equiv
        rm -f /etc/hosts.equiv
    fi

    # 사용자 홈 디렉토리의 .rhosts 파일 삭제
    for home_dir in /home/*; do
        if [ -f "$home_dir/.rhosts" ]; then
            backup_file "$home_dir/.rhosts"
            rm -f "$home_dir/.rhosts"
        fi
    done

    if [ -f /root/.rhosts ]; then
        backup_file /root/.rhosts
        rm -f /root/.rhosts
    fi

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Removed rhosts and hosts.equiv files"
}

# U-18: 접속 IP 및 포트 제한
fix_u18() {
    local check_id="U-18"
    local check_name="Network Access Control"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (방화벽 규칙은 환경에 따라 다름)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Configure firewall rules based on requirements"
}

# U-19: Finger 서비스 비활성화
fix_u19() {
    local check_id="U-19"
    local check_name="Finger Service Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # finger 서비스 중지 및 비활성화
    systemctl stop finger 2>/dev/null
    systemctl disable finger 2>/dev/null

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Finger service disabled"
}

# U-20: Anonymous FTP 비활성화
fix_u20() {
    local check_id="U-20"
    local check_name="Anonymous FTP Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # vsftpd 설정 파일 수정
    local vsftpd_conf="/etc/vsftpd/vsftpd.conf"
    if [ -f "$vsftpd_conf" ]; then
        backup_file "$vsftpd_conf"
        sed -i 's/^anonymous_enable=YES/anonymous_enable=NO/' "$vsftpd_conf"
        systemctl restart vsftpd 2>/dev/null
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Anonymous FTP disabled"
    else
        log_fix_result "$check_id" "$check_name" "SKIPPED" "vsftpd not installed"
    fi
}

# U-21: r 계열 서비스 비활성화
fix_u21() {
    local check_id="U-21"
    local check_name="R-services Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # r 계열 서비스 비활성화
    for service in rsh rlogin rexec; do
        systemctl stop $service 2>/dev/null
        systemctl disable $service 2>/dev/null
    done

    log_fix_result "$check_id" "$check_name" "SUCCESS" "R-services disabled"
}

# U-22: cron 파일 소유자 및 권한 설정
fix_u22() {
    local check_id="U-22"
    local check_name="Cron Files Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # cron 관련 파일 권한 설정
    if [ -f /etc/crontab ]; then
        chmod 640 /etc/crontab
        chown root:root /etc/crontab
    fi

    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
        if [ -d "$dir" ]; then
            chmod 640 "$dir"/*  2>/dev/null
            chown root:root "$dir"/* 2>/dev/null
        fi
    done

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Cron files permissions set correctly"
}

# U-23: DoS 공격에 취약한 서비스 비활성화
fix_u23() {
    local check_id="U-23"
    local check_name="DoS Vulnerable Services Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # DoS 취약 서비스 비활성화
    for service in echo discard daytime chargen; do
        systemctl stop $service 2>/dev/null
        systemctl disable $service 2>/dev/null
    done

    log_fix_result "$check_id" "$check_name" "SUCCESS" "DoS vulnerable services disabled"
}

# U-24: NFS 서비스 비활성화
fix_u24() {
    local check_id="U-24"
    local check_name="NFS Service Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # NFS 관련 서비스 비활성화
    for service in nfs-server nfs-client rpcbind; do
        systemctl stop $service 2>/dev/null
        systemctl disable $service 2>/dev/null
    done

    log_fix_result "$check_id" "$check_name" "SUCCESS" "NFS services disabled"
}

# U-25: NFS 접근 통제
fix_u25() {
    local check_id="U-25"
    local check_name="NFS Access Control"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (/etc/exports 설정은 환경에 따라 다름)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Configure /etc/exports with proper access controls"
}

# U-26: automountd 제거
fix_u26() {
    local check_id="U-26"
    local check_name="Automountd Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    systemctl stop autofs 2>/dev/null
    systemctl disable autofs 2>/dev/null

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Automountd disabled"
}

# U-27: RPC 서비스 확인
fix_u27() {
    local check_id="U-27"
    local check_name="RPC Services Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 불필요한 RPC 서비스 비활성화
    systemctl stop rpcbind 2>/dev/null
    systemctl disable rpcbind 2>/dev/null

    log_fix_result "$check_id" "$check_name" "SUCCESS" "RPC services disabled"
}

# U-28: NIS, NIS+ 점검
fix_u28() {
    local check_id="U-28"
    local check_name="NIS/NIS+ Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # NIS 서비스 비활성화
    for service in ypserv ypbind; do
        systemctl stop $service 2>/dev/null
        systemctl disable $service 2>/dev/null
    done

    log_fix_result "$check_id" "$check_name" "SUCCESS" "NIS/NIS+ services disabled"
}

# U-29: tftp, talk 서비스 비활성화
fix_u29() {
    local check_id="U-29"
    local check_name="TFTP/Talk Services Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # tftp, talk 서비스 비활성화
    for service in tftp talk ntalk; do
        systemctl stop $service 2>/dev/null
        systemctl disable $service 2>/dev/null
    done

    log_fix_result "$check_id" "$check_name" "SUCCESS" "TFTP/Talk services disabled"
}

# U-30: Sendmail 버전 점검
fix_u30() {
    local check_id="U-30"
    local check_name="Sendmail Version Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (버전 업데이트)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Update sendmail to the latest version"
}

# U-31: 스팸 메일 릴레이 제한
fix_u31() {
    local check_id="U-31"
    local check_name="Mail Relay Restriction"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (메일 서버 설정은 환경에 따라 다름)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Configure mail server to prevent relay"
}

# U-32: 일반사용자의 Sendmail 실행 방지
fix_u32() {
    local check_id="U-32"
    local check_name="Sendmail Execution Restriction"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # sendmail 실행 파일 권한 변경
    if [ -f /usr/sbin/sendmail ]; then
        chmod 4750 /usr/sbin/sendmail
        chown root:mail /usr/sbin/sendmail
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Sendmail execution restricted"
    else
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Sendmail not installed"
    fi
}

# U-33: DNS 보안 버전 패치
fix_u33() {
    local check_id="U-33"
    local check_name="DNS Version Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (DNS 버전 업데이트)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Update DNS software to the latest version"
}

# U-34: DNS Zone Transfer 설정
fix_u34() {
    local check_id="U-34"
    local check_name="DNS Zone Transfer Restriction"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (DNS 설정은 환경에 따라 다름)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Configure DNS zone transfer restrictions"
}

# U-35: 웹서비스 디렉토리 리스팅 제거
fix_u35() {
    local check_id="U-35"
    local check_name="Web Directory Listing Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # Apache 설정 파일 수정
    local httpd_conf="/etc/httpd/conf/httpd.conf"
    if [ -f "$httpd_conf" ]; then
        backup_file "$httpd_conf"
        sed -i 's/Options Indexes/Options -Indexes/' "$httpd_conf"
        systemctl restart httpd 2>/dev/null
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Web directory listing disabled"
    else
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Apache not installed"
    fi
}

# U-36: 웹서비스 웹 프로세스 권한 제한
fix_u36() {
    local check_id="U-36"
    local check_name="Web Process User Restriction"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (웹 서버 사용자 설정)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Ensure web server runs as non-root user"
}

# U-37: 웹서비스 상위 디렉토리 접근 금지
fix_u37() {
    local check_id="U-37"
    local check_name="Web Parent Directory Access Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # Apache 설정 파일 수정
    local httpd_conf="/etc/httpd/conf/httpd.conf"
    if [ -f "$httpd_conf" ]; then
        backup_file "$httpd_conf"
        sed -i 's/AllowOverride All/AllowOverride None/' "$httpd_conf"
        systemctl restart httpd 2>/dev/null
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Web parent directory access disabled"
    else
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Apache not installed"
    fi
}

# U-38: 웹서비스 불필요한 파일 제거
fix_u38() {
    local check_id="U-38"
    local check_name="Web Unnecessary Files Removal"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (매뉴얼, 샘플 파일 제거)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Remove unnecessary manual and sample files"
}

# U-39: 웹서비스 링크 사용 금지
fix_u39() {
    local check_id="U-39"
    local check_name="Web Symbolic Link Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # Apache 설정 파일 수정
    local httpd_conf="/etc/httpd/conf/httpd.conf"
    if [ -f "$httpd_conf" ]; then
        backup_file "$httpd_conf"
        sed -i 's/Options FollowSymLinks/Options -FollowSymLinks/' "$httpd_conf"
        systemctl restart httpd 2>/dev/null
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Web symbolic links disabled"
    else
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Apache not installed"
    fi
}

# U-40: 웹서비스 파일 업로드 및 다운로드 제한
fix_u40() {
    local check_id="U-40"
    local check_name="Web File Upload/Download Restriction"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (파일 크기 제한 설정)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Configure file upload/download size limits"
}

# U-41: 웹서비스 웹 로그 파일 관리
fix_u41() {
    local check_id="U-41"
    local check_name="Web Log Management"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (로그 로테이션 설정)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Configure web log rotation"
}

# U-42: 웹서비스 웹 프로세스 및 파일 권한 제한
fix_u42() {
    local check_id="U-42"
    local check_name="Web Process and File Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 웹 디렉토리 권한 설정
    local web_dir="/var/www/html"
    if [ -d "$web_dir" ]; then
        find "$web_dir" -type d -exec chmod 755 {} \;
        find "$web_dir" -type f -exec chmod 644 {} \;
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Web directory permissions set correctly"
    else
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Web directory not found"
    fi
}

# U-43: 최신 보안패치 및 벤더 권고사항 적용
fix_u43() {
    local check_id="U-43"
    local check_name="Security Patches Update"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 권장 (자동 업데이트는 위험할 수 있음)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Apply latest security patches (dnf update)"
}

# U-44: 로그의 정기적 검토 및 보고
fix_u44() {
    local check_id="U-44"
    local check_name="Log Review Configuration"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (로그 검토 정책 수립)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Establish log review policy"
}

# U-45: 정책에 따른 시스템 로깅 설정
fix_u45() {
    local check_id="U-45"
    local check_name="System Logging Configuration"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # rsyslog 활성화
    systemctl enable rsyslog
    systemctl start rsyslog

    log_fix_result "$check_id" "$check_name" "SUCCESS" "System logging enabled"
}

# U-46: 원격 로그 서버 설정
fix_u46() {
    local check_id="U-46"
    local check_name="Remote Log Server Configuration"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (원격 로그 서버 정보 필요)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Configure remote log server"
}

# U-47: 정책에 따른 시스템 로그 기록
fix_u47() {
    local check_id="U-47"
    local check_name="System Log Recording Policy"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # rsyslog 설정 확인 및 활성화
    systemctl enable rsyslog
    systemctl start rsyslog

    log_fix_result "$check_id" "$check_name" "SUCCESS" "System logging service enabled"
}

# U-48: 로그 파일 접근 권한 설정
fix_u48() {
    local check_id="U-48"
    local check_name="Log File Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 로그 파일 권한 설정
    if [ -d /var/log ]; then
        chmod 640 /var/log/messages 2>/dev/null
        chmod 640 /var/log/secure 2>/dev/null
        chmod 640 /var/log/maillog 2>/dev/null
        chmod 640 /var/log/cron 2>/dev/null
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Log file permissions set to 640"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "/var/log directory not found"
    fi
}

# U-49: su 명령어 접근 제한
fix_u49() {
    local check_id="U-49"
    local check_name="SU Command Restriction"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # wheel 그룹에 su 제한
    local pam_su="/etc/pam.d/su"
    if [ -f "$pam_su" ]; then
        backup_file "$pam_su"

        # auth required pam_wheel.so use_uid 라인이 없으면 추가
        if ! grep -q "^auth.*required.*pam_wheel.so.*use_uid" "$pam_su"; then
            sed -i '/^#auth.*required.*pam_wheel.so.*use_uid/a auth required pam_wheel.so use_uid' "$pam_su"
            log_fix_result "$check_id" "$check_name" "SUCCESS" "SU command restricted to wheel group"
        else
            log_fix_result "$check_id" "$check_name" "SKIPPED" "SU restriction already configured"
        fi
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "/etc/pam.d/su not found"
    fi
}

# U-50: 패스워드 최소 길이 설정
fix_u50() {
    local check_id="U-50"
    local check_name="Password Minimum Length"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    local pwquality_conf="/etc/security/pwquality.conf"
    if [ -f "$pwquality_conf" ]; then
        backup_file "$pwquality_conf"
        sed -i '/^[[:space:]]*minlen/d' "$pwquality_conf"
        echo "minlen = 8" >> "$pwquality_conf"
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Password minimum length set to 8"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "pwquality.conf not found"
    fi
}

# U-51: 패스워드 최대 사용 기간 설정
fix_u51() {
    local check_id="U-51"
    local check_name="Password Maximum Age"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    local login_defs="/etc/login.defs"
    if [ -f "$login_defs" ]; then
        backup_file "$login_defs"
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' "$login_defs"
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Password maximum age set to 90 days"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "login.defs not found"
    fi
}

# U-52: 패스워드 최소 사용 기간 설정
fix_u52() {
    local check_id="U-52"
    local check_name="Password Minimum Age"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    local login_defs="/etc/login.defs"
    if [ -f "$login_defs" ]; then
        backup_file "$login_defs"
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' "$login_defs"
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Password minimum age set to 1 day"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "login.defs not found"
    fi
}

# U-53: 불필요한 계정 제거
fix_u53() {
    local check_id="U-53"
    local check_name="Unnecessary Accounts Removal"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (계정 삭제는 신중해야 함)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Review and remove unnecessary accounts"
}

# U-54: 관리자 그룹에 최소한의 계정 포함
fix_u54() {
    local check_id="U-54"
    local check_name="Admin Group Minimization"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Review admin group membership"
}

# U-55: 계정이 존재하지 않는 GID 금지
fix_u55() {
    local check_id="U-55"
    local check_name="Invalid GID Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Remove invalid GIDs from /etc/group"
}

# U-56: 동일한 UID 금지
fix_u56() {
    local check_id="U-56"
    local check_name="Duplicate UID Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (UID 변경은 신중해야 함)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Resolve duplicate UIDs"
}

# U-57: 사용자 shell 점검
fix_u57() {
    local check_id="U-57"
    local check_name="User Shell Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Review user shells in /etc/passwd"
}

# U-58: Session Timeout 설정
fix_u58() {
    local check_id="U-58"
    local check_name="Session Timeout Configuration"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # /etc/profile에 TMOUT 설정
    local profile="/etc/profile"
    if [ -f "$profile" ]; then
        backup_file "$profile"

        if ! grep -q "^TMOUT=" "$profile"; then
            echo "TMOUT=600" >> "$profile"
            echo "export TMOUT" >> "$profile"
            log_fix_result "$check_id" "$check_name" "SUCCESS" "Session timeout set to 600 seconds"
        else
            log_fix_result "$check_id" "$check_name" "SKIPPED" "Session timeout already configured"
        fi
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "/etc/profile not found"
    fi
}

# U-59: Firewall 설정
fix_u59() {
    local check_id="U-59"
    local check_name="Firewall Configuration"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # firewalld 활성화
    systemctl enable firewalld
    systemctl start firewalld

    if [ $? -eq 0 ]; then
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Firewall enabled"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "Failed to enable firewall"
    fi
}

# U-60: 패스워드 암호화 저장
fix_u60() {
    local check_id="U-60"
    local check_name="Password Encryption"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # SHA512 암호화 설정
    authselect select sssd with-sha512 --force 2>/dev/null

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Password encryption configured"
}

# U-61: 패스워드 재사용 제한
fix_u61() {
    local check_id="U-61"
    local check_name="Password Reuse Restriction"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    local pam_system_auth="/etc/pam.d/system-auth"
    if [ -f "$pam_system_auth" ]; then
        backup_file "$pam_system_auth"

        # remember 옵션 추가
        if ! grep -q "remember=" "$pam_system_auth"; then
            sed -i '/password.*sufficient.*pam_unix.so/ s/$/ remember=5/' "$pam_system_auth"
            log_fix_result "$check_id" "$check_name" "SUCCESS" "Password reuse restriction set (remember=5)"
        else
            log_fix_result "$check_id" "$check_name" "SKIPPED" "Password reuse restriction already configured"
        fi
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "/etc/pam.d/system-auth not found"
    fi
}

# U-62: 취약한 프로토콜 사용 금지
fix_u62() {
    local check_id="U-62"
    local check_name="Weak Protocol Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 취약한 프로토콜 서비스 비활성화
    for service in telnet ftp; do
        systemctl stop $service 2>/dev/null
        systemctl disable $service 2>/dev/null
    done

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Weak protocols (telnet, ftp) disabled"
}

# U-63: 로그온 시 경고 메시지 제공
fix_u63() {
    local check_id="U-63"
    local check_name="Login Warning Banner"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # /etc/motd 및 /etc/issue 설정
    cat > /etc/motd << 'EOF'
***************************************************************************
WARNING: Unauthorized access to this system is forbidden and will be
prosecuted by law. By accessing this system, you agree that your actions
may be monitored if unauthorized usage is suspected.
***************************************************************************
EOF

    cp /etc/motd /etc/issue
    cp /etc/motd /etc/issue.net

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Login warning banner configured"
}

# U-64: NTP 서비스 설정
fix_u64() {
    local check_id="U-64"
    local check_name="NTP Service Configuration"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # chronyd 활성화
    systemctl enable chronyd
    systemctl start chronyd

    if [ $? -eq 0 ]; then
        log_fix_result "$check_id" "$check_name" "SUCCESS" "NTP service (chronyd) enabled"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "Failed to enable NTP service"
    fi
}

# U-65: SNMP Community String 복잡도 설정
fix_u65() {
    local check_id="U-65"
    local check_name="SNMP Community String"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (SNMP community string 설정)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Configure strong SNMP community strings"
}

# U-66: Bootloader 설정 파일 권한
fix_u66() {
    local check_id="U-66"
    local check_name="Bootloader Configuration Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # GRUB 설정 파일 권한 설정
    local grub_cfg="/boot/grub2/grub.cfg"
    if [ -f "$grub_cfg" ]; then
        chmod 600 "$grub_cfg"
        chown root:root "$grub_cfg"
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Bootloader config permissions set to 600"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "Bootloader config not found"
    fi
}

# U-67: UMASK 설정
fix_u67() {
    local check_id="U-67"
    local check_name="UMASK Configuration"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # /etc/profile에 umask 설정
    local profile="/etc/profile"
    if [ -f "$profile" ]; then
        backup_file "$profile"
        sed -i 's/^[[:space:]]*umask.*/umask 022/' "$profile"

        if ! grep -q "^umask" "$profile"; then
            echo "umask 022" >> "$profile"
        fi

        log_fix_result "$check_id" "$check_name" "SUCCESS" "UMASK set to 022"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "/etc/profile not found"
    fi
}

# U-68: 홈 디렉토리 권한 설정
fix_u68() {
    local check_id="U-68"
    local check_name="Home Directory Permission"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 홈 디렉토리 권한 설정 (700 또는 750)
    for home_dir in /home/*; do
        if [ -d "$home_dir" ]; then
            chmod 700 "$home_dir"
        fi
    done

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Home directory permissions set to 700"
}

# U-69: 홈 디렉토리 소유자 설정
fix_u69() {
    local check_id="U-69"
    local check_name="Home Directory Ownership"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (소유자 변경은 신중해야 함)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Verify home directory ownership"
}

# U-70: 숨겨진 파일 및 디렉토리 검색 및 제거
fix_u70() {
    local check_id="U-70"
    local check_name="Hidden Files Check"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (숨겨진 파일 검토)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Review hidden files and directories"
}

# U-71: 시스템 core dump 비활성화
fix_u71() {
    local check_id="U-71"
    local check_name="Core Dump Disable"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # core dump 비활성화
    local limits_conf="/etc/security/limits.conf"
    if [ -f "$limits_conf" ]; then
        backup_file "$limits_conf"

        if ! grep -q "^\*.*hard.*core.*0" "$limits_conf"; then
            echo "* hard core 0" >> "$limits_conf"
        fi

        # sysctl 설정
        echo "kernel.core_pattern = |/bin/false" > /etc/sysctl.d/50-coredump.conf
        sysctl -p /etc/sysctl.d/50-coredump.conf 2>/dev/null

        log_fix_result "$check_id" "$check_name" "SUCCESS" "Core dump disabled"
    else
        log_fix_result "$check_id" "$check_name" "FAILED" "/etc/security/limits.conf not found"
    fi
}

# U-72: 취약점 관리 계획 수립
fix_u72() {
    local check_id="U-72"
    local check_name="Vulnerability Management Plan"

    if ! is_failed "$check_id"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi

    # 수동 조치 필요 (관리 계획 수립)
    log_fix_result "$check_id" "$check_name" "FAILED" "Manual intervention required. Establish vulnerability management plan"
}

#===============================================================================
# Latest 2026 KISA UNIX/Linux remediation mapping layer (U-01 ~ U-67)
#===============================================================================

latest_status_for() {
    local id="$1"
    [ -n "$CHECK_RESULT_FILE" ] && [ -f "$CHECK_RESULT_FILE" ] || return 1
    grep -A 2 "^\[${id}\]" "$CHECK_RESULT_FILE" | grep -m1 '^Status:' | sed 's/^Status: //'
}

latest_detail_for() {
    local id="$1"
    [ -n "$CHECK_RESULT_FILE" ] && [ -f "$CHECK_RESULT_FILE" ] || return 1
    grep -A 2 "^\[${id}\]" "$CHECK_RESULT_FILE" | grep -m1 '^Detail:' | sed 's/^Detail: //'
}

latest_legacy_result_mode() {
    [ -n "$CHECK_RESULT_FILE" ] && [ -f "$CHECK_RESULT_FILE" ] || return 1
    grep -Eq '^\[U-(68|69|70|71|72|73|74)\]' "$CHECK_RESULT_FILE"
}

latest_is_failed() {
    local id="$1"
    local fallback_id="$2"
    local status
    status=$(latest_status_for "$id")
    if [ -z "$status" ] && [ -n "$fallback_id" ] && latest_legacy_result_mode; then
        status=$(latest_status_for "$fallback_id")
    fi
    [ "$status" = "FAIL" ]
}

latest_run_legacy_fix() {
    local new_id="$1"
    local new_name="$2"
    local legacy_id="$3"
    local legacy_func="$4"
    local tmp_check tmp_fix status detail out_status out_detail

    tmp_check=$(mktemp)
    tmp_fix=$(mktemp)
    status=$(latest_status_for "$new_id")
    detail=$(latest_detail_for "$new_id")
    if [ -z "$status" ] && latest_legacy_result_mode; then
        status=$(latest_status_for "$legacy_id")
        detail=$(latest_detail_for "$legacy_id")
    fi
    [ -z "$status" ] && status="PASS"
    [ -z "$detail" ] && detail="Mapped from ${new_id} to legacy ${legacy_id}"

    if [ "$DRY_RUN" = true ]; then
        rm -f "$tmp_check" "$tmp_fix"
        if [ "$status" = "FAIL" ]; then
            log_fix_result "$new_id" "$new_name" "PLANNED" "Dry-run: would run mapped remediation ${legacy_func}. Current finding: ${detail}"
        else
            log_fix_result "$new_id" "$new_name" "SKIPPED" "Already passed or N/A"
        fi
        return
    fi

    {
        echo "[${legacy_id}] ${new_name}"
        echo "Status: ${status}"
        echo "Detail: ${detail}"
        echo "--------------------------------------------------------------------------------"
    } > "$tmp_check"

    ( CHECK_RESULT_FILE="$tmp_check"; FIX_RESULT_FILE="$tmp_fix"; "$legacy_func" ) >/dev/null 2>&1

    out_status=$(grep -m1 '^Status:' "$tmp_fix" | sed 's/^Status: //')
    out_detail=$(grep -m1 '^Detail:' "$tmp_fix" | sed 's/^Detail: //')
    rm -f "$tmp_check" "$tmp_fix"

    [ -z "$out_status" ] && out_status="SKIPPED"
    [ -z "$out_detail" ] && out_detail="Legacy remediation ${legacy_func} produced no parseable result"
    log_fix_result "$new_id" "$new_name" "$out_status" "$out_detail"
}

latest_manual_fix() {
    local id="$1"
    local name="$2"
    local fallback_id="$3"
    local message="$4"
    if ! latest_is_failed "$id" "$fallback_id"; then
        log_fix_result "$id" "$name" "SKIPPED" "Already passed or N/A"
        return
    fi
    if [ "$DRY_RUN" = true ]; then
        log_fix_result "$id" "$name" "MANUAL" "Dry-run: manual intervention required. ${message}"
        return
    fi
    log_fix_result "$id" "$name" "FAILED" "Manual intervention required. ${message}"
}


latest_fix_u02() {
    local check_id="U-02"
    local check_name="비밀번호 관리정책 설정"

    if ! latest_is_failed "$check_id" "U-02"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi
    if [ "$DRY_RUN" = true ]; then
        log_fix_result "$check_id" "$check_name" "PLANNED" "Dry-run: would set pwquality minlen=9 and require digit/upper/lower/special classes, plus PASS_MAX_DAYS=90 and PASS_MIN_DAYS=1. Backups: /etc/security/pwquality.conf, /etc/login.defs."
        return
    fi

    local pwquality_conf="/etc/security/pwquality.conf"
    local login_defs="/etc/login.defs"
    [ -d /etc/security ] || { log_fix_result "$check_id" "$check_name" "FAILED" "/etc/security directory not found"; return; }
    [ -f "$login_defs" ] || { log_fix_result "$check_id" "$check_name" "FAILED" "$login_defs not found"; return; }

    [ -f "$pwquality_conf" ] && backup_file "$pwquality_conf"
    backup_file "$login_defs"
    [ -f "$pwquality_conf" ] || touch "$pwquality_conf"

    for key in minlen dcredit ucredit lcredit ocredit; do
        sed -i "/^[[:space:]]*${key}[[:space:]]*=/d" "$pwquality_conf"
    done
    cat >> "$pwquality_conf" << 'EOF'

# Managed by linux_vuln_fix.sh for U-02
minlen = 9
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF

    if grep -Eq '^[[:space:]]*PASS_MAX_DAYS[[:space:]]+' "$login_defs"; then
        sed -i -E 's/^[[:space:]]*PASS_MAX_DAYS[[:space:]]+.*/PASS_MAX_DAYS 90/' "$login_defs"
    else
        echo "PASS_MAX_DAYS 90" >> "$login_defs"
    fi
    if grep -Eq '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+' "$login_defs"; then
        sed -i -E 's/^[[:space:]]*PASS_MIN_DAYS[[:space:]]+.*/PASS_MIN_DAYS 1/' "$login_defs"
    else
        echo "PASS_MIN_DAYS 1" >> "$login_defs"
    fi

    log_fix_result "$check_id" "$check_name" "SUCCESS" "Configured pwquality policy and login.defs password age policy to match U-02 check criteria"
}

latest_fix_u03() {
    local check_id="U-03"
    local check_name="계정 잠금 임계값 설정"

    if ! latest_is_failed "$check_id" "U-03"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi
    if [ "$DRY_RUN" = true ]; then
        log_fix_result "$check_id" "$check_name" "PLANNED" "Dry-run: would configure /etc/security/faillock.conf with deny=5, unlock_time=600, remove even_deny_root, and enable authselect with-faillock when available. Backup: /etc/security/faillock.conf."
        return
    fi

    local faillock_conf="/etc/security/faillock.conf"
    [ -d /etc/security ] || { log_fix_result "$check_id" "$check_name" "FAILED" "/etc/security directory not found"; return; }
    [ -f "$faillock_conf" ] && backup_file "$faillock_conf"
    [ -f "$faillock_conf" ] || touch "$faillock_conf"

    sed -i '/^[[:space:]]*deny[[:space:]]*=/d' "$faillock_conf"
    sed -i '/^[[:space:]]*unlock_time[[:space:]]*=/d' "$faillock_conf"
    sed -i '/^[[:space:]]*even_deny_root/d' "$faillock_conf"
    cat >> "$faillock_conf" << 'EOF'

# Managed by linux_vuln_fix.sh for U-03
deny = 5
unlock_time = 600
EOF

    if command -v authselect >/dev/null 2>&1 && authselect current >/dev/null 2>&1; then
        if ! authselect current 2>/dev/null | grep -q 'with-faillock'; then
            authselect enable-feature with-faillock >/dev/null 2>&1 && authselect apply-changes >/dev/null 2>&1
        fi
    fi

    if grep -Rqs 'pam_faillock\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || { command -v authselect >/dev/null 2>&1 && authselect current 2>/dev/null | grep -q 'with-faillock'; }; then
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Configured faillock policy and verified PAM/authselect faillock binding"
    else
        log_fix_result "$check_id" "$check_name" "MANUAL" "faillock.conf configured, but pam_faillock/authselect with-faillock binding requires manual verification"
    fi
}

latest_fix_u12() {
    local check_id="U-12"
    local check_name="세션 종료 시간 설정"
    local tmout_file="/etc/profile.d/security_tmout.sh"

    if ! latest_is_failed "$check_id" "U-54"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi
    if [ "$DRY_RUN" = true ]; then
        log_fix_result "$check_id" "$check_name" "PLANNED" "Dry-run: would create/update $tmout_file with TMOUT=900, readonly TMOUT, and export TMOUT. Backup if file exists."
        return
    fi

    [ -d /etc/profile.d ] || { log_fix_result "$check_id" "$check_name" "FAILED" "/etc/profile.d not found"; return; }
    [ -f "$tmout_file" ] && backup_file "$tmout_file"
    cat > "$tmout_file" << 'EOF'
# Managed by linux_vuln_fix.sh for U-12
TMOUT=900
readonly TMOUT
export TMOUT
EOF
    chown root:root "$tmout_file" 2>/dev/null
    chmod 644 "$tmout_file"
    log_fix_result "$check_id" "$check_name" "SUCCESS" "Configured shell session timeout in $tmout_file"
}

latest_fix_u37() {
    local check_id="U-37"
    local check_name="crontab 설정파일 권한 설정 미흡"

    if ! latest_is_failed "$check_id" "U-22"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi
    if [ "$DRY_RUN" = true ]; then
        log_fix_result "$check_id" "$check_name" "PLANNED" "Dry-run: would back up cron files where possible, set cron configuration ownership to root:root, set modes <=640, and remove world-write from /usr/bin/crontab."
        return
    fi

    local file count=0
    for file in /etc/crontab /etc/cron.allow /etc/cron.deny /etc/cron.d/* /var/spool/cron/*; do
        [ -e "$file" ] || continue
        [ -f "$file" ] && backup_file "$file"
        chown root:root "$file" 2>/dev/null
        chmod 640 "$file" 2>/dev/null
        count=$((count + 1))
    done
    if [ -e /usr/bin/crontab ]; then
        chown root:root /usr/bin/crontab 2>/dev/null
        chmod o-w /usr/bin/crontab 2>/dev/null
        count=$((count + 1))
    fi

    if [ "$count" -gt 0 ]; then
        log_fix_result "$check_id" "$check_name" "SUCCESS" "Adjusted owner/permission on ${count} cron-related paths"
    else
        log_fix_result "$check_id" "$check_name" "SKIPPED" "No cron-related paths found"
    fi
}

latest_fix_u58() {
    local check_id="U-58"
    local check_name="불필요한 SNMP 서비스 구동 점검"

    if ! latest_is_failed "$check_id" "U-66"; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi
    if [ "$DRY_RUN" = true ]; then
        log_fix_result "$check_id" "$check_name" "PLANNED" "Dry-run: would stop and disable snmpd service when systemctl is available."
        return
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop snmpd 2>/dev/null || true
        systemctl disable snmpd 2>/dev/null || true
    fi

    if { command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet snmpd 2>/dev/null; } || pgrep -x snmpd >/dev/null 2>&1; then
        log_fix_result "$check_id" "$check_name" "FAILED" "SNMP service is still running after stop/disable attempt"
    else
        log_fix_result "$check_id" "$check_name" "SUCCESS" "SNMP service stopped/disabled or not active"
    fi
}

latest_fix_u60() {
    latest_manual_fix "U-60" "SNMP Community String 복잡성 설정" "U-67" "Replace default/weak SNMP community strings with site-approved non-default values of length >= 10, or migrate to SNMPv3. Backup /etc/snmp/snmpd.conf before editing."
}

latest_fix_u63() {
    local check_id="U-63"
    local check_name="sudo 명령어 접근 관리"

    if ! latest_is_failed "$check_id" ""; then
        log_fix_result "$check_id" "$check_name" "SKIPPED" "Already passed or N/A"
        return
    fi
    if [ "$DRY_RUN" = true ]; then
        log_fix_result "$check_id" "$check_name" "PLANNED" "Dry-run: would back up sudoers files, set sudoers ownership to root:root, enforce mode 440 on sudoers files, and flag NOPASSWD rules for manual review."
        return
    fi

    [ -f /etc/sudoers ] || { log_fix_result "$check_id" "$check_name" "FAILED" "/etc/sudoers not found"; return; }
    local files=(/etc/sudoers) file nopasswd=false
    if [ -d /etc/sudoers.d ]; then
        chown root:root /etc/sudoers.d 2>/dev/null
        chmod go-w /etc/sudoers.d 2>/dev/null
        while IFS= read -r file; do files+=("$file"); done < <(find /etc/sudoers.d -maxdepth 1 -type f ! -name '*~' ! -name '*.bak' 2>/dev/null | sort)
    fi

    for file in "${files[@]}"; do
        [ -f "$file" ] || continue
        backup_file "$file"
        chown root:root "$file" 2>/dev/null
        chmod 440 "$file" 2>/dev/null
        if awk '
            /^[[:space:]]*($|#)/ { next }
            /NOPASSWD[[:space:]]*:/ { found=1 }
            END { exit found ? 0 : 1 }
        ' "$file" 2>/dev/null; then
            nopasswd=true
        fi
    done

    if [ "$nopasswd" = true ]; then
        log_fix_result "$check_id" "$check_name" "MANUAL" "sudoers owner/mode remediated; NOPASSWD sudo rules require policy review and manual removal"
    else
        log_fix_result "$check_id" "$check_name" "SUCCESS" "sudoers files protected with root ownership and restrictive permissions"
    fi
}

latest_fix_u64() {
    latest_manual_fix "U-64" "주기적 보안 패치 및 벤더 권고사항 적용" "U-42" "Review vendor advisories and apply security updates through a controlled change window, for example dnf update --security on Rocky/RHEL systems."
}

latest_fix_u01() { latest_run_legacy_fix "U-01" "root 계정 원격 접속 제한" "U-01" fix_u01; }
# latest_fix_u02 is implemented directly above.
# latest_fix_u03 is implemented directly above.
latest_fix_u04() { latest_run_legacy_fix "U-04" "비밀번호 파일 보호" "U-04" fix_u04; }
latest_fix_u05() { latest_run_legacy_fix "U-05" "root 이외의 UID가 ‘0’ 금지" "U-44" fix_u44; }
latest_fix_u06() { latest_run_legacy_fix "U-06" "사용자 계정 su 기능 제한" "U-45" fix_u45; }
latest_fix_u07() { latest_run_legacy_fix "U-07" "불필요한 계정 제거" "U-49" fix_u49; }
latest_fix_u08() { latest_run_legacy_fix "U-08" "관리자 그룹에 최소한의 계정 포함" "U-50" fix_u50; }
latest_fix_u09() { latest_run_legacy_fix "U-09" "계정이 존재하지 않는 GID 금지" "U-51" fix_u51; }
latest_fix_u10() { latest_run_legacy_fix "U-10" "동일한 UID 금지" "U-52" fix_u52; }
latest_fix_u11() { latest_run_legacy_fix "U-11" "사용자 Shell 점검" "U-53" fix_u53; }
# latest_fix_u12 is implemented directly above.
latest_fix_u13() { latest_manual_fix "U-13" "안전한 비밀번호 암호화 알고리즘 사용" "" "Configure SHA-256/SHA-512/yescrypt password hashing policy and rotate weak hashes."; }
latest_fix_u14() { latest_run_legacy_fix "U-14" "root 홈, 패스 디렉터리 권한 및 패스 설정" "U-05" fix_u05; }
latest_fix_u15() { latest_run_legacy_fix "U-15" "파일 및 디렉터리 소유자 설정" "U-06" fix_u06; }
latest_fix_u16() { latest_run_legacy_fix "U-16" "/etc/passwd 파일 소유자 및 권한 설정" "U-07" fix_u07; }
latest_fix_u17() { latest_manual_fix "U-17" "시스템 시작 스크립트 권한 설정" "" "Set startup scripts to root ownership and remove group/world write permissions after service impact review."; }
latest_fix_u18() { latest_run_legacy_fix "U-18" "/etc/shadow 파일 소유자 및 권한 설정" "U-08" fix_u08; }
latest_fix_u19() { latest_run_legacy_fix "U-19" "/etc/hosts 파일 소유자 및 권한 설정" "U-09" fix_u09; }
latest_fix_u20() { latest_run_legacy_fix "U-20" "/etc/(x)inetd.conf 파일 소유자 및 권한 설정" "U-10" fix_u10; }
latest_fix_u21() { latest_run_legacy_fix "U-21" "/etc/(r)syslog.conf 파일 소유자 및 권한 설정" "U-11" fix_u11; }
latest_fix_u22() { latest_run_legacy_fix "U-22" "/etc/services 파일 소유자 및 권한 설정" "U-12" fix_u12; }
latest_fix_u23() { latest_run_legacy_fix "U-23" "SUID, SGID, Sticky bit 설정 파일 점검" "U-13" fix_u13; }
latest_fix_u24() { latest_run_legacy_fix "U-24" "사용자, 시스템 환경변수 파일 소유자 및 권한 설정" "U-14" fix_u14; }
latest_fix_u25() { latest_run_legacy_fix "U-25" "world writable 파일 점검" "U-15" fix_u15; }
latest_fix_u26() { latest_run_legacy_fix "U-26" "/dev에 존재하지 않는 device 파일 점검" "U-16" fix_u16; }
latest_fix_u27() { latest_run_legacy_fix "U-27" "\$HOME/.rhosts, hosts.equiv 사용 금지" "U-17" fix_u17; }
latest_fix_u28() { latest_run_legacy_fix "U-28" "접속 IP 및 포트 제한" "U-18" fix_u18; }
latest_fix_u29() { latest_run_legacy_fix "U-29" "hosts.lpd 파일 소유자 및 권한 설정" "U-55" fix_u55; }
latest_fix_u30() { latest_run_legacy_fix "U-30" "UMASK 설정 관리" "U-56" fix_u56; }
latest_fix_u31() { latest_run_legacy_fix "U-31" "홈디렉토리 소유자 및 권한 설정" "U-57" fix_u57; }
latest_fix_u32() { latest_run_legacy_fix "U-32" "홈 디렉토리로 지정한 디렉토리의 존재 관리" "U-58" fix_u58; }
latest_fix_u33() { latest_run_legacy_fix "U-33" "숨겨진 파일 및 디렉토리 검색 및 제거" "U-59" fix_u59; }
latest_fix_u34() { latest_run_legacy_fix "U-34" "Finger 서비스 비활성화" "U-19" fix_u19; }
latest_fix_u35() { latest_run_legacy_fix "U-35" "공유 서비스에 대한 익명 접근 제한 설정" "U-20" fix_u20; }
latest_fix_u36() { latest_run_legacy_fix "U-36" "r 계열 서비스 비활성화" "U-21" fix_u21; }
# latest_fix_u37 is implemented directly above.
latest_fix_u38() { latest_run_legacy_fix "U-38" "DoS 공격에 취약한 서비스 비활성화" "U-23" fix_u23; }
latest_fix_u39() { latest_run_legacy_fix "U-39" "불필요한 NFS 서비스 비활성화" "U-24" fix_u24; }
latest_fix_u40() { latest_run_legacy_fix "U-40" "NFS 접근 통제" "U-25" fix_u25; }
latest_fix_u41() { latest_run_legacy_fix "U-41" "불필요한 automountd 제거" "U-26" fix_u26; }
latest_fix_u42() { latest_run_legacy_fix "U-42" "불필요한 RPC 서비스 비활성화" "U-27" fix_u27; }
latest_fix_u43() { latest_run_legacy_fix "U-43" "NIS, NIS+ 점검" "U-28" fix_u28; }
latest_fix_u44() { latest_run_legacy_fix "U-44" "tftp, talk 서비스 비활성화" "U-29" fix_u29; }
latest_fix_u45() { latest_run_legacy_fix "U-45" "메일 서비스 버전 점검" "U-30" fix_u30; }
latest_fix_u46() { latest_run_legacy_fix "U-46" "일반 사용자의 메일 서비스 실행 방지" "U-32" fix_u32; }
latest_fix_u47() { latest_run_legacy_fix "U-47" "스팸 메일 릴레이 제한" "U-31" fix_u31; }
latest_fix_u48() { latest_run_legacy_fix "U-48" "expn, vrfy 명령어 제한" "U-70" fix_u70; }
latest_fix_u49() { latest_run_legacy_fix "U-49" "DNS 보안 버전 패치" "U-33" fix_u33; }
latest_fix_u50() { latest_run_legacy_fix "U-50" "DNS Zone Transfer 설정" "U-34" fix_u34; }
latest_fix_u51() { latest_manual_fix "U-51" "DNS 서비스의 취약한 동적 업데이트 설정 금지" "" "Set BIND allow-update to none or restrict it to authenticated/approved hosts."; }
latest_fix_u52() { latest_manual_fix "U-52" "Telnet 서비스 비활성화" "" "Disable telnet.socket/telnet service and use SSH."; }
latest_fix_u53() { latest_manual_fix "U-53" "FTP 서비스 정보 노출 제한" "" "Configure FTP banner and response settings to avoid product/version disclosure."; }
latest_fix_u54() { latest_run_legacy_fix "U-54" "암호화되지 않는 FTP 서비스 비활성화" "U-61" fix_u61; }
latest_fix_u55() { latest_run_legacy_fix "U-55" "FTP 계정 Shell 제한" "U-62" fix_u62; }
latest_fix_u56() { latest_manual_fix "U-56" "FTP 서비스 접근 제어 설정" "" "Restrict FTP access by approved users, groups, and source addresses."; }
latest_fix_u57() { latest_run_legacy_fix "U-57" "Ftpusers 파일 설정" "U-64" fix_u64; }
# latest_fix_u58 is implemented directly above.
latest_fix_u59() { latest_manual_fix "U-59" "안전한 SNMP 버전 사용" "" "Migrate SNMP to v3 and remove v1/v2 community settings."; }
# latest_fix_u60 is implemented directly above.
latest_fix_u61() { latest_manual_fix "U-61" "SNMP Access Control 설정" "" "Restrict SNMP users/communities to approved managers and views."; }
latest_fix_u62() { latest_run_legacy_fix "U-62" "로그인 시 경고 메시지 설정" "U-68" fix_u68; }
# latest_fix_u63 is implemented directly above.
# latest_fix_u64 is implemented directly above.
latest_fix_u65() { latest_manual_fix "U-65" "NTP 및 시각 동기화 설정" "" "Enable chronyd/ntpd or systemd-timesyncd with approved time sources."; }
latest_fix_u66() { latest_run_legacy_fix "U-66" "정책에 따른 시스템 로깅 설정" "U-72" fix_u72; }
latest_fix_u67() { latest_manual_fix "U-67" "로그 디렉터리 소유자 및 권한 설정" "" "Set log directories to root-owned, remove world-write permissions, and preserve application-specific ownership exceptions."; }


#===============================================================================
# 메인 실행 로직
#===============================================================================

main() {
    # 파라미터 파싱 (--version, --help는 여기서 처리)
    parse_args "$@"

    if [ "$QUIET" != true ]; then
        echo -e "${BLUE}================================================================================${NC}"
        echo -e "${BLUE}Rocky Linux 8.10/9.x Security Vulnerability Auto-Remediation Script${NC}"
        echo -e "${BLUE}================================================================================${NC}"
        echo ""
    fi

    if [ "$DRY_RUN" = true ] && [ -n "$CHECK_RESULT_FILE" ] && [ -f "$CHECK_RESULT_FILE" ]; then
        [ "$QUIET" = true ] || echo -e "${BLUE}[DRY-RUN] Using provided result file without OS/root preflight.${NC}"
    else
        # Root 권한 확인
        check_root

        # 운영체제 환경 확인
        check_os_environment

        # OS 기능 감지
        detect_os_capabilities
    fi

    # 백업 디렉토리 생성
    create_backup_dir

    # 점검 결과 파일이 없으면 점검 스크립트 실행
    if [ -z "$CHECK_RESULT_FILE" ] || [ ! -f "$CHECK_RESULT_FILE" ]; then
        [ "$QUIET" = true ] || echo -e "${YELLOW}[INFO] No check result file provided. Running vulnerability check first...${NC}"

        if [ ! -f "$CHECK_SCRIPT" ]; then
            echo -e "${RED}[ERROR] Check script not found: $CHECK_SCRIPT${NC}"
            exit 1
        fi

        # 점검 스크립트 실행
        check_args=()
        [ "$QUIET" = true ] && check_args+=(--quiet)
        [ "$NO_COLOR" = true ] && check_args+=(--no-color)
        bash "$CHECK_SCRIPT" "${check_args[@]}"

        # 가장 최근 생성된 결과 파일 찾기
        CHECK_RESULT_FILE=$(ls -t ${HOSTNAME}_*_result.txt 2>/dev/null | head -1)

        if [ -z "$CHECK_RESULT_FILE" ] || [ ! -f "$CHECK_RESULT_FILE" ]; then
            echo -e "${RED}[ERROR] Failed to create check result file${NC}"
            exit 1
        fi

        if [ "$QUIET" != true ]; then
            echo -e "${GREEN}[SUCCESS] Vulnerability check completed: $CHECK_RESULT_FILE${NC}"
            echo ""
        fi
    else
        if [ "$QUIET" != true ]; then
            echo -e "${BLUE}[INFO] Using existing check result file: $CHECK_RESULT_FILE${NC}"
            echo ""
        fi
    fi

    # 조치 결과 파일 초기화
    init_fix_result_file

    if [ "$QUIET" != true ]; then
        echo -e "${BLUE}[INFO] Starting vulnerability remediation...${NC}"
        echo ""
    fi

    # 최신 2026 UNIX/Linux 기준 모든 조치 함수 실행 (U-01 ~ U-67)
    latest_fix_u01
    latest_fix_u02
    latest_fix_u03
    latest_fix_u04
    latest_fix_u05
    latest_fix_u06
    latest_fix_u07
    latest_fix_u08
    latest_fix_u09
    latest_fix_u10
    latest_fix_u11
    latest_fix_u12
    latest_fix_u13
    latest_fix_u14
    latest_fix_u15
    latest_fix_u16
    latest_fix_u17
    latest_fix_u18
    latest_fix_u19
    latest_fix_u20
    latest_fix_u21
    latest_fix_u22
    latest_fix_u23
    latest_fix_u24
    latest_fix_u25
    latest_fix_u26
    latest_fix_u27
    latest_fix_u28
    latest_fix_u29
    latest_fix_u30
    latest_fix_u31
    latest_fix_u32
    latest_fix_u33
    latest_fix_u34
    latest_fix_u35
    latest_fix_u36
    latest_fix_u37
    latest_fix_u38
    latest_fix_u39
    latest_fix_u40
    latest_fix_u41
    latest_fix_u42
    latest_fix_u43
    latest_fix_u44
    latest_fix_u45
    latest_fix_u46
    latest_fix_u47
    latest_fix_u48
    latest_fix_u49
    latest_fix_u50
    latest_fix_u51
    latest_fix_u52
    latest_fix_u53
    latest_fix_u54
    latest_fix_u55
    latest_fix_u56
    latest_fix_u57
    latest_fix_u58
    latest_fix_u59
    latest_fix_u60
    latest_fix_u61
    latest_fix_u62
    latest_fix_u63
    latest_fix_u64
    latest_fix_u65
    latest_fix_u66
    latest_fix_u67

    # 최종 통계 출력
    if [ "$QUIET" != true ]; then
        echo ""
        echo -e "${BLUE}================================================================================${NC}"
        echo -e "${BLUE}Remediation Summary${NC}"
        echo -e "${BLUE}================================================================================${NC}"
        echo -e "Total fixes attempted: ${TOTAL_FIXES}"
        echo -e "${GREEN}Successful fixes: ${SUCCESS_FIXES}${NC}"
        echo -e "${RED}Failed fixes: ${FAILED_FIXES}${NC}"
        echo -e "${YELLOW}Skipped fixes: ${SKIPPED_FIXES}${NC}"
        echo -e "${BLUE}Planned fixes: ${PLANNED_FIXES}${NC}"
        echo -e "${YELLOW}Manual fixes: ${MANUAL_FIXES}${NC}"
        echo -e "${BLUE}================================================================================${NC}"
        echo ""
        echo -e "${BLUE}[INFO] Remediation result saved to: $FIX_RESULT_FILE${NC}"
        echo -e "${BLUE}[INFO] Backup files saved to: $BACKUP_DIR${NC}"
        echo ""
    fi

    # 최종 통계를 결과 파일에도 기록
    {
        echo ""
        echo "================================================================================"
        echo "Remediation Summary"
        echo "================================================================================"
        echo "Total fixes attempted: ${TOTAL_FIXES}"
        echo "Successful fixes: ${SUCCESS_FIXES}"
        echo "Failed fixes: ${FAILED_FIXES}"
        echo "Skipped fixes: ${SKIPPED_FIXES}"
        echo "Planned fixes: ${PLANNED_FIXES}"
        echo "Manual fixes: ${MANUAL_FIXES}"
        echo "================================================================================"
    } >> "$FIX_RESULT_FILE"
}

# 메인 함수 실행
main "$@"
