#!/bin/bash
#===============================================================================
# RHEL/Rocky Linux 9 보안 취약점 조치 스크립트
#
# 설명: 점검 결과 파일을 기반으로 취약점을 자동 조치합니다.
# 요구사항: 점검 결과 파일(hostname_YYMMDD_result.txt)이 필요합니다.
#===============================================================================

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 변수 설정
HOSTNAME=$(hostname)
DATE=$(date +%y%m%d)
TIME=$(date +%H%M%S)
# 점검 결과 파일은 가장 최근 파일을 자동으로 찾음
RESULT_FILE=$(ls -t ${HOSTNAME}_${DATE}_*_result.txt 2>/dev/null | head -1)
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
BACKUP_DIR="${SCRIPT_DIR}/backup_${DATE}"
FIX_LOG="${SCRIPT_DIR}/${HOSTNAME}_${DATE}_fix_log.txt"

# Root 권한 확인
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR] 이 스크립트는 root 권한으로 실행해야 합니다.${NC}"
        exit 1
    fi
}

# 점검 결과 파일 확인
check_result_file() {
    if [ -z "$RESULT_FILE" ] || [ ! -f "$RESULT_FILE" ]; then
        echo -e "${RED}[ERROR] 점검 결과 파일이 존재하지 않습니다.${NC}"
        echo -e "${YELLOW}[INFO] 먼저 vuln_check.sh 스크립트를 실행하여 점검을 진행해 주세요.${NC}"
        exit 1
    fi
}

# 백업 디렉토리 생성
create_backup_dir() {
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        echo -e "${BLUE}[INFO] 백업 디렉토리 생성: ${BACKUP_DIR}${NC}"
    fi
}

# 파일 백업 함수
backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        cp -p "$file" "${BACKUP_DIR}/$(basename "$file").bak"
        echo "[BACKUP] ${file} -> ${BACKUP_DIR}/$(basename "$file").bak" >> "$FIX_LOG"
    fi
}

# 조치 로그 기록 함수
log_fix() {
    local check_id="$1"
    local action="$2"
    local status="$3"
    local detail="$4"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${check_id}] ${action}" >> "$FIX_LOG"
    echo "  상태: ${status}" >> "$FIX_LOG"
    echo "  상세: ${detail}" >> "$FIX_LOG"
    echo "--------------------------------------------------------------------------------" >> "$FIX_LOG"

    case "$status" in
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} [${check_id}] ${action}"
            ;;
        "SKIPPED")
            echo -e "${YELLOW}[SKIPPED]${NC} [${check_id}] ${action}"
            ;;
        "FAILED")
            echo -e "${RED}[FAILED]${NC} [${check_id}] ${action}"
            ;;
    esac
}

# 취약점 상태 확인 함수
is_vulnerable() {
    local check_id="$1"
    if grep -q "\[${check_id}\]" "$RESULT_FILE" && grep -A1 "\[${check_id}\]" "$RESULT_FILE" | grep -q "상태: FAIL"; then
        return 0
    else
        return 1
    fi
}

#===============================================================================
# 취약점 조치 함수들
#===============================================================================

# U-01: root 계정 원격 접속 제한
fix_u01() {
    local check_id="U-01"
    local action="root 계정 원격 접속 제한 조치"

    if ! is_vulnerable "$check_id"; then
        log_fix "$check_id" "$action" "SKIPPED" "취약하지 않음"
        return
    fi

    local sshd_config="/etc/ssh/sshd_config"

    if [ -f "$sshd_config" ]; then
        backup_file "$sshd_config"

        # 기존 설정 제거 및 새 설정 추가
        sed -i '/^#*PermitRootLogin/d' "$sshd_config"
        echo "PermitRootLogin no" >> "$sshd_config"

        # SSH 서비스 재시작
        systemctl restart sshd 2>/dev/null

        log_fix "$check_id" "$action" "SUCCESS" "PermitRootLogin no 설정 완료"
    else
        log_fix "$check_id" "$action" "FAILED" "sshd_config 파일이 존재하지 않음"
    fi
}

# U-02: 패스워드 복잡성 설정
fix_u02() {
    local check_id="U-02"
    local action="패스워드 복잡성 설정 조치"

    if ! is_vulnerable "$check_id"; then
        log_fix "$check_id" "$action" "SKIPPED" "취약하지 않음"
        return
    fi

    local pwquality_conf="/etc/security/pwquality.conf"

    if [ -f "$pwquality_conf" ]; then
        backup_file "$pwquality_conf"

        # 기존 설정 제거
        sed -i '/^#*minlen/d' "$pwquality_conf"
        sed -i '/^#*dcredit/d' "$pwquality_conf"
        sed -i '/^#*ucredit/d' "$pwquality_conf"
        sed -i '/^#*lcredit/d' "$pwquality_conf"
        sed -i '/^#*ocredit/d' "$pwquality_conf"

        # 새 설정 추가
        echo "" >> "$pwquality_conf"
        echo "# Security hardening settings" >> "$pwquality_conf"
        echo "minlen = 8" >> "$pwquality_conf"
        echo "dcredit = -1" >> "$pwquality_conf"
        echo "ucredit = -1" >> "$pwquality_conf"
        echo "lcredit = -1" >> "$pwquality_conf"
        echo "ocredit = -1" >> "$pwquality_conf"

        log_fix "$check_id" "$action" "SUCCESS" "패스워드 복잡성 설정 완료 (최소 8자, 숫자/대문자/소문자/특수문자 각 1개 이상)"
    else
        log_fix "$check_id" "$action" "FAILED" "pwquality.conf 파일이 존재하지 않음"
    fi
}

# U-03: 계정 잠금 임계값 설정
fix_u03() {
    local check_id="U-03"
    local action="계정 잠금 임계값 설정 조치"

    if ! is_vulnerable "$check_id"; then
        log_fix "$check_id" "$action" "SKIPPED" "취약하지 않음"
        return
    fi

    local faillock_conf="/etc/security/faillock.conf"

    if [ -f "$faillock_conf" ]; then
        backup_file "$faillock_conf"

        # 기존 설정 제거
        sed -i '/^#*deny/d' "$faillock_conf"
        sed -i '/^#*unlock_time/d' "$faillock_conf"

        # 새 설정 추가
        echo "" >> "$faillock_conf"
        echo "# Account lockout settings" >> "$faillock_conf"
        echo "deny = 5" >> "$faillock_conf"
        echo "unlock_time = 600" >> "$faillock_conf"

        log_fix "$check_id" "$action" "SUCCESS" "계정 잠금 임계값 설정 완료 (5회 실패 시 600초 잠금)"
    else
        log_fix "$check_id" "$action" "FAILED" "faillock.conf 파일이 존재하지 않음"
    fi
}

# U-04: 패스워드 최대 사용 기간 설정
fix_u04() {
    local check_id="U-04"
    local action="패스워드 최대 사용 기간 설정 조치"

    if ! is_vulnerable "$check_id"; then
        log_fix "$check_id" "$action" "SKIPPED" "취약하지 않음"
        return
    fi

    local login_defs="/etc/login.defs"

    if [ -f "$login_defs" ]; then
        backup_file "$login_defs"

        # 기존 설정 수정
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' "$login_defs"

        # 설정이 없으면 추가
        if ! grep -q "^PASS_MAX_DAYS" "$login_defs"; then
            echo "PASS_MAX_DAYS   90" >> "$login_defs"
        fi

        log_fix "$check_id" "$action" "SUCCESS" "패스워드 최대 사용 기간 90일 설정 완료"
    else
        log_fix "$check_id" "$action" "FAILED" "login.defs 파일이 존재하지 않음"
    fi
}

# U-05: 패스워드 최소 사용 기간 설정
fix_u05() {
    local check_id="U-05"
    local action="패스워드 최소 사용 기간 설정 조치"

    if ! is_vulnerable "$check_id"; then
        log_fix "$check_id" "$action" "SKIPPED" "취약하지 않음"
        return
    fi

    local login_defs="/etc/login.defs"

    if [ -f "$login_defs" ]; then
        backup_file "$login_defs"

        # 기존 설정 수정
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' "$login_defs"

        # 설정이 없으면 추가
        if ! grep -q "^PASS_MIN_DAYS" "$login_defs"; then
            echo "PASS_MIN_DAYS   1" >> "$login_defs"
        fi

        log_fix "$check_id" "$action" "SUCCESS" "패스워드 최소 사용 기간 1일 설정 완료"
    else
        log_fix "$check_id" "$action" "FAILED" "login.defs 파일이 존재하지 않음"
    fi
}

# U-06: /etc/passwd 파일 소유자 및 권한 설정
fix_u06() {
    local check_id="U-06"
    local action="/etc/passwd 파일 소유자 및 권한 설정 조치"

    if ! is_vulnerable "$check_id"; then
        log_fix "$check_id" "$action" "SKIPPED" "취약하지 않음"
        return
    fi

    local passwd_file="/etc/passwd"

    if [ -f "$passwd_file" ]; then
        chown root:root "$passwd_file"
        chmod 644 "$passwd_file"

        log_fix "$check_id" "$action" "SUCCESS" "소유자 root, 권한 644로 설정 완료"
    else
        log_fix "$check_id" "$action" "FAILED" "/etc/passwd 파일이 존재하지 않음"
    fi
}

# U-07: /etc/shadow 파일 소유자 및 권한 설정
fix_u07() {
    local check_id="U-07"
    local action="/etc/shadow 파일 소유자 및 권한 설정 조치"

    if ! is_vulnerable "$check_id"; then
        log_fix "$check_id" "$action" "SKIPPED" "취약하지 않음"
        return
    fi

    local shadow_file="/etc/shadow"

    if [ -f "$shadow_file" ]; then
        chown root:root "$shadow_file"
        chmod 400 "$shadow_file"

        log_fix "$check_id" "$action" "SUCCESS" "소유자 root, 권한 400으로 설정 완료"
    else
        log_fix "$check_id" "$action" "FAILED" "/etc/shadow 파일이 존재하지 않음"
    fi
}

# U-08: /etc/hosts 파일 소유자 및 권한 설정
fix_u08() {
    local check_id="U-08"
    local action="/etc/hosts 파일 소유자 및 권한 설정 조치"

    if ! is_vulnerable "$check_id"; then
        log_fix "$check_id" "$action" "SKIPPED" "취약하지 않음"
        return
    fi

    local hosts_file="/etc/hosts"

    if [ -f "$hosts_file" ]; then
        chown root:root "$hosts_file"
        chmod 644 "$hosts_file"

        log_fix "$check_id" "$action" "SUCCESS" "소유자 root, 권한 644로 설정 완료"
    else
        log_fix "$check_id" "$action" "FAILED" "/etc/hosts 파일이 존재하지 않음"
    fi
}

# U-09: UMASK 설정 관리
fix_u09() {
    local check_id="U-09"
    local action="UMASK 설정 관리 조치"

    if ! is_vulnerable "$check_id"; then
        log_fix "$check_id" "$action" "SKIPPED" "취약하지 않음"
        return
    fi

    local profile_file="/etc/profile"

    if [ -f "$profile_file" ]; then
        backup_file "$profile_file"

        # 기존 umask 설정 제거
        sed -i '/^umask/d' "$profile_file"

        # 새 umask 설정 추가
        echo "" >> "$profile_file"
        echo "# Security hardening - UMASK setting" >> "$profile_file"
        echo "umask 022" >> "$profile_file"

        log_fix "$check_id" "$action" "SUCCESS" "UMASK 022 설정 완료"
    else
        log_fix "$check_id" "$action" "FAILED" "/etc/profile 파일이 존재하지 않음"
    fi
}

# U-10: 불필요한 서비스 비활성화
fix_u10() {
    local check_id="U-10"
    local action="불필요한 서비스 비활성화 조치"

    if ! is_vulnerable "$check_id"; then
        log_fix "$check_id" "$action" "SKIPPED" "취약하지 않음"
        return
    fi

    local unnecessary_services=("telnet" "rsh" "rlogin" "rexec" "finger" "tftp")
    local disabled_services=""

    for service in "${unnecessary_services[@]}"; do
        # 서비스 비활성화
        if systemctl is-enabled "${service}.socket" 2>/dev/null | grep -q "enabled"; then
            systemctl disable "${service}.socket" 2>/dev/null
            systemctl stop "${service}.socket" 2>/dev/null
            disabled_services="${disabled_services} ${service}.socket"
        fi
        if systemctl is-enabled "${service}" 2>/dev/null | grep -q "enabled"; then
            systemctl disable "${service}" 2>/dev/null
            systemctl stop "${service}" 2>/dev/null
            disabled_services="${disabled_services} ${service}"
        fi
    done

    if [ -n "$disabled_services" ]; then
        log_fix "$check_id" "$action" "SUCCESS" "비활성화된 서비스:${disabled_services}"
    else
        log_fix "$check_id" "$action" "SKIPPED" "비활성화할 서비스가 없음"
    fi
}

#===============================================================================
# 메인 실행
#===============================================================================

main() {
    echo "================================================================================"
    echo "RHEL/Rocky Linux 9 보안 취약점 조치 스크립트"
    echo "================================================================================"
    echo ""

    # Root 권한 확인
    check_root

    # 점검 결과 파일 확인
    check_result_file

    # 백업 디렉토리 생성
    create_backup_dir

    # 조치 로그 초기화
    echo "================================================================================" > "$FIX_LOG"
    echo "보안 취약점 조치 로그" >> "$FIX_LOG"
    echo "================================================================================" >> "$FIX_LOG"
    echo "조치 일시: $(date '+%Y-%m-%d %H:%M:%S')" >> "$FIX_LOG"
    echo "호스트명: $HOSTNAME" >> "$FIX_LOG"
    echo "점검 결과 파일: $RESULT_FILE" >> "$FIX_LOG"
    echo "================================================================================" >> "$FIX_LOG"
    echo "" >> "$FIX_LOG"

    echo -e "${BLUE}[INFO] 점검 결과 파일: ${RESULT_FILE}${NC}"
    echo -e "${BLUE}[INFO] 백업 디렉토리: ${BACKUP_DIR}${NC}"
    echo ""
    echo "조치를 시작합니다..."
    echo ""

    # 취약점 조치 실행
    fix_u01
    fix_u02
    fix_u03
    fix_u04
    fix_u05
    fix_u06
    fix_u07
    fix_u08
    fix_u09
    fix_u10

    # 결과 요약
    echo "" >> "$FIX_LOG"
    echo "================================================================================" >> "$FIX_LOG"
    echo "조치 완료: $(date '+%Y-%m-%d %H:%M:%S')" >> "$FIX_LOG"
    echo "================================================================================" >> "$FIX_LOG"

    echo ""
    echo "================================================================================"
    echo -e "${GREEN}조치가 완료되었습니다.${NC}"
    echo "조치 로그: ${FIX_LOG}"
    echo "백업 디렉토리: ${BACKUP_DIR}"
    echo ""
    echo -e "${YELLOW}[주의] 조치 후 시스템을 재부팅하거나 서비스를 재시작해야 할 수 있습니다.${NC}"
    echo -e "${YELLOW}[주의] 다시 점검 스크립트를 실행하여 조치 결과를 확인해 주세요.${NC}"
    echo "================================================================================"
}

# 스크립트 실행
main "$@"
