#!/bin/bash
#===============================================================================
# RHEL/Rocky Linux 9 보안 취약점 점검 스크립트
#
# 설명: 시스템의 보안 취약점을 점검하고 결과를 파일로 저장합니다.
# 출력: hostname_YYMMDD_result.txt 형식의 결과 파일
#===============================================================================

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 결과 파일 설정
HOSTNAME=$(hostname)
DATE=$(date +%y%m%d)
TIME=$(date +%H%M%S)
RESULT_FILE="${HOSTNAME}_${DATE}_${TIME}_result.txt"
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Root 권한 확인
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR] 이 스크립트는 root 권한으로 실행해야 합니다.${NC}"
        exit 1
    fi
}

# 결과 파일 초기화
init_result_file() {
    echo "================================================================================" > "$RESULT_FILE"
    echo "보안 취약점 점검 결과 보고서" >> "$RESULT_FILE"
    echo "================================================================================" >> "$RESULT_FILE"
    echo "점검 일시: $(date '+%Y-%m-%d %H:%M:%S')" >> "$RESULT_FILE"
    echo "호스트명: $HOSTNAME" >> "$RESULT_FILE"
    echo "OS 버전: $(cat /etc/redhat-release 2>/dev/null || echo 'Unknown')" >> "$RESULT_FILE"
    echo "================================================================================" >> "$RESULT_FILE"
    echo "" >> "$RESULT_FILE"
}

# 점검 결과 기록 함수
log_result() {
    local check_id="$1"
    local check_name="$2"
    local status="$3"  # PASS, FAIL, N/A
    local detail="$4"

    echo "[${check_id}] ${check_name}" >> "$RESULT_FILE"
    echo "상태: ${status}" >> "$RESULT_FILE"
    echo "상세: ${detail}" >> "$RESULT_FILE"
    echo "--------------------------------------------------------------------------------" >> "$RESULT_FILE"

    # 화면 출력
    case "$status" in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} [${check_id}] ${check_name}"
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} [${check_id}] ${check_name}"
            ;;
        *)
            echo -e "${YELLOW}[N/A]${NC} [${check_id}] ${check_name}"
            ;;
    esac
}

#===============================================================================
# 취약점 점검 항목들
#===============================================================================

# U-01: root 계정 원격 접속 제한
check_u01() {
    local check_id="U-01"
    local check_name="root 계정 원격 접속 제한"

    if [ -f /etc/ssh/sshd_config ]; then
        local permit_root=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
        if [ "$permit_root" == "no" ]; then
            log_result "$check_id" "$check_name" "PASS" "PermitRootLogin이 no로 설정됨"
        else
            log_result "$check_id" "$check_name" "FAIL" "PermitRootLogin이 ${permit_root:-'설정되지 않음'}으로 설정됨"
        fi
    else
        log_result "$check_id" "$check_name" "N/A" "sshd_config 파일이 존재하지 않음"
    fi
}

# U-02: 패스워드 복잡성 설정
check_u02() {
    local check_id="U-02"
    local check_name="패스워드 복잡성 설정"

    if [ -f /etc/security/pwquality.conf ]; then
        local minlen=$(grep -i "^minlen" /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$minlen" ] && [ "$minlen" -ge 8 ]; then
            log_result "$check_id" "$check_name" "PASS" "최소 패스워드 길이: ${minlen}"
        else
            log_result "$check_id" "$check_name" "FAIL" "최소 패스워드 길이가 8 미만이거나 설정되지 않음"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "pwquality.conf 파일이 존재하지 않음"
    fi
}

# U-03: 계정 잠금 임계값 설정
check_u03() {
    local check_id="U-03"
    local check_name="계정 잠금 임계값 설정"

    local faillock_conf="/etc/security/faillock.conf"
    if [ -f "$faillock_conf" ]; then
        local deny=$(grep -i "^deny" "$faillock_conf" | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$deny" ] && [ "$deny" -le 5 ] && [ "$deny" -gt 0 ]; then
            log_result "$check_id" "$check_name" "PASS" "계정 잠금 임계값: ${deny}회"
        else
            log_result "$check_id" "$check_name" "FAIL" "계정 잠금 임계값이 적절하지 않음 (현재: ${deny:-'미설정'})"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "faillock.conf 파일이 존재하지 않음"
    fi
}

# U-04: 패스워드 최대 사용 기간 설정
check_u04() {
    local check_id="U-04"
    local check_name="패스워드 최대 사용 기간 설정"

    if [ -f /etc/login.defs ]; then
        local pass_max_days=$(grep -i "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        if [ -n "$pass_max_days" ] && [ "$pass_max_days" -le 90 ]; then
            log_result "$check_id" "$check_name" "PASS" "패스워드 최대 사용 기간: ${pass_max_days}일"
        else
            log_result "$check_id" "$check_name" "FAIL" "패스워드 최대 사용 기간이 90일 초과 (현재: ${pass_max_days:-'미설정'})"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "login.defs 파일이 존재하지 않음"
    fi
}

# U-05: 패스워드 최소 사용 기간 설정
check_u05() {
    local check_id="U-05"
    local check_name="패스워드 최소 사용 기간 설정"

    if [ -f /etc/login.defs ]; then
        local pass_min_days=$(grep -i "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
        if [ -n "$pass_min_days" ] && [ "$pass_min_days" -ge 1 ]; then
            log_result "$check_id" "$check_name" "PASS" "패스워드 최소 사용 기간: ${pass_min_days}일"
        else
            log_result "$check_id" "$check_name" "FAIL" "패스워드 최소 사용 기간이 1일 미만 (현재: ${pass_min_days:-'미설정'})"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "login.defs 파일이 존재하지 않음"
    fi
}

# U-06: /etc/passwd 파일 소유자 및 권한 설정
check_u06() {
    local check_id="U-06"
    local check_name="/etc/passwd 파일 소유자 및 권한 설정"

    if [ -f /etc/passwd ]; then
        local owner=$(stat -c %U /etc/passwd)
        local perm=$(stat -c %a /etc/passwd)

        if [ "$owner" == "root" ] && [ "$perm" -le 644 ]; then
            log_result "$check_id" "$check_name" "PASS" "소유자: ${owner}, 권한: ${perm}"
        else
            log_result "$check_id" "$check_name" "FAIL" "소유자: ${owner}, 권한: ${perm} (root 소유, 644 이하 권장)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "/etc/passwd 파일이 존재하지 않음"
    fi
}

# U-07: /etc/shadow 파일 소유자 및 권한 설정
check_u07() {
    local check_id="U-07"
    local check_name="/etc/shadow 파일 소유자 및 권한 설정"

    if [ -f /etc/shadow ]; then
        local owner=$(stat -c %U /etc/shadow)
        local perm=$(stat -c %a /etc/shadow)

        if [ "$owner" == "root" ] && [ "$perm" -le 400 ]; then
            log_result "$check_id" "$check_name" "PASS" "소유자: ${owner}, 권한: ${perm}"
        else
            log_result "$check_id" "$check_name" "FAIL" "소유자: ${owner}, 권한: ${perm} (root 소유, 400 이하 권장)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "/etc/shadow 파일이 존재하지 않음"
    fi
}

# U-08: /etc/hosts 파일 소유자 및 권한 설정
check_u08() {
    local check_id="U-08"
    local check_name="/etc/hosts 파일 소유자 및 권한 설정"

    if [ -f /etc/hosts ]; then
        local owner=$(stat -c %U /etc/hosts)
        local perm=$(stat -c %a /etc/hosts)

        if [ "$owner" == "root" ] && [ "$perm" -le 644 ]; then
            log_result "$check_id" "$check_name" "PASS" "소유자: ${owner}, 권한: ${perm}"
        else
            log_result "$check_id" "$check_name" "FAIL" "소유자: ${owner}, 권한: ${perm} (root 소유, 644 이하 권장)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "/etc/hosts 파일이 존재하지 않음"
    fi
}

# U-09: UMASK 설정 관리
check_u09() {
    local check_id="U-09"
    local check_name="UMASK 설정 관리"

    local umask_value=""

    if [ -f /etc/profile ]; then
        umask_value=$(grep -i "^umask" /etc/profile | tail -1 | awk '{print $2}')
    fi

    if [ -n "$umask_value" ]; then
        if [ "$umask_value" == "022" ] || [ "$umask_value" == "027" ]; then
            log_result "$check_id" "$check_name" "PASS" "UMASK 값: ${umask_value}"
        else
            log_result "$check_id" "$check_name" "FAIL" "UMASK 값이 부적절 (현재: ${umask_value}, 022 또는 027 권장)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "UMASK 설정이 되어있지 않음"
    fi
}

# U-10: 불필요한 서비스 비활성화
check_u10() {
    local check_id="U-10"
    local check_name="불필요한 서비스 비활성화"

    local unnecessary_services=("telnet" "rsh" "rlogin" "rexec" "finger" "tftp")
    local enabled_services=""

    for service in "${unnecessary_services[@]}"; do
        if systemctl is-enabled "${service}.socket" 2>/dev/null | grep -q "enabled"; then
            enabled_services="${enabled_services} ${service}"
        fi
        if systemctl is-enabled "${service}" 2>/dev/null | grep -q "enabled"; then
            enabled_services="${enabled_services} ${service}"
        fi
    done

    if [ -z "$enabled_services" ]; then
        log_result "$check_id" "$check_name" "PASS" "불필요한 서비스가 비활성화됨"
    else
        log_result "$check_id" "$check_name" "FAIL" "활성화된 불필요한 서비스:${enabled_services}"
    fi
}

#===============================================================================
# 메인 실행
#===============================================================================

main() {
    echo "================================================================================"
    echo "RHEL/Rocky Linux 9 보안 취약점 점검 스크립트"
    echo "================================================================================"
    echo ""

    # Root 권한 확인
    check_root

    # 결과 파일 초기화
    init_result_file

    echo "점검을 시작합니다..."
    echo ""

    # 취약점 점검 실행
    check_u01
    check_u02
    check_u03
    check_u04
    check_u05
    check_u06
    check_u07
    check_u08
    check_u09
    check_u10

    # 결과 요약
    echo "" >> "$RESULT_FILE"
    echo "================================================================================" >> "$RESULT_FILE"
    echo "점검 완료: $(date '+%Y-%m-%d %H:%M:%S')" >> "$RESULT_FILE"
    echo "================================================================================" >> "$RESULT_FILE"

    echo ""
    echo "================================================================================"
    echo -e "${GREEN}점검이 완료되었습니다.${NC}"
    echo "결과 파일: ${SCRIPT_DIR}/${RESULT_FILE}"
    echo "================================================================================"
}

# 스크립트 실행
main "$@"
