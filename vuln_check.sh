#!/bin/bash
#===============================================================================
# RHEL/Rocky Linux 9 보안 취약점 점검 스크립트
#
# 설명: 시스템의 보안 취약점을 점검하고 결과를 파일로 저장합니다.
# 출력: hostname_YYMMDD_hhmmss_result.txt 형식의 결과 파일
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
        echo -e "${RED}[ERROR] This script must be run as root.${NC}"
        exit 1
    fi
}

# 결과 파일 초기화
init_result_file() {
    echo "================================================================================" > "$RESULT_FILE"
    echo "Security Vulnerability Assessment Report" >> "$RESULT_FILE"
    echo "================================================================================" >> "$RESULT_FILE"
    echo "Assessment Date: $(date '+%Y-%m-%d %H:%M:%S')" >> "$RESULT_FILE"
    echo "Hostname: $HOSTNAME" >> "$RESULT_FILE"
    echo "OS Version: $(cat /etc/redhat-release 2>/dev/null || echo 'Unknown')" >> "$RESULT_FILE"
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
    echo "Status: ${status}" >> "$RESULT_FILE"
    echo "Detail: ${detail}" >> "$RESULT_FILE"
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

# U-01: root 계정 원격 접속 제한 (위험도: 상)
check_u01() {
    local check_id="U-01"
    local check_name="Root Remote Login Restriction"
    local risk_level="HIGH"

    # sshd_config 파일 경로 확인
    local sshd_config=""
    if [ -f /etc/ssh/sshd_config ]; then
        sshd_config="/etc/ssh/sshd_config"
    else
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] sshd_config file does not exist"
        return
    fi

    # PermitRootLogin 설정 확인
    # 1. 주석이 아닌 활성 설정만 검색
    local permit_root=$(grep -i "^[[:space:]]*PermitRootLogin" "$sshd_config" | grep -v "^[[:space:]]*#" | tail -1 | awk '{print tolower($2)}')

    if [ -z "$permit_root" ]; then
        # 설정이 없는 경우 (주석처리 또는 미설정)
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] PermitRootLogin is not set or commented out"
    elif [ "$permit_root" == "no" ]; then
        # no로 설정된 경우 - 양호
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] PermitRootLogin is set to no"
    else
        # yes 또는 다른 값으로 설정된 경우 - 취약
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] PermitRootLogin is set to ${permit_root} (should be set to no)"
    fi
}

# U-02: 패스워드 복잡성 설정 (위험도: 상)
check_u02() {
    local check_id="U-02"
    local check_name="Password Complexity Settings"
    local risk_level="HIGH"

    local pwquality_conf="/etc/security/pwquality.conf"

    if [ ! -f "$pwquality_conf" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] pwquality.conf file does not exist"
        return
    fi

    # 각 조건 검사 결과 저장
    local fail_reasons=""
    local pass_details=""

    # 1. 최소 패스워드 길이 검사 (8자리 이상)
    local minlen=$(grep -i "^[[:space:]]*minlen" "$pwquality_conf" | grep -v "^[[:space:]]*#" | tail -1 | awk -F= '{print $2}' | tr -d ' ')
    if [ -n "$minlen" ] && [ "$minlen" -ge 8 ]; then
        pass_details="${pass_details}minlen=${minlen}, "
    else
        fail_reasons="${fail_reasons}minlen not set or less than 8 (current: ${minlen:-'not set'}), "
    fi

    # 2. 숫자 포함 검사 (dcredit)
    # dcredit = -1 이면 최소 1개의 숫자 필요
    local dcredit=$(grep -i "^[[:space:]]*dcredit" "$pwquality_conf" | grep -v "^[[:space:]]*#" | tail -1 | awk -F= '{print $2}' | tr -d ' ')
    if [ -n "$dcredit" ] && [ "$dcredit" -lt 0 ]; then
        pass_details="${pass_details}digit required, "
    else
        fail_reasons="${fail_reasons}digit requirement not set (dcredit=${dcredit:-'not set'}), "
    fi

    # 3. 영문 대문자 포함 검사 (ucredit)
    local ucredit=$(grep -i "^[[:space:]]*ucredit" "$pwquality_conf" | grep -v "^[[:space:]]*#" | tail -1 | awk -F= '{print $2}' | tr -d ' ')
    if [ -n "$ucredit" ] && [ "$ucredit" -lt 0 ]; then
        pass_details="${pass_details}uppercase required, "
    else
        fail_reasons="${fail_reasons}uppercase requirement not set (ucredit=${ucredit:-'not set'}), "
    fi

    # 4. 영문 소문자 포함 검사 (lcredit)
    local lcredit=$(grep -i "^[[:space:]]*lcredit" "$pwquality_conf" | grep -v "^[[:space:]]*#" | tail -1 | awk -F= '{print $2}' | tr -d ' ')
    if [ -n "$lcredit" ] && [ "$lcredit" -lt 0 ]; then
        pass_details="${pass_details}lowercase required, "
    else
        fail_reasons="${fail_reasons}lowercase requirement not set (lcredit=${lcredit:-'not set'}), "
    fi

    # 5. 특수문자 포함 검사 (ocredit)
    local ocredit=$(grep -i "^[[:space:]]*ocredit" "$pwquality_conf" | grep -v "^[[:space:]]*#" | tail -1 | awk -F= '{print $2}' | tr -d ' ')
    if [ -n "$ocredit" ] && [ "$ocredit" -lt 0 ]; then
        pass_details="${pass_details}special char required"
    else
        fail_reasons="${fail_reasons}special char requirement not set (ocredit=${ocredit:-'not set'})"
    fi

    # 최종 결과 판정
    if [ -z "$fail_reasons" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] ${pass_details}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_reasons}"
    fi
}

# U-03: 계정 잠금 임계값 설정
check_u03() {
    local check_id="U-03"
    local check_name="Account Lockout Threshold"

    local faillock_conf="/etc/security/faillock.conf"
    if [ -f "$faillock_conf" ]; then
        local deny=$(grep -i "^deny" "$faillock_conf" | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$deny" ] && [ "$deny" -le 5 ] && [ "$deny" -gt 0 ]; then
            log_result "$check_id" "$check_name" "PASS" "Account lockout threshold: ${deny} attempts"
        else
            log_result "$check_id" "$check_name" "FAIL" "Account lockout threshold is inappropriate (current: ${deny:-'not set'})"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "faillock.conf file does not exist"
    fi
}

# U-04: 패스워드 최대 사용 기간 설정
check_u04() {
    local check_id="U-04"
    local check_name="Password Maximum Age"

    if [ -f /etc/login.defs ]; then
        local pass_max_days=$(grep -i "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        if [ -n "$pass_max_days" ] && [ "$pass_max_days" -le 90 ]; then
            log_result "$check_id" "$check_name" "PASS" "Password maximum age: ${pass_max_days} days"
        else
            log_result "$check_id" "$check_name" "FAIL" "Password maximum age exceeds 90 days (current: ${pass_max_days:-'not set'})"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "login.defs file does not exist"
    fi
}

# U-05: 패스워드 최소 사용 기간 설정
check_u05() {
    local check_id="U-05"
    local check_name="Password Minimum Age"

    if [ -f /etc/login.defs ]; then
        local pass_min_days=$(grep -i "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
        if [ -n "$pass_min_days" ] && [ "$pass_min_days" -ge 1 ]; then
            log_result "$check_id" "$check_name" "PASS" "Password minimum age: ${pass_min_days} days"
        else
            log_result "$check_id" "$check_name" "FAIL" "Password minimum age is less than 1 day (current: ${pass_min_days:-'not set'})"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "login.defs file does not exist"
    fi
}

# U-06: /etc/passwd 파일 소유자 및 권한 설정
check_u06() {
    local check_id="U-06"
    local check_name="/etc/passwd File Owner and Permission"

    if [ -f /etc/passwd ]; then
        local owner=$(stat -c %U /etc/passwd)
        local perm=$(stat -c %a /etc/passwd)

        if [ "$owner" == "root" ] && [ "$perm" -le 644 ]; then
            log_result "$check_id" "$check_name" "PASS" "Owner: ${owner}, Permission: ${perm}"
        else
            log_result "$check_id" "$check_name" "FAIL" "Owner: ${owner}, Permission: ${perm} (should be root owned, 644 or less)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "/etc/passwd file does not exist"
    fi
}

# U-07: /etc/shadow 파일 소유자 및 권한 설정
check_u07() {
    local check_id="U-07"
    local check_name="/etc/shadow File Owner and Permission"

    if [ -f /etc/shadow ]; then
        local owner=$(stat -c %U /etc/shadow)
        local perm=$(stat -c %a /etc/shadow)

        if [ "$owner" == "root" ] && [ "$perm" -le 400 ]; then
            log_result "$check_id" "$check_name" "PASS" "Owner: ${owner}, Permission: ${perm}"
        else
            log_result "$check_id" "$check_name" "FAIL" "Owner: ${owner}, Permission: ${perm} (should be root owned, 400 or less)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "/etc/shadow file does not exist"
    fi
}

# U-08: /etc/hosts 파일 소유자 및 권한 설정
check_u08() {
    local check_id="U-08"
    local check_name="/etc/hosts File Owner and Permission"

    if [ -f /etc/hosts ]; then
        local owner=$(stat -c %U /etc/hosts)
        local perm=$(stat -c %a /etc/hosts)

        if [ "$owner" == "root" ] && [ "$perm" -le 644 ]; then
            log_result "$check_id" "$check_name" "PASS" "Owner: ${owner}, Permission: ${perm}"
        else
            log_result "$check_id" "$check_name" "FAIL" "Owner: ${owner}, Permission: ${perm} (should be root owned, 644 or less)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "/etc/hosts file does not exist"
    fi
}

# U-09: UMASK 설정 관리
check_u09() {
    local check_id="U-09"
    local check_name="UMASK Configuration"

    local umask_value=""

    if [ -f /etc/profile ]; then
        umask_value=$(grep -i "^umask" /etc/profile | tail -1 | awk '{print $2}')
    fi

    if [ -n "$umask_value" ]; then
        if [ "$umask_value" == "022" ] || [ "$umask_value" == "027" ]; then
            log_result "$check_id" "$check_name" "PASS" "UMASK value: ${umask_value}"
        else
            log_result "$check_id" "$check_name" "FAIL" "UMASK value is inappropriate (current: ${umask_value}, recommended: 022 or 027)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "UMASK is not configured"
    fi
}

# U-10: 불필요한 서비스 비활성화
check_u10() {
    local check_id="U-10"
    local check_name="Unnecessary Services Disabled"

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
        log_result "$check_id" "$check_name" "PASS" "All unnecessary services are disabled"
    else
        log_result "$check_id" "$check_name" "FAIL" "Enabled unnecessary services:${enabled_services}"
    fi
}

#===============================================================================
# 메인 실행
#===============================================================================

main() {
    echo "================================================================================"
    echo "RHEL/Rocky Linux 9 Security Vulnerability Assessment Script"
    echo "================================================================================"
    echo ""

    # Root 권한 확인
    check_root

    # 결과 파일 초기화
    init_result_file

    echo "Starting security assessment..."
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
    echo "Assessment Completed: $(date '+%Y-%m-%d %H:%M:%S')" >> "$RESULT_FILE"
    echo "================================================================================" >> "$RESULT_FILE"

    echo ""
    echo "================================================================================"
    echo -e "${GREEN}Assessment completed.${NC}"
    echo "Result file: ${SCRIPT_DIR}/${RESULT_FILE}"
    echo "================================================================================"
}

# 스크립트 실행
main "$@"
