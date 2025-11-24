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

# U-03: 계정 잠금 임계값 설정 (위험도: 상)
check_u03() {
    local check_id="U-03"
    local check_name="Account Lockout Threshold"
    local risk_level="HIGH"

    local faillock_conf="/etc/security/faillock.conf"

    if [ ! -f "$faillock_conf" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] faillock.conf file does not exist"
        return
    fi

    # 각 조건 검사 결과 저장
    local fail_reasons=""
    local pass_details=""

    # 조건1: root에게는 패스워드 잠금 설정을 적용하지 않음 (even_deny_root가 설정되지 않아야 함)
    local even_deny_root=$(grep -i "^[[:space:]]*even_deny_root" "$faillock_conf" | grep -v "^[[:space:]]*#")
    if [ -z "$even_deny_root" ]; then
        pass_details="${pass_details}root excluded from lockout, "
    else
        fail_reasons="${fail_reasons}root should be excluded from lockout (even_deny_root is set), "
    fi

    # 조건2: 5회 입력 실패 시 패스워드 잠금 (deny = 5)
    local deny=$(grep -i "^[[:space:]]*deny" "$faillock_conf" | grep -v "^[[:space:]]*#" | tail -1 | awk -F= '{print $2}' | tr -d ' ')
    if [ -n "$deny" ] && [ "$deny" -eq 5 ]; then
        pass_details="${pass_details}deny=${deny}, "
    else
        fail_reasons="${fail_reasons}deny should be 5 (current: ${deny:-'not set'}), "
    fi

    # 조건3: 계정 잠김 후 마지막 계정 실패 시간부터 120초가 지나면 자동 계정 잠김 해제 (unlock_time = 120)
    local unlock_time=$(grep -i "^[[:space:]]*unlock_time" "$faillock_conf" | grep -v "^[[:space:]]*#" | tail -1 | awk -F= '{print $2}' | tr -d ' ')
    if [ -n "$unlock_time" ] && [ "$unlock_time" -eq 120 ]; then
        pass_details="${pass_details}unlock_time=${unlock_time}, "
    else
        fail_reasons="${fail_reasons}unlock_time should be 120 (current: ${unlock_time:-'not set'}), "
    fi

    # 조건4: 접속 시도 성공 시 실패한 횟수 초기화 (reset_on_success 기본값이 true이므로 명시적으로 false가 아니면 양호)
    local reset_on_success=$(grep -i "^[[:space:]]*reset_on_success" "$faillock_conf" | grep -v "^[[:space:]]*#" | tail -1 | awk -F= '{print $2}' | tr -d ' ')
    # reset_on_success가 설정되지 않았거나 true로 설정된 경우 양호 (기본값이 true)
    if [ -z "$reset_on_success" ] || [ "$reset_on_success" == "true" ]; then
        pass_details="${pass_details}reset_on_success=true"
    else
        fail_reasons="${fail_reasons}reset_on_success should be true (current: ${reset_on_success})"
    fi

    # 최종 결과 판정
    if [ -z "$fail_reasons" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] ${pass_details}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_reasons}"
    fi
}

# U-04: 패스워드 파일 보호 (위험도: 상)
check_u04() {
    local check_id="U-04"
    local check_name="Password File Protection"
    local risk_level="HIGH"

    local passwd_file="/etc/passwd"

    # 각 조건 검사 결과 저장
    local fail_reasons=""
    local pass_details=""

    # 조건1: /etc 경로 하위에 passwd 파일이 존재하는지 확인
    if [ -f "$passwd_file" ]; then
        pass_details="${pass_details}/etc/passwd exists, "
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] /etc/passwd file does not exist"
        return
    fi

    # 조건2: /etc/passwd 파일 내 두 번째 필드가 "x" 표시되는지 확인
    # 모든 계정의 두 번째 필드가 "x"인지 검사 (패스워드가 shadow 파일에 암호화되어 저장됨을 의미)
    local invalid_entries=$(awk -F: '$2 != "x" {print $1}' "$passwd_file")

    if [ -z "$invalid_entries" ]; then
        pass_details="${pass_details}all passwords are shadowed (field 2 = x)"
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] ${pass_details}"
    else
        fail_reasons="accounts with unshadowed passwords: ${invalid_entries}"
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_reasons}"
    fi
}

# U-05: root홈, 패스 디렉터리 권한 및 패스 설정 (위험도: 상)
check_u05() {
    local check_id="U-05"
    local check_name="Root Home and PATH Directory Configuration"
    local risk_level="HIGH"

    # 검사할 환경변수 설정 파일 목록
    local config_files=("/etc/profile" "/root/.profile" "/root/.bashrc" "/root/.bash_profile" "/root/.cshrc")

    local fail_reasons=""
    local pass_details=""
    local vulnerable_files=""

    for config_file in "${config_files[@]}"; do
        if [ -f "$config_file" ]; then
            # PATH 설정 라인 추출 (export PATH= 또는 PATH= 형태)
            local path_lines=$(grep -n "^[[:space:]]*\(export \)\?PATH=" "$config_file" | grep -v "^[[:space:]]*#")

            if [ -n "$path_lines" ]; then
                while IFS= read -r line; do
                    local line_num=$(echo "$line" | cut -d: -f1)
                    local path_value=$(echo "$line" | cut -d= -f2- | tr -d '"' | tr -d "'")

                    # PATH를 콜론으로 분리하여 배열로 변환
                    IFS=':' read -ra path_array <<< "$path_value"
                    local path_count=${#path_array[@]}

                    # "."이 맨 앞이나 중간에 있는지 검사 (마지막 위치는 허용)
                    local idx=0
                    for path_entry in "${path_array[@]}"; do
                        # 현재 디렉터리를 나타내는 "." 또는 빈 문자열(::) 검사
                        if [ "$path_entry" == "." ] || [ -z "$path_entry" ]; then
                            # 마지막 위치가 아닌 경우 취약
                            if [ $idx -lt $((path_count - 1)) ]; then
                                vulnerable_files="${vulnerable_files}${config_file}:${line_num}, "
                                break
                            fi
                        fi
                        ((idx++))
                    done
                done <<< "$path_lines"
            fi
        fi
    done

    # 현재 root의 PATH 환경변수도 검사
    local current_path="$PATH"
    IFS=':' read -ra current_path_array <<< "$current_path"
    local current_path_count=${#current_path_array[@]}
    local current_path_vulnerable=false

    local idx=0
    for path_entry in "${current_path_array[@]}"; do
        if [ "$path_entry" == "." ] || [ -z "$path_entry" ]; then
            if [ $idx -lt $((current_path_count - 1)) ]; then
                current_path_vulnerable=true
                break
            fi
        fi
        ((idx++))
    done

    # 최종 결과 판정
    if [ -z "$vulnerable_files" ] && [ "$current_path_vulnerable" == false ]; then
        pass_details="PATH does not contain '.' at the beginning or middle"
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] ${pass_details}"
    else
        if [ -n "$vulnerable_files" ]; then
            fail_reasons="'.' found in PATH at beginning/middle in: ${vulnerable_files}"
        fi
        if [ "$current_path_vulnerable" == true ]; then
            fail_reasons="${fail_reasons}current PATH contains '.' at beginning/middle"
        fi
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_reasons}"
    fi
}

# U-06: 파일 및 디렉터리 소유자 설정 (위험도: 상)
check_u06() {
    local check_id="U-06"
    local check_name="File and Directory Owner Configuration"
    local risk_level="HIGH"

    # 소유자가 존재하지 않는 파일 및 디렉터리 검색
    # -nouser: UID가 /etc/passwd에 없는 파일
    # -nogroup: GID가 /etc/group에 없는 파일
    local noowner_files=$(find / -nouser -o -nogroup 2>/dev/null | head -100)

    if [ -z "$noowner_files" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No files or directories with non-existent owner found"
    else
        # 파일 개수 확인
        local file_count=$(echo "$noowner_files" | wc -l)

        # 결과를 한 줄로 변환 (최대 10개만 표시)
        local file_list=$(echo "$noowner_files" | head -10 | tr '\n' ', ' | sed 's/,$//')

        if [ "$file_count" -gt 10 ]; then
            file_list="${file_list} ... and $((file_count - 10)) more"
        fi

        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Found ${file_count} files/directories with non-existent owner: ${file_list}"
    fi
}

# U-07: /etc/passwd 파일 소유자 및 권한 설정 (위험도: 상)
check_u07() {
    local check_id="U-07"
    local check_name="/etc/passwd File Owner and Permission"
    local risk_level="HIGH"

    local passwd_file="/etc/passwd"

    if [ ! -f "$passwd_file" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] /etc/passwd file does not exist"
        return
    fi

    local owner=$(stat -c %U "$passwd_file")
    local perm=$(stat -c %a "$passwd_file")

    local fail_reasons=""

    # 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        fail_reasons="${fail_reasons}owner is ${owner} (should be root), "
    fi

    # 권한이 644 이하인지 확인
    if [ "$perm" -gt 644 ]; then
        fail_reasons="${fail_reasons}permission is ${perm} (should be 644 or less)"
    fi

    if [ -z "$fail_reasons" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Owner: ${owner}, Permission: ${perm}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_reasons}"
    fi
}

# U-08: /etc/shadow 파일 소유자 및 권한 설정 (위험도: 상)
check_u08() {
    local check_id="U-08"
    local check_name="/etc/shadow File Owner and Permission"
    local risk_level="HIGH"

    local shadow_file="/etc/shadow"

    if [ ! -f "$shadow_file" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] /etc/shadow file does not exist"
        return
    fi

    local owner=$(stat -c %U "$shadow_file")
    local perm=$(stat -c %a "$shadow_file")

    local fail_reasons=""

    # 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        fail_reasons="${fail_reasons}owner is ${owner} (should be root), "
    fi

    # 권한이 400 이하인지 확인
    if [ "$perm" -gt 400 ]; then
        fail_reasons="${fail_reasons}permission is ${perm} (should be 400 or less)"
    fi

    if [ -z "$fail_reasons" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Owner: ${owner}, Permission: ${perm}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_reasons}"
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
