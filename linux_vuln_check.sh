#!/bin/bash
#===============================================================================
# RHEL/Rocky Linux 9 보안 취약점 점검 스크립트
#
# 설명: 시스템의 보안 취약점을 점검하고 결과를 파일로 저장합니다.
# 출력: hostname_YYMMDD_hhmmss_result.txt 형식의 결과 파일
# 버전: 26.05.01
#===============================================================================

# 버전 정보
VERSION="26.05.01"
SCRIPT_NAME="Linux Vulnerability Check Script"

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

# 운영체제 환경 확인
check_os_environment() {
    echo -e "${BLUE}Checking operating system environment...${NC}"

    # /etc/os-release 파일 확인
    if [ ! -f /etc/os-release ]; then
        echo -e "${RED}[ERROR] /etc/os-release file not found.${NC}"
        echo -e "${RED}[ERROR] This script is designed for RHEL or Rocky Linux 9.${NC}"
        exit 1
    fi

    # OS 정보 읽기
    source /etc/os-release

    # OS ID 확인 (rhel 또는 rocky)
    if [ "$ID" != "rhel" ] && [ "$ID" != "rocky" ]; then
        echo -e "${RED}[ERROR] Unsupported operating system: $ID${NC}"
        echo -e "${RED}[ERROR] This script is designed for RHEL or Rocky Linux 9.${NC}"
        echo -e "${RED}Current OS: ${NAME:-Unknown}${NC}"
        echo ""
        exit 1
    fi

    # 버전 확인 (9.x)
    local major_version=$(echo "$VERSION_ID" | cut -d. -f1)
    if [ "$major_version" != "9" ]; then
        echo -e "${RED}[ERROR] Unsupported OS version: $VERSION_ID${NC}"
        echo -e "${RED}[ERROR] This script is designed for RHEL or Rocky Linux 9.${NC}"
        echo -e "${RED}Current OS: ${PRETTY_NAME:-Unknown}${NC}"
        echo ""
        exit 1
    fi

    echo -e "${GREEN}Operating system check passed: ${PRETTY_NAME:-$NAME $VERSION_ID}${NC}"
}

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

# U-09: /etc/hosts 파일 소유자 및 권한 설정 (위험도: 상)
check_u09() {
    local check_id="U-09"
    local check_name="/etc/hosts File Owner and Permission"
    local risk_level="HIGH"

    local hosts_file="/etc/hosts"

    if [ ! -f "$hosts_file" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] /etc/hosts file does not exist"
        return
    fi

    local owner=$(stat -c %U "$hosts_file")
    local perm=$(stat -c %a "$hosts_file")

    local fail_reasons=""

    # 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        fail_reasons="${fail_reasons}owner is ${owner} (should be root), "
    fi

    # 권한이 600 이하인지 확인
    if [ "$perm" -gt 600 ]; then
        fail_reasons="${fail_reasons}permission is ${perm} (should be 600 or less)"
    fi

    if [ -z "$fail_reasons" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Owner: ${owner}, Permission: ${perm}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_reasons}"
    fi
}

# U-10: /etc/(x)inetd.conf 파일 소유자 및 권한 설정 (위험도: 상)
check_u10() {
    local check_id="U-10"
    local check_name="/etc/(x)inetd.conf File Owner and Permission"
    local risk_level="HIGH"

    # inetd.conf 또는 xinetd.conf 파일 확인
    local inetd_file=""
    if [ -f "/etc/inetd.conf" ]; then
        inetd_file="/etc/inetd.conf"
    elif [ -f "/etc/xinetd.conf" ]; then
        inetd_file="/etc/xinetd.conf"
    else
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] /etc/inetd.conf or /etc/xinetd.conf file does not exist"
        return
    fi

    local owner=$(stat -c %U "$inetd_file")
    local perm=$(stat -c %a "$inetd_file")

    local fail_reasons=""

    # 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        fail_reasons="${fail_reasons}owner is ${owner} (should be root), "
    fi

    # 권한이 600인지 확인
    if [ "$perm" -ne 600 ]; then
        fail_reasons="${fail_reasons}permission is ${perm} (should be 600)"
    fi

    if [ -z "$fail_reasons" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] File: ${inetd_file}, Owner: ${owner}, Permission: ${perm}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] File: ${inetd_file}, ${fail_reasons}"
    fi
}

# U-11: /etc/syslog.conf 파일 소유자 및 권한 설정 (위험도: 상)
check_u11() {
    local check_id="U-11"
    local check_name="/etc/syslog.conf File Owner and Permission"
    local risk_level="HIGH"

    # syslog.conf, rsyslog.conf 또는 syslog-ng.conf 파일 확인
    local syslog_file=""
    if [ -f "/etc/syslog.conf" ]; then
        syslog_file="/etc/syslog.conf"
    elif [ -f "/etc/rsyslog.conf" ]; then
        syslog_file="/etc/rsyslog.conf"
    elif [ -f "/etc/syslog-ng/syslog-ng.conf" ]; then
        syslog_file="/etc/syslog-ng/syslog-ng.conf"
    else
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] /etc/syslog.conf or /etc/rsyslog.conf file does not exist"
        return
    fi

    local owner=$(stat -c %U "$syslog_file")
    local perm=$(stat -c %a "$syslog_file")

    local fail_reasons=""

    # 소유자가 root, bin, sys 중 하나인지 확인
    if [[ "$owner" != "root" && "$owner" != "bin" && "$owner" != "sys" ]]; then
        fail_reasons="${fail_reasons}owner is ${owner} (should be root, bin, or sys), "
    fi

    # 권한이 640 이하인지 확인
    if [ "$perm" -gt 640 ]; then
        fail_reasons="${fail_reasons}permission is ${perm} (should be 640 or less)"
    fi

    if [ -z "$fail_reasons" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] File: ${syslog_file}, Owner: ${owner}, Permission: ${perm}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] File: ${syslog_file}, ${fail_reasons}"
    fi
}

# U-12: /etc/services 파일 소유자 및 권한 설정 (위험도: 상)
check_u12() {
    local check_id="U-12"
    local check_name="/etc/services File Owner and Permission"
    local risk_level="HIGH"

    local services_file="/etc/services"

    if [ ! -f "$services_file" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] /etc/services file does not exist"
        return
    fi

    local owner=$(stat -c %U "$services_file")
    local perm=$(stat -c %a "$services_file")

    local fail_reasons=""

    # 소유자가 root, bin, sys 중 하나인지 확인
    if [[ "$owner" != "root" && "$owner" != "bin" && "$owner" != "sys" ]]; then
        fail_reasons="${fail_reasons}owner is ${owner} (should be root, bin, or sys), "
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

# U-13: SUID, SGID 설정 파일 점검 (위험도: 상)
check_u13() {
    local check_id="U-13"
    local check_name="SUID and SGID File Check"
    local risk_level="HIGH"

    # SUID, SGID가 설정되면 안 되는 주요 실행파일 목록
    local critical_files=(
        "/sbin/dump"
        "/sbin/restore"
        "/sbin/unix_chkpwd"
        "/usr/bin/at"
        "/usr/bin/lpq"
        "/usr/bin/lpq-lpd"
        "/usr/bin/lpr"
        "/usr/bin/lpr-lpd"
        "/usr/bin/lprm"
        "/usr/bin/lprm-lpd"
        "/usr/bin/newgrp"
        "/usr/sbin/traceroute"
        "/usr/bin/traceroute6"
        "/usr/bin/traceroute6.iputils"
    )

    local vulnerable_files=""
    local found_count=0

    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            # SUID(4000) 또는 SGID(2000) 비트가 설정되어 있는지 확인
            local perm=$(stat -c %a "$file" 2>/dev/null)
            if [ -n "$perm" ]; then
                # 첫 번째 자리가 4(SUID), 2(SGID), 6(SUID+SGID)인지 확인
                local first_digit=${perm:0:1}
                if [[ "$first_digit" == "4" || "$first_digit" == "2" || "$first_digit" == "6" ]]; then
                    vulnerable_files="${vulnerable_files}${file}(${perm}), "
                    ((found_count++))
                fi
            fi
        fi
    done

    if [ -z "$vulnerable_files" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No critical files with SUID/SGID found"
    else
        # 최대 10개까지만 표시
        if [ "$found_count" -gt 10 ]; then
            local display_files=$(echo "$vulnerable_files" | cut -d',' -f1-10)
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Found ${found_count} files with SUID/SGID: ${display_files}, ... and $((found_count - 10)) more"
        else
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Files with SUID/SGID: ${vulnerable_files}"
        fi
    fi
}

# U-14: 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 (위험도: 상)
check_u14() {
    local check_id="U-14"
    local check_name="User and System Startup Files Owner and Permission"
    local risk_level="HIGH"

    # 검사할 환경변수 파일 목록
    local env_files=(
        ".bashrc"
        ".bash_profile"
        ".profile"
        ".cshrc"
        ".login"
        ".kshrc"
        ".bash_login"
        ".zshrc"
    )

    local vulnerable_files=""
    local found_count=0

    # /etc/passwd에서 일반 사용자 홈 디렉터리 추출 (UID >= 1000)
    while IFS=: read -r username _ uid _ _ homedir _; do
        # UID가 1000 이상인 일반 사용자만 검사
        if [ "$uid" -ge 1000 ] && [ -d "$homedir" ]; then
            for env_file in "${env_files[@]}"; do
                local full_path="${homedir}/${env_file}"

                if [ -f "$full_path" ]; then
                    local owner=$(stat -c %U "$full_path" 2>/dev/null)
                    local perm=$(stat -c %a "$full_path" 2>/dev/null)

                    # 조건1: 소유자가 root 또는 해당 계정인지 확인
                    if [[ "$owner" != "root" && "$owner" != "$username" ]]; then
                        vulnerable_files="${vulnerable_files}${full_path}(owner:${owner}), "
                        ((found_count++))
                        continue
                    fi

                    # 조건2: other에게 쓰기 권한이 없는지 확인 (권한의 마지막 자리가 2, 3, 6, 7이 아니어야 함)
                    local last_digit=${perm: -1}
                    if [[ "$last_digit" == "2" || "$last_digit" == "3" || "$last_digit" == "6" || "$last_digit" == "7" ]]; then
                        vulnerable_files="${vulnerable_files}${full_path}(perm:${perm}), "
                        ((found_count++))
                        continue
                    fi

                    # 조건3: group에게 쓰기 권한이 없는지 확인 (권한의 두 번째 자리가 2, 3, 6, 7이 아니어야 함)
                    local second_digit=${perm:1:1}
                    if [[ "$second_digit" == "2" || "$second_digit" == "3" || "$second_digit" == "6" || "$second_digit" == "7" ]]; then
                        vulnerable_files="${vulnerable_files}${full_path}(perm:${perm}), "
                        ((found_count++))
                    fi
                fi
            done
        fi
    done < /etc/passwd

    if [ -z "$vulnerable_files" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] All environment files have proper owner and permissions"
    else
        # 최대 10개까지만 표시
        if [ "$found_count" -gt 10 ]; then
            local display_files=$(echo "$vulnerable_files" | cut -d',' -f1-10)
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Found ${found_count} files with improper owner/permissions: ${display_files}, ... and $((found_count - 10)) more"
        else
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Files with improper owner/permissions: ${vulnerable_files}"
        fi
    fi
}

# U-15: world writable 파일 점검 (위험도: 상)
check_u15() {
    local check_id="U-15"
    local check_name="World Writable File Check"
    local risk_level="HIGH"

    # 시스템 중요 디렉터리에서 world writable 파일 검색
    # -perm -002: other에게 쓰기 권한이 있는 파일
    # -type f: 일반 파일만 검색 (디렉터리 제외)
    local critical_paths=(
        "/etc"
        "/bin"
        "/sbin"
        "/usr/bin"
        "/usr/sbin"
        "/usr/local/bin"
        "/usr/local/sbin"
    )

    local writable_files=""
    local found_count=0

    for path in "${critical_paths[@]}"; do
        if [ -d "$path" ]; then
            # world writable 파일 검색 (sticky bit가 있는 파일 제외)
            local files=$(find "$path" -type f -perm -002 ! -perm -1000 2>/dev/null)

            if [ -n "$files" ]; then
                while IFS= read -r file; do
                    local perm=$(stat -c %a "$file" 2>/dev/null)
                    writable_files="${writable_files}${file}(${perm}), "
                    ((found_count++))
                done <<< "$files"
            fi
        fi
    done

    if [ -z "$writable_files" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No world writable files found in critical directories"
    else
        # 최대 10개까지만 표시
        if [ "$found_count" -gt 10 ]; then
            local display_files=$(echo "$writable_files" | cut -d',' -f1-10)
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Found ${found_count} world writable files: ${display_files}, ... and $((found_count - 10)) more"
        else
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] World writable files: ${writable_files}"
        fi
    fi
}

# U-16: /dev에 존재하지 않아야 하는 device 파일 점검 (위험도: 상)
check_u16() {
    local check_id="U-16"
    local check_name="Unusual Device Files Check"
    local risk_level="HIGH"

    # /dev 디렉터리가 존재하는지 확인
    if [ ! -d "/dev" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] /dev directory does not exist"
        return
    fi

    # 일반 파일 형태의 디바이스 파일 검색 (정상적인 디바이스 파일은 블록/문자 디바이스여야 함)
    local unusual_files=$(find /dev -type f 2>/dev/null | head -20)

    if [ -z "$unusual_files" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No unusual device files found"
    else
        local file_count=$(echo "$unusual_files" | wc -l)
        local file_list=$(echo "$unusual_files" | head -10 | tr '\n' ', ' | sed 's/,$//')

        if [ "$file_count" -gt 10 ]; then
            file_list="${file_list} ... and $((file_count - 10)) more"
        fi

        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Found ${file_count} unusual files in /dev: ${file_list}"
    fi
}

# U-17: $HOME/.rhosts, hosts.equiv 사용 금지 (위험도: 상)
check_u17() {
    local check_id="U-17"
    local check_name="rhosts and hosts.equiv Usage Check"
    local risk_level="HIGH"

    local found_files=""
    local found_count=0

    # /etc/hosts.equiv 파일 검사
    if [ -f "/etc/hosts.equiv" ]; then
        found_files="${found_files}/etc/hosts.equiv, "
        ((found_count++))
    fi

    # 각 사용자 홈 디렉터리의 .rhosts 파일 검사
    while IFS=: read -r username _ uid _ _ homedir _; do
        if [ "$uid" -ge 0 ] && [ -d "$homedir" ]; then
            if [ -f "${homedir}/.rhosts" ]; then
                found_files="${found_files}${homedir}/.rhosts, "
                ((found_count++))
            fi
        fi
    done < /etc/passwd

    if [ -z "$found_files" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No .rhosts or hosts.equiv files found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Found ${found_count} files: ${found_files}"
    fi
}

# U-18: 접속 IP 및 포트 제한 (위험도: 상)
check_u18() {
    local check_id="U-18"
    local check_name="Connection IP and Port Restriction"
    local risk_level="HIGH"

    # 열려있는 포트 확인
    local listening_ports=$(ss -tulpen 2>/dev/null | grep LISTEN | wc -l)

    if [ -z "$listening_ports" ] || [ "$listening_ports" -eq 0 ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No listening ports found"
        return
    fi

    # 방화벽 설정 확인 (firewalld 또는 iptables)
    local firewall_active=false

    if command -v firewall-cmd &>/dev/null; then
        if systemctl is-active firewalld &>/dev/null; then
            firewall_active=true
        fi
    fi

    if [ "$firewall_active" == false ]; then
        if command -v iptables &>/dev/null; then
            local iptables_rules=$(iptables -L -n 2>/dev/null | grep -v "^Chain\|^target" | wc -l)
            if [ "$iptables_rules" -gt 0 ]; then
                firewall_active=true
            fi
        fi
    fi

    # TCP Wrapper 확인
    local tcp_wrapper_exists=false
    if [ -f "/etc/hosts.allow" ] || [ -f "/etc/hosts.deny" ]; then
        tcp_wrapper_exists=true
    fi

    if [ "$firewall_active" == true ] || [ "$tcp_wrapper_exists" == true ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Firewall or TCP Wrapper is configured (listening ports: ${listening_ports})"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] No firewall or TCP Wrapper configured (listening ports: ${listening_ports})"
    fi
}

# U-19: Finger 서비스 비활성화 (위험도: 상)
check_u19() {
    local check_id="U-19"
    local check_name="Finger Service Disabled"
    local risk_level="HIGH"

    # finger 서비스 확인
    local finger_status=""

    if command -v systemctl &>/dev/null; then
        finger_status=$(systemctl is-enabled finger 2>/dev/null)
    fi

    if [ -z "$finger_status" ] || [ "$finger_status" == "disabled" ] || [[ "$finger_status" == *"not-found"* ]]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Finger service is disabled or not installed"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Finger service is ${finger_status}"
    fi
}

# U-20: Anonymous FTP 비활성화 (위험도: 상)
check_u20() {
    local check_id="U-20"
    local check_name="Anonymous FTP Disabled"
    local risk_level="HIGH"

    # vsftpd 설정 파일 확인
    local vsftpd_conf="/etc/vsftpd/vsftpd.conf"

    if [ ! -f "$vsftpd_conf" ]; then
        # FTP 서비스가 설치되지 않은 경우
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] FTP service is not installed"
        return
    fi

    # anonymous_enable 설정 확인
    local anon_enabled=$(grep -i "^[[:space:]]*anonymous_enable" "$vsftpd_conf" | grep -v "^[[:space:]]*#" | tail -1 | awk -F= '{print tolower($2)}' | tr -d ' ')

    if [ -z "$anon_enabled" ] || [ "$anon_enabled" == "no" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Anonymous FTP is disabled"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Anonymous FTP is enabled (anonymous_enable=${anon_enabled})"
    fi
}

# U-21: r 계열 서비스 비활성화 (위험도: 상)
check_u21() {
    local check_id="U-21"
    local check_name="R-command Services Disabled"
    local risk_level="HIGH"

    local r_services=("rlogin" "rsh" "rexec")
    local enabled_services=""
    local enabled_count=0

    for service in "${r_services[@]}"; do
        if command -v systemctl &>/dev/null; then
            local status=$(systemctl is-enabled "$service" 2>/dev/null)
            if [ "$status" == "enabled" ]; then
                enabled_services="${enabled_services}${service}, "
                ((enabled_count++))
            fi
        fi
    done

    if [ -z "$enabled_services" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] All r-command services are disabled"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Enabled services: ${enabled_services}"
    fi
}

# U-22: cron 파일 소유자 및 권한 설정 (위험도: 상)
check_u22() {
    local check_id="U-22"
    local check_name="Cron File Owner and Permission"
    local risk_level="HIGH"

    local cron_file="/etc/crontab"

    if [ ! -f "$cron_file" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] /etc/crontab file does not exist"
        return
    fi

    local owner=$(stat -c %U "$cron_file")
    local perm=$(stat -c %a "$cron_file")

    local fail_reasons=""

    # 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        fail_reasons="${fail_reasons}owner is ${owner} (should be root), "
    fi

    # 권한이 640 이하인지 확인
    if [ "$perm" -gt 640 ]; then
        fail_reasons="${fail_reasons}permission is ${perm} (should be 640 or less)"
    fi

    if [ -z "$fail_reasons" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Owner: ${owner}, Permission: ${perm}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_reasons}"
    fi
}

# U-23: DoS 공격에 취약한 서비스 비활성화 (위험도: 상)
check_u23() {
    local check_id="U-23"
    local check_name="Vulnerable Services for DoS Attack Disabled"
    local risk_level="HIGH"

    local vulnerable_services=("echo" "discard" "daytime" "chargen")
    local enabled_services=""
    local enabled_count=0

    for service in "${vulnerable_services[@]}"; do
        if command -v systemctl &>/dev/null; then
            local status=$(systemctl is-enabled "$service" 2>/dev/null)
            if [ "$status" == "enabled" ]; then
                enabled_services="${enabled_services}${service}, "
                ((enabled_count++))
            fi
        fi
    done

    # xinetd 설정 확인
    if [ -d "/etc/xinetd.d" ]; then
        for service in "${vulnerable_services[@]}"; do
            if [ -f "/etc/xinetd.d/$service" ]; then
                local disabled=$(grep "disable.*=.*yes" "/etc/xinetd.d/$service" 2>/dev/null)
                if [ -z "$disabled" ]; then
                    enabled_services="${enabled_services}xinetd:${service}, "
                    ((enabled_count++))
                fi
            fi
        done
    fi

    if [ -z "$enabled_services" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No vulnerable services enabled"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Enabled services: ${enabled_services}"
    fi
}

# U-24: NFS 서비스 비활성화 (위험도: 상)
check_u24() {
    local check_id="U-24"
    local check_name="NFS Service Disabled"
    local risk_level="HIGH"

    local nfs_status=""

    if command -v systemctl &>/dev/null; then
        nfs_status=$(systemctl is-enabled nfs-server 2>/dev/null)
    fi

    if [ -z "$nfs_status" ] || [ "$nfs_status" == "disabled" ] || [[ "$nfs_status" == *"not-found"* ]]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] NFS service is disabled or not installed"
    else
        # NFS가 활성화된 경우, 사용 중인지 확인
        local nfs_exports=$(cat /etc/exports 2>/dev/null | grep -v "^#" | grep -v "^$")
        if [ -n "$nfs_exports" ]; then
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] NFS service is ${nfs_status} and in use"
        else
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] NFS service is ${nfs_status} but not configured"
        fi
    fi
}

# U-25: NFS 접근 통제 (위험도: 상)
check_u25() {
    local check_id="U-25"
    local check_name="NFS Access Control"
    local risk_level="HIGH"

    local exports_file="/etc/exports"

    if [ ! -f "$exports_file" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] /etc/exports file does not exist"
        return
    fi

    # 활성 설정 라인 추출 (주석 제외)
    local active_exports=$(grep -v "^#" "$exports_file" | grep -v "^$")

    if [ -z "$active_exports" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No NFS exports configured"
        return
    fi

    # everyone 접근 허용 여부 확인 (*, 0.0.0.0 등)
    local insecure_exports=$(echo "$active_exports" | grep -E '\*|0\.0\.0\.0|everyone')

    if [ -z "$insecure_exports" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] NFS exports have proper access control"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Insecure NFS exports found: everyone access allowed"
    fi
}

# U-26: automountd 제거 (위험도: 상)
check_u26() {
    local check_id="U-26"
    local check_name="Automountd Service Disabled"
    local risk_level="HIGH"

    local autofs_status=""

    if command -v systemctl &>/dev/null; then
        autofs_status=$(systemctl is-enabled autofs 2>/dev/null)
    fi

    if [ -z "$autofs_status" ] || [ "$autofs_status" == "disabled" ] || [[ "$autofs_status" == *"not-found"* ]]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Autofs service is disabled or not installed"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Autofs service is ${autofs_status}"
    fi
}

# U-27: RPC 서비스 점검 (위험도: 상)
check_u27() {
    local check_id="U-27"
    local check_name="RPC Service Check"
    local risk_level="HIGH"

    # rpcbind 서비스 확인
    local rpcbind_status=""

    if command -v systemctl &>/dev/null; then
        rpcbind_status=$(systemctl is-active rpcbind 2>/dev/null)
    fi

    if [ "$rpcbind_status" == "active" ]; then
        # RPC 서비스가 실행 중인 경우 rpcinfo로 확인
        if command -v rpcinfo &>/dev/null; then
            local rpc_services=$(rpcinfo -p 2>/dev/null | wc -l)
            if [ "$rpc_services" -gt 0 ]; then
                log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] RPC services are running (${rpc_services} services found)"
            else
                log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No RPC services registered"
            fi
        else
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] rpcbind is active"
        fi
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] RPC service is not active"
    fi
}

# U-28: NIS 서비스 비활성화 (위험도: 상)
check_u28() {
    local check_id="U-28"
    local check_name="NIS Service Disabled"
    local risk_level="HIGH"

    local nis_services=("ypserv" "ypbind")
    local enabled_services=""
    local enabled_count=0

    for service in "${nis_services[@]}"; do
        if command -v systemctl &>/dev/null; then
            local status=$(systemctl is-enabled "$service" 2>/dev/null)
            if [ "$status" == "enabled" ]; then
                enabled_services="${enabled_services}${service}, "
                ((enabled_count++))
            fi
        fi
    done

    if [ -z "$enabled_services" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] NIS services are disabled or not installed"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Enabled services: ${enabled_services}"
    fi
}

# U-29: tftp, talk 서비스 비활성화 (위험도: 상)
check_u29() {
    local check_id="U-29"
    local check_name="TFTP and Talk Services Disabled"
    local risk_level="HIGH"

    local services=("tftp" "talk" "ntalk")
    local enabled_services=""
    local enabled_count=0

    for service in "${services[@]}"; do
        if command -v systemctl &>/dev/null; then
            local status=$(systemctl is-enabled "$service" 2>/dev/null)
            if [ "$status" == "enabled" ]; then
                enabled_services="${enabled_services}${service}, "
                ((enabled_count++))
            fi
        fi
    done

    if [ -z "$enabled_services" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] TFTP and Talk services are disabled"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Enabled services: ${enabled_services}"
    fi
}

# U-30: Sendmail 버전 점검 (위험도: 상)
check_u30() {
    local check_id="U-30"
    local check_name="Sendmail Version Check"
    local risk_level="HIGH"

    # sendmail이 설치되어 있는지 확인
    if ! command -v sendmail &>/dev/null; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Sendmail is not installed"
        return
    fi

    # sendmail 버전 확인
    local sendmail_version=$(sendmail -d0.1 -bv root 2>&1 | grep "Version" | head -1)

    if [ -n "$sendmail_version" ]; then
        # 취약 버전인지 확인 (8.12.0 미만 버전은 취약)
        # 실제 운영 환경에서는 최신 패치 여부를 확인해야 함
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Sendmail version: ${sendmail_version} (manual verification required)"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Cannot determine Sendmail version"
    fi
}

# U-31: 스팸 메일 릴레이 제한 (위험도: 상)
check_u31() {
    local check_id="U-31"
    local check_name="Mail Relay Restriction"
    local risk_level="HIGH"

    local sendmail_mc="/etc/mail/sendmail.mc"
    local sendmail_cf="/etc/mail/sendmail.cf"

    # sendmail이 설치되지 않은 경우
    if [ ! -f "$sendmail_mc" ] && [ ! -f "$sendmail_cf" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Sendmail configuration files not found"
        return
    fi

    # relay 제한 설정 확인
    local relay_config=""

    if [ -f "$sendmail_mc" ]; then
        relay_config=$(grep -i "RELAY" "$sendmail_mc" 2>/dev/null | grep -v "^dnl")
    fi

    if [ -f "$sendmail_cf" ]; then
        local relay_cf=$(grep -i "R.*Relaying" "$sendmail_cf" 2>/dev/null)
        relay_config="${relay_config}${relay_cf}"
    fi

    # access 파일 확인
    if [ -f "/etc/mail/access" ]; then
        local relay_access=$(grep -i "relay" "/etc/mail/access" 2>/dev/null | grep -v "^#")
        if [ -n "$relay_access" ]; then
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Mail relay restrictions are configured"
            return
        fi
    fi

    if [ -n "$relay_config" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Relay configuration found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] No relay restrictions configured"
    fi
}

# U-32: 일반사용자의 Sendmail 실행 방지 (위험도: 상)
check_u32() {
    local check_id="U-32"
    local check_name="Sendmail Execution Restriction"
    local risk_level="HIGH"

    if [ ! -f "/usr/sbin/sendmail" ] && [ ! -f "/usr/lib/sendmail" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Sendmail is not installed"
        return
    fi

    local sendmail_path=""
    if [ -f "/usr/sbin/sendmail" ]; then
        sendmail_path="/usr/sbin/sendmail"
    elif [ -f "/usr/lib/sendmail" ]; then
        sendmail_path="/usr/lib/sendmail"
    fi

    local owner=$(stat -c %U "$sendmail_path" 2>/dev/null)
    local perm=$(stat -c %a "$sendmail_path" 2>/dev/null)

    local fail_reasons=""

    # 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        fail_reasons="${fail_reasons}owner is ${owner} (should be root), "
    fi

    # SUID 비트 확인 (4755는 일반적이나, 더 제한적으로 설정 가능)
    local first_digit=${perm:0:1}
    if [ "$first_digit" == "4" ]; then
        # SUID가 설정되어 있는 경우 (일반적이나 주의 필요)
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Sendmail has SUID bit (${perm}) - review if necessary"
    elif [ "$perm" -le 755 ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Owner: ${owner}, Permission: ${perm}"
    else
        fail_reasons="${fail_reasons}permission is ${perm} (too permissive)"
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_reasons}"
    fi
}

# U-33: DNS 보안 버전 패치 (위험도: 상)
check_u33() {
    local check_id="U-33"
    local check_name="DNS Security Version Check"
    local risk_level="HIGH"

    # named (BIND) 확인
    if ! command -v named &>/dev/null; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] DNS service (named) is not installed"
        return
    fi

    local named_version=$(named -v 2>/dev/null | head -1)

    if [ -n "$named_version" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] DNS version: ${named_version} (manual verification required)"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Cannot determine DNS version"
    fi
}

# U-34: DNS Zone Transfer 설정 (위험도: 상)
check_u34() {
    local check_id="U-34"
    local check_name="DNS Zone Transfer Restriction"
    local risk_level="HIGH"

    local named_conf="/etc/named.conf"

    if [ ! -f "$named_conf" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] named.conf file does not exist"
        return
    fi

    # allow-transfer 설정 확인
    local allow_transfer=$(grep -i "allow-transfer" "$named_conf" 2>/dev/null | grep -v "^[[:space:]]*//")

    if [ -n "$allow_transfer" ]; then
        # any나 0.0.0.0이 포함되어 있는지 확인
        local insecure=$(echo "$allow_transfer" | grep -E "any|0\.0\.0\.0")
        if [ -n "$insecure" ]; then
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Zone transfer allows unrestricted access"
        else
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Zone transfer is restricted"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] No allow-transfer configuration found"
    fi
}

# U-35: 웹서비스 디렉토리 리스팅 제거 (위험도: 상)
check_u35() {
    local check_id="U-35"
    local check_name="Web Service Directory Listing Disabled"
    local risk_level="HIGH"

    # Apache 설정 파일 경로
    local apache_configs=("/etc/httpd/conf/httpd.conf" "/etc/apache2/apache2.conf")
    local config_found=false
    local indexes_enabled=false

    for config in "${apache_configs[@]}"; do
        if [ -f "$config" ]; then
            config_found=true
            # Indexes 옵션 확인
            local indexes=$(grep -i "Options.*Indexes" "$config" 2>/dev/null | grep -v "^[[:space:]]*#")
            if [ -n "$indexes" ]; then
                # -Indexes가 아닌 Indexes가 있는지 확인
                local positive_indexes=$(echo "$indexes" | grep -v "\-Indexes")
                if [ -n "$positive_indexes" ]; then
                    indexes_enabled=true
                fi
            fi
        fi
    done

    # conf.d 디렉토리 확인
    for conf_dir in "/etc/httpd/conf.d" "/etc/apache2/conf.d" "/etc/apache2/sites-enabled"; do
        if [ -d "$conf_dir" ]; then
            config_found=true
            local indexes=$(grep -ri "Options.*Indexes" "$conf_dir" 2>/dev/null | grep -v "^[[:space:]]*#" | grep -v ".conf:#")
            if [ -n "$indexes" ]; then
                local positive_indexes=$(echo "$indexes" | grep -v "\-Indexes")
                if [ -n "$positive_indexes" ]; then
                    indexes_enabled=true
                fi
            fi
        fi
    done

    if [ "$config_found" == false ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Web service configuration not found"
    elif [ "$indexes_enabled" == true ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Directory listing (Indexes) is enabled"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Directory listing is disabled"
    fi
}

# U-36: 웹서비스 웹 프로세스 권한 제한 (위험도: 상)
check_u36() {
    local check_id="U-36"
    local check_name="Web Process User Privilege Restriction"
    local risk_level="HIGH"

    # 실행 중인 웹 서버 프로세스 확인
    local web_processes=$(ps -ef | grep -E "httpd|apache2|nginx" | grep -v grep)

    if [ -z "$web_processes" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] No web server processes running"
        return
    fi

    # root로 실행되는 웹 프로세스 확인 (마스터 프로세스 제외)
    local root_workers=$(ps -ef | grep -E "httpd|apache2|nginx" | grep -v grep | grep -v "^root" | wc -l)
    local root_processes=$(ps -ef | grep -E "httpd|apache2|nginx" | grep -v grep | grep "^root" | wc -l)

    # worker 프로세스가 non-root로 실행되는지 확인
    if [ "$root_workers" -gt 0 ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Web server processes running as non-root user"
    elif [ "$root_processes" -gt 1 ]; then
        # root로 실행되는 프로세스가 여러 개 (마스터뿐만 아니라 워커도)
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Web server worker processes running as root"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Only master process running as root"
    fi
}

# U-37: 웹서비스 상위 디렉토리 접근 금지 (위험도: 상)
check_u37() {
    local check_id="U-37"
    local check_name="Web Service Parent Directory Access Restriction"
    local risk_level="HIGH"

    local apache_configs=("/etc/httpd/conf/httpd.conf" "/etc/apache2/apache2.conf")
    local config_found=false
    local allowoverride_all=false

    for config in "${apache_configs[@]}"; do
        if [ -f "$config" ]; then
            config_found=true
            # AllowOverride All 설정 확인 (상위 디렉토리 접근 가능)
            local allowoverride=$(grep -i "AllowOverride.*All" "$config" 2>/dev/null | grep -v "^[[:space:]]*#")
            if [ -n "$allowoverride" ]; then
                allowoverride_all=true
            fi
        fi
    done

    if [ "$config_found" == false ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Web service configuration not found"
    elif [ "$allowoverride_all" == true ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] AllowOverride All is enabled (may allow .htaccess parent directory access)"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Parent directory access is properly restricted"
    fi
}

# U-38: 웹서비스 불필요한 파일 제거 (위험도: 상)
check_u38() {
    local check_id="U-38"
    local check_name="Web Service Unnecessary Files Removal"
    local risk_level="HIGH"

    local web_dirs=("/var/www/html" "/var/www" "/usr/share/nginx/html")
    local manual_dir=""
    local found_manual=false

    for web_dir in "${web_dirs[@]}"; do
        if [ -d "$web_dir" ]; then
            # 매뉴얼, 샘플 파일 확인
            local manual_files=$(find "$web_dir" -type d -name "manual" -o -name "doc" -o -name "example" 2>/dev/null | head -10)
            if [ -n "$manual_files" ]; then
                found_manual=true
                manual_dir="${manual_dir}$(echo "$manual_files" | tr '\n' ', ')"
            fi
        fi
    done

    if [ "$found_manual" == true ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Sample/manual directories found: ${manual_dir}"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No unnecessary sample/manual files found"
    fi
}

# U-39: 웹서비스 링크 사용 금지 (위험도: 상)
check_u39() {
    local check_id="U-39"
    local check_name="Web Service Symbolic Link Restriction"
    local risk_level="HIGH"

    local apache_configs=("/etc/httpd/conf/httpd.conf" "/etc/apache2/apache2.conf")
    local config_found=false
    local followsymlinks_enabled=false

    for config in "${apache_configs[@]}"; do
        if [ -f "$config" ]; then
            config_found=true
            # FollowSymLinks 옵션 확인
            local symlinks=$(grep -i "Options.*FollowSymLinks" "$config" 2>/dev/null | grep -v "^[[:space:]]*#")
            if [ -n "$symlinks" ]; then
                # -FollowSymLinks가 아닌 FollowSymLinks가 있는지 확인
                local positive_symlinks=$(echo "$symlinks" | grep -v "\-FollowSymLinks" | grep "FollowSymLinks")
                if [ -n "$positive_symlinks" ]; then
                    followsymlinks_enabled=true
                fi
            fi
        fi
    done

    if [ "$config_found" == false ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Web service configuration not found"
    elif [ "$followsymlinks_enabled" == true ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] FollowSymLinks is enabled"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] FollowSymLinks is disabled"
    fi
}

# U-40: 웹서비스 파일 업로드 및 다운로드 제한 (위험도: 상)
check_u40() {
    local check_id="U-40"
    local check_name="Web Service Upload/Download Size Restriction"
    local risk_level="HIGH"

    local apache_configs=("/etc/httpd/conf/httpd.conf" "/etc/apache2/apache2.conf")
    local config_found=false
    local limit_set=false

    for config in "${apache_configs[@]}"; do
        if [ -f "$config" ]; then
            config_found=true
            # LimitRequestBody 설정 확인
            local limit=$(grep -i "LimitRequestBody" "$config" 2>/dev/null | grep -v "^[[:space:]]*#")
            if [ -n "$limit" ]; then
                limit_set=true
            fi
        fi
    done

    # conf.d 디렉토리도 확인
    for conf_dir in "/etc/httpd/conf.d" "/etc/apache2/conf.d"; do
        if [ -d "$conf_dir" ]; then
            config_found=true
            local limit=$(grep -ri "LimitRequestBody" "$conf_dir" 2>/dev/null | grep -v "^[[:space:]]*#")
            if [ -n "$limit" ]; then
                limit_set=true
            fi
        fi
    done

    if [ "$config_found" == false ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Web service configuration not found"
    elif [ "$limit_set" == true ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Upload/download size limit is configured"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] No upload/download size limit configured"
    fi
}

# U-41: 웹서비스 영역의 분리 (위험도: 상)
check_u41() {
    local check_id="U-41"
    local check_name="Web Service Area Separation"
    local risk_level="HIGH"

    # 웹 디렉토리가 별도 파티션에 있는지 확인
    local web_dirs=("/var/www" "/usr/share/nginx/html")
    local separate_partition=false

    for web_dir in "${web_dirs[@]}"; do
        if [ -d "$web_dir" ]; then
            # 해당 디렉토리가 별도 마운트 포인트인지 확인
            local mount_point=$(df "$web_dir" 2>/dev/null | tail -1 | awk '{print $6}')
            if [ "$mount_point" == "$web_dir" ] || [ "$mount_point" == "/var" ]; then
                separate_partition=true
                log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Web directory is on separate partition: ${mount_point}"
                return
            fi
        fi
    done

    log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Web directory is not on separate partition (recommended for security)"
}

# U-42: 최신 보안패치 및 벤더 권고사항 적용 (위험도: 상)
check_u42() {
    local check_id="U-42"
    local check_name="Latest Security Patches Applied"
    local risk_level="HIGH"

    # 시스템 정보 확인
    local kernel_version=$(uname -r)
    local os_version=$(cat /etc/redhat-release 2>/dev/null || echo "Unknown")

    # 마지막 업데이트 확인
    local last_update=""
    if command -v rpm &>/dev/null; then
        last_update=$(rpm -qa --last | head -5)
    fi

    # 업데이트 가능한 패키지 확인
    local updates_available=0
    if command -v dnf &>/dev/null; then
        updates_available=$(dnf check-update 2>/dev/null | grep -E "^[a-zA-Z]" | wc -l)
    elif command -v yum &>/dev/null; then
        updates_available=$(yum check-update 2>/dev/null | grep -E "^[a-zA-Z]" | wc -l)
    fi

    if [ "$updates_available" -eq 0 ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] System is up to date. Kernel: ${kernel_version}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${updates_available} updates available. Kernel: ${kernel_version}"
    fi
}

# U-43: 로그의 정기적 검토 및 보고 (위험도: 상)
check_u43() {
    local check_id="U-43"
    local check_name="Regular Log Review and Reporting"
    local risk_level="HIGH"

    # 로그 파일 존재 확인
    local log_files=("/var/log/messages" "/var/log/secure" "/var/log/audit/audit.log")
    local logs_found=0
    local logs_detail=""

    for log_file in "${log_files[@]}"; do
        if [ -f "$log_file" ]; then
            ((logs_found++))
            local log_size=$(du -h "$log_file" 2>/dev/null | awk '{print $1}')
            local log_modified=$(stat -c %y "$log_file" 2>/dev/null | cut -d' ' -f1)
            logs_detail="${logs_detail}${log_file}(${log_size}, modified:${log_modified}), "
        fi
    done

    # rsyslog 또는 syslog 서비스 확인
    local logging_active=false
    if systemctl is-active rsyslog &>/dev/null || systemctl is-active syslog &>/dev/null; then
        logging_active=true
    fi

    if [ "$logs_found" -gt 0 ] && [ "$logging_active" == true ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Logging is active. ${logs_found} log files found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Logging service not active or log files not found"
    fi
}

# U-44: 취약점 관리 - root 이외의 UID가 '0' 금지 (위험도: 상)
check_u44() {
    local check_id="U-44"
    local check_name="Prevent Non-root UID 0 Accounts"
    local risk_level="HIGH"

    # UID가 0인 계정 확인 (root 제외)
    local uid_zero_accounts=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd)

    if [ -z "$uid_zero_accounts" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No non-root accounts with UID 0"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Non-root accounts with UID 0: ${uid_zero_accounts}"
    fi
}

# U-45: 취약점 관리 - root 계정 su 제한 (위험도: 상)
check_u45() {
    local check_id="U-45"
    local check_name="Root Account su Command Restriction"
    local risk_level="HIGH"

    local pam_su="/etc/pam.d/su"

    if [ ! -f "$pam_su" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] /etc/pam.d/su file does not exist"
        return
    fi

    # pam_wheel 모듈 설정 확인
    local wheel_config=$(grep "pam_wheel" "$pam_su" | grep -v "^[[:space:]]*#")

    if [ -n "$wheel_config" ]; then
        # wheel 그룹 설정이 있는 경우
        local wheel_required=$(echo "$wheel_config" | grep "use_uid")
        if [ -n "$wheel_required" ]; then
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] su command is restricted to wheel group"
        else
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] pam_wheel is configured"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] su command is not restricted (pam_wheel not configured)"
    fi
}

# U-46: 패스워드 최소 길이 설정 (위험도: 중)
check_u46() {
    local check_id="U-46"
    local check_name="Password Minimum Length"
    local risk_level="MEDIUM"

    local pwquality_conf="/etc/security/pwquality.conf"

    if [ ! -f "$pwquality_conf" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] pwquality.conf file does not exist"
        return
    fi

    # 최소 패스워드 길이 검사 (8자리 이상)
    local minlen=$(grep -i "^[[:space:]]*minlen" "$pwquality_conf" | grep -v "^[[:space:]]*#" | tail -1 | awk -F= '{print $2}' | tr -d ' ')

    if [ -n "$minlen" ] && [ "$minlen" -ge 8 ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Minimum password length is ${minlen}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Minimum password length not set or less than 8 (current: ${minlen:-'not set'})"
    fi
}

# U-47: 패스워드 최대 사용기간 설정 (위험도: 중)
check_u47() {
    local check_id="U-47"
    local check_name="Password Maximum Age"
    local risk_level="MEDIUM"

    local login_defs="/etc/login.defs"

    if [ ! -f "$login_defs" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] /etc/login.defs file does not exist"
        return
    fi

    # PASS_MAX_DAYS 설정 확인
    local pass_max_days=$(grep "^[[:space:]]*PASS_MAX_DAYS" "$login_defs" | grep -v "^[[:space:]]*#" | awk '{print $2}')

    if [ -n "$pass_max_days" ] && [ "$pass_max_days" -le 90 ] && [ "$pass_max_days" -gt 0 ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Password max age is ${pass_max_days} days"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Password max age not properly set (current: ${pass_max_days:-'not set'}, should be 1-90 days)"
    fi
}

# U-48: 패스워드 최소 사용기간 설정 (위험도: 중)
check_u48() {
    local check_id="U-48"
    local check_name="Password Minimum Age"
    local risk_level="MEDIUM"

    local login_defs="/etc/login.defs"

    if [ ! -f "$login_defs" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] /etc/login.defs file does not exist"
        return
    fi

    # PASS_MIN_DAYS 설정 확인
    local pass_min_days=$(grep "^[[:space:]]*PASS_MIN_DAYS" "$login_defs" | grep -v "^[[:space:]]*#" | awk '{print $2}')

    if [ -n "$pass_min_days" ] && [ "$pass_min_days" -ge 1 ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Password min age is ${pass_min_days} days"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Password min age not set or less than 1 (current: ${pass_min_days:-'not set'})"
    fi
}

# U-49: 불필요한 계정 제거 (위험도: 중)
check_u49() {
    local check_id="U-49"
    local check_name="Unnecessary Accounts Removal"
    local risk_level="MEDIUM"

    # 로그인 가능한 불필요한 계정 확인 (UID >= 1000이지만 오랫동안 로그인하지 않은 계정)
    local unnecessary_accounts=""
    local count=0

    # 시스템 계정 중 불필요한 계정 (일반적으로 nologin이어야 하는 계정들)
    local system_accounts=("lp" "news" "uucp" "games" "gopher")

    for account in "${system_accounts[@]}"; do
        local account_info=$(grep "^${account}:" /etc/passwd 2>/dev/null)
        if [ -n "$account_info" ]; then
            local shell=$(echo "$account_info" | cut -d: -f7)
            # 로그인 가능한 쉘이 설정되어 있는지 확인
            if [[ "$shell" != "/sbin/nologin" && "$shell" != "/bin/false" && "$shell" != "/usr/sbin/nologin" ]]; then
                unnecessary_accounts="${unnecessary_accounts}${account}(shell:${shell}), "
                ((count++))
            fi
        fi
    done

    if [ -z "$unnecessary_accounts" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No unnecessary accounts with login shell found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Unnecessary accounts found: ${unnecessary_accounts}"
    fi
}

# U-50: 관리자 그룹에 최소한의 계정 포함 (위험도: 중)
check_u50() {
    local check_id="U-50"
    local check_name="Minimize Administrator Group Members"
    local risk_level="MEDIUM"

    # wheel 그룹 확인
    local wheel_members=$(getent group wheel 2>/dev/null | cut -d: -f4)

    if [ -z "$wheel_members" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No users in wheel group"
    else
        local member_count=$(echo "$wheel_members" | tr ',' '\n' | wc -l)
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Wheel group members (${member_count}): ${wheel_members} (verify if necessary)"
    fi
}

# U-51: 계정이 존재하지 않는 GID 금지 (위험도: 중)
check_u51() {
    local check_id="U-51"
    local check_name="Prevent Non-existent GID"
    local risk_level="MEDIUM"

    # /etc/passwd의 GID가 /etc/group에 존재하는지 확인
    local invalid_gids=""
    local count=0

    while IFS=: read -r username _ uid gid _ _ _; do
        # GID가 /etc/group에 존재하는지 확인
        if ! getent group "$gid" &>/dev/null; then
            invalid_gids="${invalid_gids}${username}(GID:${gid}), "
            ((count++))
        fi
    done < /etc/passwd

    if [ -z "$invalid_gids" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] All user GIDs exist in /etc/group"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Users with non-existent GID: ${invalid_gids}"
    fi
}

# U-52: 동일한 UID 금지 (위험도: 중)
check_u52() {
    local check_id="U-52"
    local check_name="Prevent Duplicate UIDs"
    local risk_level="MEDIUM"

    # 중복된 UID 확인
    local duplicate_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)

    if [ -z "$duplicate_uids" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No duplicate UIDs found"
    else
        local dup_details=""
        for uid in $duplicate_uids; do
            local users=$(awk -F: -v uid="$uid" '$3==uid {print $1}' /etc/passwd | tr '\n' ',' | sed 's/,$//')
            dup_details="${dup_details}UID ${uid}(${users}), "
        done
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Duplicate UIDs found: ${dup_details}"
    fi
}

# U-53: 사용자 shell 점검 (위험도: 중)
check_u53() {
    local check_id="U-53"
    local check_name="User Shell Check"
    local risk_level="MEDIUM"

    # /etc/shells에 등록된 유효한 쉘 목록
    local valid_shells=""
    if [ -f "/etc/shells" ]; then
        valid_shells=$(cat /etc/shells | grep -v "^#" | grep -v "^$")
    fi

    # 유효하지 않은 쉘을 사용하는 계정 확인
    local invalid_shell_users=""
    local count=0

    while IFS=: read -r username _ uid _ _ _ shell; do
        # 로그인 가능한 쉘이 설정된 경우만 확인
        if [[ "$shell" != "/sbin/nologin" && "$shell" != "/bin/false" && "$shell" != "/usr/sbin/nologin" ]]; then
            # /etc/shells에 등록되어 있는지 확인
            if [ -n "$valid_shells" ]; then
                if ! echo "$valid_shells" | grep -q "^${shell}$"; then
                    invalid_shell_users="${invalid_shell_users}${username}(${shell}), "
                    ((count++))
                fi
            fi
        fi
    done < /etc/passwd

    if [ -z "$invalid_shell_users" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] All user shells are valid"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Users with invalid shells: ${invalid_shell_users}"
    fi
}

# U-54: Session Timeout 설정 (위험도: 중)
check_u54() {
    local check_id="U-54"
    local check_name="Session Timeout Configuration"
    local risk_level="MEDIUM"

    local config_files=("/etc/profile" "/etc/bashrc" "/etc/bash.bashrc")
    local tmout_set=false
    local tmout_value=""

    for config in "${config_files[@]}"; do
        if [ -f "$config" ]; then
            local tmout=$(grep "^[[:space:]]*TMOUT=" "$config" | grep -v "^[[:space:]]*#" | tail -1)
            if [ -n "$tmout" ]; then
                tmout_set=true
                tmout_value=$(echo "$tmout" | cut -d= -f2 | tr -d ' ' | tr -d ';')
                break
            fi
        fi
    done

    if [ "$tmout_set" == true ]; then
        # TMOUT 값이 적절한지 확인 (600초 = 10분 이하 권장)
        if [ "$tmout_value" -le 600 ] && [ "$tmout_value" -gt 0 ]; then
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Session timeout is set to ${tmout_value} seconds"
        else
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Session timeout too long (${tmout_value} seconds, should be <= 600)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Session timeout (TMOUT) is not configured"
    fi
}

# U-55: hosts.lpd 파일 소유자 및 권한 설정 (위험도: 중)
check_u55() {
    local check_id="U-55"
    local check_name="hosts.lpd File Owner and Permission"
    local risk_level="MEDIUM"

    local hosts_lpd="/etc/hosts.lpd"

    if [ ! -f "$hosts_lpd" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] /etc/hosts.lpd file does not exist"
        return
    fi

    local owner=$(stat -c %U "$hosts_lpd")
    local perm=$(stat -c %a "$hosts_lpd")

    local fail_reasons=""

    # 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        fail_reasons="${fail_reasons}owner is ${owner} (should be root), "
    fi

    # 권한이 600 이하인지 확인
    if [ "$perm" -gt 600 ]; then
        fail_reasons="${fail_reasons}permission is ${perm} (should be 600 or less)"
    fi

    if [ -z "$fail_reasons" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Owner: ${owner}, Permission: ${perm}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_reasons}"
    fi
}

# U-56: UMASK 설정 관리 (위험도: 중)
check_u56() {
    local check_id="U-56"
    local check_name="UMASK Configuration"
    local risk_level="MEDIUM"

    local config_files=("/etc/profile" "/etc/bashrc" "/etc/bash.bashrc" "/etc/login.defs")
    local umask_set=false
    local umask_value=""

    for config in "${config_files[@]}"; do
        if [ -f "$config" ]; then
            local umask_line=$(grep "^[[:space:]]*umask" "$config" | grep -v "^[[:space:]]*#" | tail -1)
            if [ -n "$umask_line" ]; then
                umask_set=true
                umask_value=$(echo "$umask_line" | awk '{print $2}')
                break
            fi
        fi
    done

    if [ "$umask_set" == true ]; then
        # UMASK 값이 022 또는 027인지 확인
        if [[ "$umask_value" == "022" || "$umask_value" == "027" ]]; then
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] UMASK is set to ${umask_value}"
        else
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] UMASK is ${umask_value} (should be 022 or 027)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] UMASK is not configured"
    fi
}

# U-57: 홈디렉토리 소유자 및 권한 설정 (위험도: 중)
check_u57() {
    local check_id="U-57"
    local check_name="Home Directory Owner and Permission"
    local risk_level="MEDIUM"

    local vulnerable_dirs=""
    local count=0

    # 일반 사용자 홈 디렉토리 검사 (UID >= 1000)
    while IFS=: read -r username _ uid _ _ homedir _; do
        if [ "$uid" -ge 1000 ] && [ -d "$homedir" ]; then
            local owner=$(stat -c %U "$homedir" 2>/dev/null)
            local perm=$(stat -c %a "$homedir" 2>/dev/null)

            # 소유자가 사용자 본인인지 확인
            if [ "$owner" != "$username" ]; then
                vulnerable_dirs="${vulnerable_dirs}${homedir}(owner:${owner}), "
                ((count++))
                continue
            fi

            # 권한이 750 이하인지 확인 (other에게 권한 없음)
            local last_digit=${perm: -1}
            if [ "$last_digit" -gt 0 ]; then
                vulnerable_dirs="${vulnerable_dirs}${homedir}(perm:${perm}), "
                ((count++))
            fi
        fi
    done < /etc/passwd

    if [ -z "$vulnerable_dirs" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] All home directories have proper owner and permissions"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Vulnerable directories (${count}): ${vulnerable_dirs}"
    fi
}

# U-58: 홈디렉토리로 지정한 디렉토리의 존재 관리 (위험도: 중)
check_u58() {
    local check_id="U-58"
    local check_name="Home Directory Existence Check"
    local risk_level="MEDIUM"

    local missing_dirs=""
    local count=0

    # 홈 디렉토리가 존재하지 않는 계정 확인
    while IFS=: read -r username _ uid _ _ homedir shell; do
        # 로그인 가능한 계정만 확인 (nologin이 아닌 경우)
        if [[ "$shell" != "/sbin/nologin" && "$shell" != "/bin/false" && "$shell" != "/usr/sbin/nologin" ]]; then
            if [ ! -d "$homedir" ]; then
                missing_dirs="${missing_dirs}${username}(${homedir}), "
                ((count++))
            fi
        fi
    done < /etc/passwd

    if [ -z "$missing_dirs" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] All user home directories exist"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Missing home directories (${count}): ${missing_dirs}"
    fi
}

# U-59: 숨김 파일 및 디렉토리 검색 및 제거 (위험도: 중)
check_u59() {
    local check_id="U-59"
    local check_name="Hidden Files and Directories Check"
    local risk_level="MEDIUM"

    # 홈 디렉토리에서 의심스러운 숨김 파일 검색 (일반적이지 않은 파일)
    local suspicious_files=""
    local count=0

    # 정상적인 숨김 파일 목록 (제외할 파일)
    local normal_hidden=(".bash_logout .bash_profile .bashrc .bash_history .profile .ssh .gnupg .config .local .cache")

    # 일반 사용자 홈 디렉토리에서 숨김 파일 확인
    while IFS=: read -r username _ uid _ _ homedir _; do
        if [ "$uid" -ge 1000 ] && [ -d "$homedir" ]; then
            # 숨김 파일 찾기
            local hidden_files=$(find "$homedir" -maxdepth 1 -name ".*" -type f 2>/dev/null)

            if [ -n "$hidden_files" ]; then
                while IFS= read -r file; do
                    local basename=$(basename "$file")
                    # 정상 파일 목록에 없는 경우
                    if ! echo "$normal_hidden" | grep -q "$basename"; then
                        if [ "$count" -lt 10 ]; then
                            suspicious_files="${suspicious_files}${file}, "
                        fi
                        ((count++))
                    fi
                done <<< "$hidden_files"
            fi
        fi
    done < /etc/passwd

    if [ "$count" -eq 0 ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No suspicious hidden files found"
    else
        if [ "$count" -gt 10 ]; then
            suspicious_files="${suspicious_files}... and $((count - 10)) more"
        fi
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Found ${count} hidden files (manual review required): ${suspicious_files}"
    fi
}

# U-60: ssh 원격접속 허용 (위험도: 중)
check_u60() {
    local check_id="U-60"
    local check_name="SSH Access Control Policy"
    local risk_level="MEDIUM"

    local sshd_config="/etc/ssh/sshd_config"

    if [ ! -f "$sshd_config" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] sshd_config file does not exist"
        return
    fi

    # AllowUsers 또는 AllowGroups 설정 확인
    local allow_users=$(grep -i "^[[:space:]]*AllowUsers" "$sshd_config" | grep -v "^[[:space:]]*#")
    local allow_groups=$(grep -i "^[[:space:]]*AllowGroups" "$sshd_config" | grep -v "^[[:space:]]*#")

    if [ -n "$allow_users" ] || [ -n "$allow_groups" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] SSH access is restricted (AllowUsers/AllowGroups configured)"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] No SSH user/group restrictions configured (consider using AllowUsers or AllowGroups)"
    fi
}

# U-61: ftp 서비스 확인 (위험도: 중)
check_u61() {
    local check_id="U-61"
    local check_name="FTP Service Check"
    local risk_level="MEDIUM"

    local ftp_services=("vsftpd" "proftpd" "pureftpd")
    local enabled_services=""
    local enabled_count=0

    for service in "${ftp_services[@]}"; do
        if command -v systemctl &>/dev/null; then
            local status=$(systemctl is-enabled "$service" 2>/dev/null)
            if [ "$status" == "enabled" ]; then
                enabled_services="${enabled_services}${service}, "
                ((enabled_count++))
            fi
        fi
    done

    if [ -z "$enabled_services" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] FTP service is disabled or not installed"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] FTP services enabled: ${enabled_services} (use SFTP instead)"
    fi
}

# U-62: ftp 계정 shell 제한 (위험도: 중)
check_u62() {
    local check_id="U-62"
    local check_name="FTP Account Shell Restriction"
    local risk_level="MEDIUM"

    # ftp 계정 확인
    local ftp_account=$(grep "^ftp:" /etc/passwd 2>/dev/null)

    if [ -z "$ftp_account" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] FTP account does not exist"
        return
    fi

    local ftp_shell=$(echo "$ftp_account" | cut -d: -f7)

    if [[ "$ftp_shell" == "/sbin/nologin" || "$ftp_shell" == "/bin/false" || "$ftp_shell" == "/usr/sbin/nologin" ]]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] FTP account shell is ${ftp_shell}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] FTP account has login shell: ${ftp_shell}"
    fi
}

# U-63: ftpusers 파일 소유자 및 권한 설정 (위험도: 중)
check_u63() {
    local check_id="U-63"
    local check_name="ftpusers File Owner and Permission"
    local risk_level="MEDIUM"

    local ftpusers_files=("/etc/ftpusers" "/etc/vsftpd/ftpusers" "/etc/vsftpd.ftpusers")
    local file_found=false
    local ftpusers_file=""

    for file in "${ftpusers_files[@]}"; do
        if [ -f "$file" ]; then
            file_found=true
            ftpusers_file="$file"
            break
        fi
    done

    if [ "$file_found" == false ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] ftpusers file does not exist"
        return
    fi

    local owner=$(stat -c %U "$ftpusers_file")
    local perm=$(stat -c %a "$ftpusers_file")

    local fail_reasons=""

    # 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        fail_reasons="${fail_reasons}owner is ${owner} (should be root), "
    fi

    # 권한이 640 이하인지 확인
    if [ "$perm" -gt 640 ]; then
        fail_reasons="${fail_reasons}permission is ${perm} (should be 640 or less)"
    fi

    if [ -z "$fail_reasons" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] File: ${ftpusers_file}, Owner: ${owner}, Permission: ${perm}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] File: ${ftpusers_file}, ${fail_reasons}"
    fi
}

# U-64: ftpusers 파일 설정 (위험도: 중)
check_u64() {
    local check_id="U-64"
    local check_name="ftpusers File Configuration"
    local risk_level="MEDIUM"

    local ftpusers_files=("/etc/ftpusers" "/etc/vsftpd/ftpusers" "/etc/vsftpd.ftpusers")
    local file_found=false
    local ftpusers_file=""

    for file in "${ftpusers_files[@]}"; do
        if [ -f "$file" ]; then
            file_found=true
            ftpusers_file="$file"
            break
        fi
    done

    if [ "$file_found" == false ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] ftpusers file does not exist"
        return
    fi

    # root 계정이 포함되어 있는지 확인
    local root_blocked=$(grep "^root$" "$ftpusers_file" 2>/dev/null)

    if [ -n "$root_blocked" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] root account is blocked in ftpusers"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] root account is not blocked in ftpusers"
    fi
}

# U-65: at 파일 소유자 및 권한 설정 (위험도: 중)
check_u65() {
    local check_id="U-65"
    local check_name="at File Owner and Permission"
    local risk_level="MEDIUM"

    local at_files=("/etc/at.allow" "/etc/at.deny")
    local file_checked=false
    local all_pass=true
    local fail_details=""

    for at_file in "${at_files[@]}"; do
        if [ -f "$at_file" ]; then
            file_checked=true
            local owner=$(stat -c %U "$at_file")
            local perm=$(stat -c %a "$at_file")

            # 소유자가 root인지, 권한이 640 이하인지 확인
            if [ "$owner" != "root" ] || [ "$perm" -gt 640 ]; then
                all_pass=false
                fail_details="${fail_details}${at_file}(owner:${owner}, perm:${perm}), "
            fi
        fi
    done

    if [ "$file_checked" == false ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] at.allow/at.deny files do not exist"
    elif [ "$all_pass" == true ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] at files have proper owner and permissions"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_details}"
    fi
}

# U-66: SNMP 서비스 구동 점검 (위험도: 중)
check_u66() {
    local check_id="U-66"
    local check_name="SNMP Service Check"
    local risk_level="MEDIUM"

    local snmp_status=""

    if command -v systemctl &>/dev/null; then
        snmp_status=$(systemctl is-active snmpd 2>/dev/null)
    fi

    if [ "$snmp_status" == "active" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] SNMP service is running (disable if not needed)"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] SNMP service is not active"
    fi
}

# U-67: SNMP 서비스 Community String 복잡성 설정 (위험도: 중)
check_u67() {
    local check_id="U-67"
    local check_name="SNMP Community String Complexity"
    local risk_level="MEDIUM"

    local snmpd_conf="/etc/snmp/snmpd.conf"

    if [ ! -f "$snmpd_conf" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] snmpd.conf file does not exist"
        return
    fi

    # community string 확인
    local community=$(grep -i "^[[:space:]]*community" "$snmpd_conf" | grep -v "^[[:space:]]*#")

    if [ -z "$community" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No community string configured"
        return
    fi

    # 기본 community string (public, private) 사용 여부 확인
    local default_community=$(echo "$community" | grep -iE "public|private")

    if [ -n "$default_community" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Default community string (public/private) is used"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Custom community string is configured"
    fi
}

# U-68: 로그온 시 경고 메시지 제공 (위험도: 하)
check_u68() {
    local check_id="U-68"
    local check_name="Login Warning Message"
    local risk_level="LOW"

    local message_files=("/etc/motd" "/etc/issue" "/etc/issue.net")
    local message_found=false

    for msg_file in "${message_files[@]}"; do
        if [ -f "$msg_file" ]; then
            local content=$(cat "$msg_file" 2>/dev/null | grep -v "^$")
            if [ -n "$content" ]; then
                message_found=true
                break
            fi
        fi
    done

    if [ "$message_found" == true ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Login warning message is configured"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] No login warning message configured"
    fi
}

# U-69: NFS 설정파일 접근권한 (위험도: 중)
check_u69() {
    local check_id="U-69"
    local check_name="NFS Configuration File Permission"
    local risk_level="MEDIUM"

    local exports_file="/etc/exports"

    if [ ! -f "$exports_file" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] /etc/exports file does not exist"
        return
    fi

    local owner=$(stat -c %U "$exports_file")
    local perm=$(stat -c %a "$exports_file")

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

# U-70: expn, vrfy 명령어 제한 (위험도: 중)
check_u70() {
    local check_id="U-70"
    local check_name="EXPN/VRFY Command Restriction"
    local risk_level="MEDIUM"

    local sendmail_cf="/etc/mail/sendmail.cf"

    if [ ! -f "$sendmail_cf" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] sendmail.cf file does not exist"
        return
    fi

    # PrivacyOptions 확인
    local privacy=$(grep -i "PrivacyOptions" "$sendmail_cf" 2>/dev/null)

    if [ -n "$privacy" ]; then
        # noexpn, novrfy 옵션 확인
        local noexpn=$(echo "$privacy" | grep -i "noexpn")
        local novrfy=$(echo "$privacy" | grep -i "novrfy")

        if [ -n "$noexpn" ] && [ -n "$novrfy" ]; then
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] EXPN and VRFY commands are disabled"
        else
            log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] EXPN or VRFY commands are not fully disabled"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] PrivacyOptions not configured"
    fi
}

# U-71: Apache 웹서비스 정보 숨김 (위험도: 중)
check_u71() {
    local check_id="U-71"
    local check_name="Apache Web Service Information Hiding"
    local risk_level="MEDIUM"

    local apache_configs=("/etc/httpd/conf/httpd.conf" "/etc/apache2/apache2.conf")
    local config_found=false
    local servertokens_ok=false
    local serversignature_ok=false

    for config in "${apache_configs[@]}"; do
        if [ -f "$config" ]; then
            config_found=true

            # ServerTokens 확인
            local servertokens=$(grep -i "^[[:space:]]*ServerTokens" "$config" | grep -v "^[[:space:]]*#" | tail -1 | awk '{print tolower($2)}')
            if [[ "$servertokens" == "prod" || "$servertokens" == "productonly" ]]; then
                servertokens_ok=true
            fi

            # ServerSignature 확인
            local serversignature=$(grep -i "^[[:space:]]*ServerSignature" "$config" | grep -v "^[[:space:]]*#" | tail -1 | awk '{print tolower($2)}')
            if [ "$serversignature" == "off" ]; then
                serversignature_ok=true
            fi
        fi
    done

    if [ "$config_found" == false ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Apache configuration not found"
    elif [ "$servertokens_ok" == true ] && [ "$serversignature_ok" == true ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] ServerTokens and ServerSignature are properly configured"
    else
        local fail_msg=""
        if [ "$servertokens_ok" == false ]; then
            fail_msg="${fail_msg}ServerTokens not set to Prod, "
        fi
        if [ "$serversignature_ok" == false ]; then
            fail_msg="${fail_msg}ServerSignature not set to Off"
        fi
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_msg}"
    fi
}

# U-72: 로그 설정 및 관리 (위험도: 하)
check_u72() {
    local check_id="U-72"
    local check_name="System Logging Configuration"
    local risk_level="LOW"

    local rsyslog_conf="/etc/rsyslog.conf"
    local syslog_conf="/etc/syslog.conf"

    local config_found=false
    local logging_rules=0

    if [ -f "$rsyslog_conf" ]; then
        config_found=true
        logging_rules=$(grep -v "^#" "$rsyslog_conf" | grep -v "^$" | grep -E "\*\.\*|auth|authpriv|daemon|kern|mail" | wc -l)
    elif [ -f "$syslog_conf" ]; then
        config_found=true
        logging_rules=$(grep -v "^#" "$syslog_conf" | grep -v "^$" | grep -E "\*\.\*|auth|authpriv|daemon|kern|mail" | wc -l)
    fi

    # rsyslog 서비스 확인
    local rsyslog_active=false
    if systemctl is-active rsyslog &>/dev/null; then
        rsyslog_active=true
    fi

    if [ "$config_found" == true ] && [ "$logging_rules" -gt 0 ] && [ "$rsyslog_active" == true ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] System logging is properly configured (${logging_rules} rules)"
    else
        local fail_msg=""
        if [ "$config_found" == false ]; then
            fail_msg="rsyslog.conf not found, "
        fi
        if [ "$logging_rules" -eq 0 ]; then
            fail_msg="${fail_msg}no logging rules configured, "
        fi
        if [ "$rsyslog_active" == false ]; then
            fail_msg="${fail_msg}rsyslog service not active"
        fi
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${fail_msg}"
    fi
}

# U-73: OpenSSL CVE-2025-11187 Vulnerability Check
check_u73() {
    local check_id="U-73"
    local check_name="OpenSSL CVE-2025-11187 Security Patch"
    local risk_level="HIGH"

    # openssl 패키지 설치 확인
    if ! rpm -q openssl &>/dev/null; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] OpenSSL package is not installed"
        return
    fi

    # 현재 설치된 openssl 버전
    local openssl_version=$(rpm -q openssl)

    # Rocky Linux는 백포트를 사용하므로 RPM changelog에서 CVE 패치 여부 확인
    local cve_patched=false
    if rpm -q --changelog openssl 2>/dev/null | grep -qi "CVE-2025-11187"; then
        cve_patched=true
    fi

    # yum/dnf를 통한 보안 업데이트 확인
    local security_updates=$(yum check-update --security openssl 2>/dev/null | grep -c "openssl" || echo "0")

    if [ "$cve_patched" == true ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] CVE-2025-11187 patch is applied ($openssl_version)"
    elif [ "$security_updates" -gt 0 ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Security updates available for OpenSSL. Manual update required ($openssl_version)"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Cannot verify CVE-2025-11187 patch status. Manual verification required ($openssl_version)"
    fi
}

# U-74: OpenSSL CVE-2025-15467 Vulnerability Check
check_u74() {
    local check_id="U-74"
    local check_name="OpenSSL CVE-2025-15467 Security Patch"
    local risk_level="HIGH"

    # openssl 패키지 설치 확인
    if ! rpm -q openssl &>/dev/null; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] OpenSSL package is not installed"
        return
    fi

    # 현재 설치된 openssl 버전
    local openssl_version=$(rpm -q openssl)

    # Rocky Linux는 백포트를 사용하므로 RPM changelog에서 CVE 패치 여부 확인
    local cve_patched=false
    if rpm -q --changelog openssl 2>/dev/null | grep -qi "CVE-2025-15467"; then
        cve_patched=true
    fi

    # yum/dnf를 통한 보안 업데이트 확인
    local security_updates=$(yum check-update --security openssl 2>/dev/null | grep -c "openssl" || echo "0")

    if [ "$cve_patched" == true ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] CVE-2025-15467 patch is applied ($openssl_version)"
    elif [ "$security_updates" -gt 0 ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Security updates available for OpenSSL. Manual update required ($openssl_version)"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Cannot verify CVE-2025-15467 patch status. Manual verification required ($openssl_version)"
    fi
}

#===============================================================================
# Latest 2026 KISA UNIX/Linux mapping layer (U-01 ~ U-67)
#===============================================================================

latest_run_legacy_check() {
    local new_id="$1"
    local new_name="$2"
    local legacy_func="$3"
    local tmp_file
    tmp_file=$(mktemp)

    ( RESULT_FILE="$tmp_file"; "$legacy_func" ) >/dev/null 2>&1

    local status detail
    status=$(grep -m1 '^Status:' "$tmp_file" | sed 's/^Status: //')
    detail=$(grep -m1 '^Detail:' "$tmp_file" | sed 's/^Detail: //')
    rm -f "$tmp_file"

    [ -z "$status" ] && status="N/A"
    [ -z "$detail" ] && detail="Legacy check ${legacy_func} produced no parseable result"
    log_result "$new_id" "$new_name" "$status" "$detail"
}

latest_check_u13() {
    local check_id="U-13"
    local check_name="안전한 비밀번호 암호화 알고리즘 사용"
    local risk_level="MEDIUM"
    local method=""

    if [ -f /etc/login.defs ]; then
        method=$(grep -E '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' /etc/login.defs | tail -1 | awk '{print toupper($2)}')
    fi

    if [[ "$method" =~ ^(SHA512|SHA256|YESCRYPT)$ ]]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] ENCRYPT_METHOD is ${method}"
    elif awk -F: '($2 ~ /^\$5\$/ || $2 ~ /^\$6\$/ || $2 ~ /^\$y\$/) {found=1} END {exit found?0:1}' /etc/shadow 2>/dev/null; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Existing password hashes use SHA-256/SHA-512/yescrypt style algorithms"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Safe password hash algorithm not verified (ENCRYPT_METHOD=${method:-not set})"
    fi
}

latest_check_u17() {
    local check_id="U-17"
    local check_name="시스템 시작 스크립트 권한 설정"
    local risk_level="HIGH"
    local dirs=(/etc/rc.d/init.d /etc/init.d)
    local found=false bad=""

    for dir in "${dirs[@]}"; do
        [ -d "$dir" ] || continue
        found=true
        local issues
        issues=$(find "$dir" -xdev \( ! -user root -o -perm /022 \) -print 2>/dev/null | head -20)
        [ -n "$issues" ] && bad="${bad}${issues} "
    done

    if [ "$found" = false ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Legacy init script directories not found"
    elif [ -z "$bad" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Startup script ownership and permissions are acceptable"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Startup scripts with unsafe owner/permissions found: ${bad}"
    fi
}

latest_check_u51() {
    local check_id="U-51"
    local check_name="DNS 서비스의 취약한 동적 업데이트 설정 금지"
    local risk_level="MEDIUM"
    local conf="/etc/named.conf"

    if ! systemctl is-active --quiet named 2>/dev/null && ! pgrep -x named >/dev/null 2>&1; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] DNS service is not running"
        return
    fi
    if [ ! -f "$conf" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] named is running but ${conf} was not found"
        return
    fi
    if grep -Eiq 'allow-update[[:space:]]*\{[[:space:]]*(any|0\.0\.0\.0/0)' "$conf"; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] DNS dynamic update appears broadly allowed"
    elif grep -Eiq 'allow-update[[:space:]]*\{[[:space:]]*none[[:space:]]*;' "$conf" || ! grep -Eiq 'allow-update' "$conf"; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Insecure DNS dynamic update setting not found"
    else
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] allow-update requires manual review"
    fi
}

latest_check_u52() {
    local check_id="U-52"
    local check_name="Telnet 서비스 비활성화"
    local risk_level="MEDIUM"

    if systemctl is-active --quiet telnet.socket 2>/dev/null || systemctl is-active --quiet telnet 2>/dev/null || pgrep -x in.telnetd >/dev/null 2>&1; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Telnet service appears active"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Telnet service is not active"
    fi
}

latest_check_u53() {
    local check_id="U-53"
    local check_name="FTP 서비스 정보 노출 제한"
    local risk_level="LOW"

    if ! systemctl is-active --quiet vsftpd 2>/dev/null && ! systemctl is-active --quiet proftpd 2>/dev/null && ! pgrep -E 'vsftpd|proftpd|pure-ftpd' >/dev/null 2>&1; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] FTP service is not running"
        return
    fi
    if grep -RiqE 'ftpd_banner|ServerIdent[[:space:]]+off|DisplayLogin' /etc/vsftpd* /etc/proftpd* 2>/dev/null; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] FTP banner/information exposure control setting found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] FTP information exposure control setting not verified"
    fi
}

latest_check_u56() {
    local check_id="U-56"
    local check_name="FTP 서비스 접근 제어 설정"
    local risk_level="LOW"

    if ! systemctl is-active --quiet vsftpd 2>/dev/null && ! systemctl is-active --quiet proftpd 2>/dev/null && ! pgrep -E 'vsftpd|proftpd|pure-ftpd' >/dev/null 2>&1; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] FTP service is not running"
        return
    fi
    if grep -RiqE 'tcp_wrappers=YES|userlist_enable=YES|<Limit|Allow(User|Group)|Deny(User|Group)' /etc/vsftpd* /etc/proftpd* 2>/dev/null; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] FTP access-control setting found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] FTP access-control setting not verified"
    fi
}

latest_check_u59() {
    local check_id="U-59"
    local check_name="안전한 SNMP 버전 사용"
    local risk_level="HIGH"
    local conf="/etc/snmp/snmpd.conf"

    if ! systemctl is-active --quiet snmpd 2>/dev/null && ! pgrep -x snmpd >/dev/null 2>&1; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] SNMP service is not running"
        return
    fi
    if [ -f "$conf" ] && grep -Eiq '^[[:space:]]*(rocommunity|rwcommunity)' "$conf"; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] SNMP v1/v2 community configuration found; use SNMPv3"
    elif [ -f "$conf" ] && grep -Eiq '^[[:space:]]*(rouser|rwuser|createUser)' "$conf"; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] SNMPv3 user-based configuration found"
    else
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] SNMP version requires manual verification"
    fi
}

latest_check_u61() {
    local check_id="U-61"
    local check_name="SNMP Access Control 설정"
    local risk_level="HIGH"
    local conf="/etc/snmp/snmpd.conf"

    if ! systemctl is-active --quiet snmpd 2>/dev/null && ! pgrep -x snmpd >/dev/null 2>&1; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] SNMP service is not running"
        return
    fi
    if [ -f "$conf" ] && grep -Eiq '^[[:space:]]*(rouser|rwuser|com2sec|access)' "$conf" && ! grep -Eiq '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+public([[:space:]]|$)' "$conf"; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] SNMP access-control configuration found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] SNMP access-control configuration is weak or not verified"
    fi
}

latest_check_u63() {
    local check_id="U-63"
    local check_name="sudo 명령어 접근 관리"
    local risk_level="MEDIUM"
    local issues=""

    [ -f /etc/sudoers ] || { log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] /etc/sudoers not found"; return; }
    local mode owner
    mode=$(stat -c '%a' /etc/sudoers 2>/dev/null)
    owner=$(stat -c '%U:%G' /etc/sudoers 2>/dev/null)
    [ "$owner" != "root:root" ] && issues="${issues}/etc/sudoers owner=${owner}; "
    [ "$mode" -gt 440 ] 2>/dev/null && issues="${issues}/etc/sudoers mode=${mode}; "
    if grep -Eq '^[[:space:]]*%wheel[[:space:]]+ALL=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
        :
    else
        issues="${issues}wheel sudo policy not found; "
    fi
    if [ -z "$issues" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] sudo access is restricted through protected sudoers policy"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${issues}"
    fi
}

latest_check_u65() {
    local check_id="U-65"
    local check_name="NTP 및 시각 동기화 설정"
    local risk_level="MEDIUM"

    if systemctl is-active --quiet chronyd 2>/dev/null || systemctl is-active --quiet ntpd 2>/dev/null; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Time synchronization service is active"
    elif timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi '^yes$'; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] System reports NTP synchronized"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] NTP/time synchronization is not active or not verified"
    fi
}

latest_check_u67() {
    local check_id="U-67"
    local check_name="로그 디렉터리 소유자 및 권한 설정"
    local risk_level="MEDIUM"
    local dir="/var/log"

    if [ ! -d "$dir" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] ${dir} not found"
        return
    fi
    local owner mode bad
    owner=$(stat -c '%U:%G' "$dir" 2>/dev/null)
    mode=$(stat -c '%a' "$dir" 2>/dev/null)
    bad=$(find "$dir" -maxdepth 1 \( -perm /002 -o ! -user root \) -print 2>/dev/null | head -20)
    if [ "$owner" = "root:root" ] && [ -z "$bad" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] ${dir} owner=${owner}, mode=${mode}, no unsafe top-level log entries found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${dir} owner=${owner}, mode=${mode}, unsafe entries: ${bad:-none}"
    fi
}

latest_check_u01() { latest_run_legacy_check "U-01" "root 계정 원격 접속 제한" check_u01; }
latest_check_u02() { latest_run_legacy_check "U-02" "비밀번호 관리정책 설정" check_u02; }
latest_check_u03() { latest_run_legacy_check "U-03" "계정 잠금 임계값 설정" check_u03; }
latest_check_u04() { latest_run_legacy_check "U-04" "비밀번호 파일 보호" check_u04; }
latest_check_u05() { latest_run_legacy_check "U-05" "root 이외의 UID가 ‘0’ 금지" check_u44; }
latest_check_u06() { latest_run_legacy_check "U-06" "사용자 계정 su 기능 제한" check_u45; }
latest_check_u07() { latest_run_legacy_check "U-07" "불필요한 계정 제거" check_u49; }
latest_check_u08() { latest_run_legacy_check "U-08" "관리자 그룹에 최소한의 계정 포함" check_u50; }
latest_check_u09() { latest_run_legacy_check "U-09" "계정이 존재하지 않는 GID 금지" check_u51; }
latest_check_u10() { latest_run_legacy_check "U-10" "동일한 UID 금지" check_u52; }
latest_check_u11() { latest_run_legacy_check "U-11" "사용자 Shell 점검" check_u53; }
latest_check_u12() { latest_run_legacy_check "U-12" "세션 종료 시간 설정" check_u54; }
latest_check_u14() { latest_run_legacy_check "U-14" "root 홈, 패스 디렉터리 권한 및 패스 설정" check_u05; }
latest_check_u15() { latest_run_legacy_check "U-15" "파일 및 디렉터리 소유자 설정" check_u06; }
latest_check_u16() { latest_run_legacy_check "U-16" "/etc/passwd 파일 소유자 및 권한 설정" check_u07; }
latest_check_u18() { latest_run_legacy_check "U-18" "/etc/shadow 파일 소유자 및 권한 설정" check_u08; }
latest_check_u19() { latest_run_legacy_check "U-19" "/etc/hosts 파일 소유자 및 권한 설정" check_u09; }
latest_check_u20() { latest_run_legacy_check "U-20" "/etc/(x)inetd.conf 파일 소유자 및 권한 설정" check_u10; }
latest_check_u21() { latest_run_legacy_check "U-21" "/etc/(r)syslog.conf 파일 소유자 및 권한 설정" check_u11; }
latest_check_u22() { latest_run_legacy_check "U-22" "/etc/services 파일 소유자 및 권한 설정" check_u12; }
latest_check_u23() { latest_run_legacy_check "U-23" "SUID, SGID, Sticky bit 설정 파일 점검" check_u13; }
latest_check_u24() { latest_run_legacy_check "U-24" "사용자, 시스템 환경변수 파일 소유자 및 권한 설정" check_u14; }
latest_check_u25() { latest_run_legacy_check "U-25" "world writable 파일 점검" check_u15; }
latest_check_u26() { latest_run_legacy_check "U-26" "/dev에 존재하지 않는 device 파일 점검" check_u16; }
latest_check_u27() { latest_run_legacy_check "U-27" "\$HOME/.rhosts, hosts.equiv 사용 금지" check_u17; }
latest_check_u28() { latest_run_legacy_check "U-28" "접속 IP 및 포트 제한" check_u18; }
latest_check_u29() { latest_run_legacy_check "U-29" "hosts.lpd 파일 소유자 및 권한 설정" check_u55; }
latest_check_u30() { latest_run_legacy_check "U-30" "UMASK 설정 관리" check_u56; }
latest_check_u31() { latest_run_legacy_check "U-31" "홈디렉토리 소유자 및 권한 설정" check_u57; }
latest_check_u32() { latest_run_legacy_check "U-32" "홈 디렉토리로 지정한 디렉토리의 존재 관리" check_u58; }
latest_check_u33() { latest_run_legacy_check "U-33" "숨겨진 파일 및 디렉토리 검색 및 제거" check_u59; }
latest_check_u34() { latest_run_legacy_check "U-34" "Finger 서비스 비활성화" check_u19; }
latest_check_u35() { latest_run_legacy_check "U-35" "공유 서비스에 대한 익명 접근 제한 설정" check_u20; }
latest_check_u36() { latest_run_legacy_check "U-36" "r 계열 서비스 비활성화" check_u21; }
latest_check_u37() { latest_run_legacy_check "U-37" "crontab 설정파일 권한 설정 미흡" check_u22; }
latest_check_u38() { latest_run_legacy_check "U-38" "DoS 공격에 취약한 서비스 비활성화" check_u23; }
latest_check_u39() { latest_run_legacy_check "U-39" "불필요한 NFS 서비스 비활성화" check_u24; }
latest_check_u40() { latest_run_legacy_check "U-40" "NFS 접근 통제" check_u25; }
latest_check_u41() { latest_run_legacy_check "U-41" "불필요한 automountd 제거" check_u26; }
latest_check_u42() { latest_run_legacy_check "U-42" "불필요한 RPC 서비스 비활성화" check_u27; }
latest_check_u43() { latest_run_legacy_check "U-43" "NIS, NIS+ 점검" check_u28; }
latest_check_u44() { latest_run_legacy_check "U-44" "tftp, talk 서비스 비활성화" check_u29; }
latest_check_u45() { latest_run_legacy_check "U-45" "메일 서비스 버전 점검" check_u30; }
latest_check_u46() { latest_run_legacy_check "U-46" "일반 사용자의 메일 서비스 실행 방지" check_u32; }
latest_check_u47() { latest_run_legacy_check "U-47" "스팸 메일 릴레이 제한" check_u31; }
latest_check_u48() { latest_run_legacy_check "U-48" "expn, vrfy 명령어 제한" check_u70; }
latest_check_u49() { latest_run_legacy_check "U-49" "DNS 보안 버전 패치" check_u33; }
latest_check_u50() { latest_run_legacy_check "U-50" "DNS Zone Transfer 설정" check_u34; }
latest_check_u54() { latest_run_legacy_check "U-54" "암호화되지 않는 FTP 서비스 비활성화" check_u61; }
latest_check_u55() { latest_run_legacy_check "U-55" "FTP 계정 Shell 제한" check_u62; }
latest_check_u57() { latest_run_legacy_check "U-57" "Ftpusers 파일 설정" check_u64; }
latest_check_u58() { latest_run_legacy_check "U-58" "불필요한 SNMP 서비스 구동 점검" check_u66; }
latest_check_u60() { latest_run_legacy_check "U-60" "SNMP Community String 복잡성 설정" check_u67; }
latest_check_u62() { latest_run_legacy_check "U-62" "로그인 시 경고 메시지 설정" check_u68; }
latest_check_u64() { latest_run_legacy_check "U-64" "주기적 보안 패치 및 벤더 권고사항 적용" check_u42; }
latest_check_u66() { latest_run_legacy_check "U-66" "정책에 따른 시스템 로깅 설정" check_u72; }


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

    # 운영체제 환경 확인
    check_os_environment

    # 결과 파일 초기화
    init_result_file

    echo "Starting security assessment..."
    echo ""

    # 최신 2026 UNIX/Linux 기준 취약점 점검 실행 (U-01 ~ U-67)
    latest_check_u01
    latest_check_u02
    latest_check_u03
    latest_check_u04
    latest_check_u05
    latest_check_u06
    latest_check_u07
    latest_check_u08
    latest_check_u09
    latest_check_u10
    latest_check_u11
    latest_check_u12
    latest_check_u13
    latest_check_u14
    latest_check_u15
    latest_check_u16
    latest_check_u17
    latest_check_u18
    latest_check_u19
    latest_check_u20
    latest_check_u21
    latest_check_u22
    latest_check_u23
    latest_check_u24
    latest_check_u25
    latest_check_u26
    latest_check_u27
    latest_check_u28
    latest_check_u29
    latest_check_u30
    latest_check_u31
    latest_check_u32
    latest_check_u33
    latest_check_u34
    latest_check_u35
    latest_check_u36
    latest_check_u37
    latest_check_u38
    latest_check_u39
    latest_check_u40
    latest_check_u41
    latest_check_u42
    latest_check_u43
    latest_check_u44
    latest_check_u45
    latest_check_u46
    latest_check_u47
    latest_check_u48
    latest_check_u49
    latest_check_u50
    latest_check_u51
    latest_check_u52
    latest_check_u53
    latest_check_u54
    latest_check_u55
    latest_check_u56
    latest_check_u57
    latest_check_u58
    latest_check_u59
    latest_check_u60
    latest_check_u61
    latest_check_u62
    latest_check_u63
    latest_check_u64
    latest_check_u65
    latest_check_u66
    latest_check_u67

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

# 버전 정보 출력
show_version() {
    echo "$SCRIPT_NAME v$VERSION"
    echo "RHEL/Rocky Linux 9 Security Vulnerability Assessment"
    echo ""
    echo "For more information, see CHANGELOG.md"
}

# 명령행 인자 처리 (버전 체크)
if [ "$1" = "--version" ] || [ "$1" = "-v" ]; then
    show_version
    exit 0
fi

# 스크립트 실행
main "$@"
