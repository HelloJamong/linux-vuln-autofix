#!/bin/bash
#===============================================================================
# MySQL/MariaDB 보안 취약점 점검 스크립트
#
# 설명: MySQL/MariaDB의 보안 취약점을 점검하고 결과를 파일로 저장합니다.
# 출력: hostname_YYMMDD_hhmmss_mysql_result.txt 형식의 결과 파일
# 버전: 26.05.01
#===============================================================================

# 버전 정보
VERSION="26.05.01"
SCRIPT_NAME="MySQL/MariaDB Vulnerability Check Script"

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 결과 파일 설정
HOSTNAME=$(hostname)
DATE=$(date +%y%m%d)
TIME=$(date +%H%M%S)
RESULT_FILE="${HOSTNAME}_${DATE}_${TIME}_mysql_result.txt"
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
QUIET=false
NO_COLOR=false

# MySQL 접속 정보 (환경 변수 또는 기본값)
MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
DB_PRODUCT="unknown"
DB_VERSION=""
DB_VERSION_COMMENT=""

# MySQL 명령어 옵션
MYSQL_CMD="mysql"
MYSQL_OPTS=""

# 사용법 출력
usage() {
    local exit_code="${1:-0}"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --host HOST       MySQL host (default: localhost)"
    echo "  -P, --port PORT       MySQL port (default: 3306)"
    echo "  -u, --user USER       MySQL user (default: root)"
    echo "  -p, --password PASS   MySQL password"
    echo "  -o, --output FILE     Write assessment result to FILE"
    echo "  -q, --quiet           Suppress progress output"
    echo "  --no-color            Disable colored terminal output"
    echo "  -v, --version         Show version information"
    echo "  --help                Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD"
    echo ""
    echo "Examples:"
    echo "  $0 -u root -p mypassword"
    echo "  MYSQL_PASSWORD=mypass $0"
    exit "$exit_code"
}

# 버전 정보 출력
show_version() {
    echo "$SCRIPT_NAME v$VERSION"
    echo "MySQL/MariaDB Security Vulnerability Assessment"
    echo ""
    echo "For more information, see CHANGELOG.md"
    exit 0
}

# 명령행 인자 파싱
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--host)
                MYSQL_HOST="$2"
                shift 2
                ;;
            -P|--port)
                MYSQL_PORT="$2"
                shift 2
                ;;
            -u|--user)
                MYSQL_USER="$2"
                shift 2
                ;;
            -p|--password)
                MYSQL_PASSWORD="$2"
                shift 2
                ;;
            -o|--output)
                RESULT_FILE="$2"
                shift 2
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            --no-color)
                NO_COLOR=true
                shift
                ;;
            -v|--version)
                show_version
                ;;
            --help)
                usage 0
                ;;
            *)
                echo "Unknown option: $1"
                usage 1
                ;;
        esac
    done

    # MySQL 명령어 옵션 구성
    MYSQL_OPTS="-h${MYSQL_HOST} -P${MYSQL_PORT} -u${MYSQL_USER}"
    if [ -n "$MYSQL_PASSWORD" ]; then
        MYSQL_OPTS="${MYSQL_OPTS} -p${MYSQL_PASSWORD}"
    fi

    if [ "$NO_COLOR" = true ]; then
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        NC=''
    fi
}

# MySQL/MariaDB 환경 확인
check_mysql_environment() {
    [ "$QUIET" = true ] || echo -e "${BLUE}Checking MySQL/MariaDB environment...${NC}"

    # MySQL/MariaDB 클라이언트 설치 확인
    if ! command -v mysql &> /dev/null; then
        echo -e "${RED}[ERROR] MySQL/MariaDB client is not installed.${NC}"
        echo -e "${RED}[ERROR] This script requires MySQL or MariaDB to be installed.${NC}"
        echo ""
        echo "Please install MySQL or MariaDB:"
        echo "  For RHEL/Rocky Linux:"
        echo "    sudo dnf install mysql"
        echo "    # or"
        echo "    sudo dnf install mariadb"
        echo ""
        exit 1
    fi

    # MySQL/MariaDB 서버 실행 확인 (프로세스 또는 소켓 확인)
    local mysql_running=false

    # mysqld 또는 mariadbd 프로세스 확인
    if pgrep -x mysqld &> /dev/null || pgrep -x mariadbd &> /dev/null; then
        mysql_running=true
    # MySQL/MariaDB 소켓 파일 확인
    elif [ -S /var/lib/mysql/mysql.sock ] || [ -S /var/run/mysqld/mysqld.sock ] || [ -S /tmp/mysql.sock ]; then
        mysql_running=true
    # systemd 서비스 상태 확인
    elif systemctl is-active --quiet mysqld 2>/dev/null || systemctl is-active --quiet mariadb 2>/dev/null; then
        mysql_running=true
    fi

    if [ "$mysql_running" = false ]; then
        echo -e "${RED}[ERROR] MySQL/MariaDB server is not running.${NC}"
        echo -e "${RED}[ERROR] This script requires a running MySQL or MariaDB server.${NC}"
        echo ""
        echo "Please start MySQL or MariaDB service:"
        echo "  sudo systemctl start mysqld"
        echo "  # or"
        echo "  sudo systemctl start mariadb"
        echo ""
        exit 1
    fi

    [ "$QUIET" = true ] || echo -e "${GREEN}MySQL/MariaDB environment check passed.${NC}"
}

# Root 권한 확인
check_root() {
    if [ "$EUID" -ne 0 ]; then
        [ "$QUIET" = true ] || echo -e "${YELLOW}[WARNING] This script is recommended to run as root.${NC}"
    fi
}

# MySQL 연결 확인
check_mysql_connection() {
    [ "$QUIET" = true ] || echo -e "${BLUE}Checking MySQL connection...${NC}"

    if ! command -v mysql &>/dev/null; then
        echo -e "${RED}[ERROR] MySQL client is not installed.${NC}"
        exit 1
    fi

    # 연결 테스트
    if ! $MYSQL_CMD $MYSQL_OPTS -e "SELECT 1" &>/dev/null; then
        echo -e "${RED}[ERROR] Cannot connect to MySQL server.${NC}"
        echo -e "${YELLOW}Please check your connection settings:${NC}"
        echo -e "  Host: ${MYSQL_HOST}"
        echo -e "  Port: ${MYSQL_PORT}"
        echo -e "  User: ${MYSQL_USER}"
        exit 1
    fi

    # MySQL/MariaDB 제품 및 버전 확인
    DB_VERSION=$($MYSQL_CMD $MYSQL_OPTS -e "SELECT VERSION()" -sN 2>/dev/null)
    DB_VERSION_COMMENT=$($MYSQL_CMD $MYSQL_OPTS -e "SELECT @@version_comment" -sN 2>/dev/null)
    if echo "${DB_VERSION} ${DB_VERSION_COMMENT}" | grep -qi 'mariadb'; then
        DB_PRODUCT="mariadb"
    else
        DB_PRODUCT="mysql"
    fi
    [ "$QUIET" = true ] || echo -e "${GREEN}[SUCCESS] Connected to ${DB_PRODUCT}: ${DB_VERSION}${NC}"
}

# 결과 파일 초기화
init_result_file() {
    echo "================================================================================" > "$RESULT_FILE"
    echo "MySQL/MariaDB Security Vulnerability Assessment Report" >> "$RESULT_FILE"
    echo "================================================================================" >> "$RESULT_FILE"
    echo "Assessment Date: $(date '+%Y-%m-%d %H:%M:%S')" >> "$RESULT_FILE"
    echo "Hostname: $HOSTNAME" >> "$RESULT_FILE"
    echo "MySQL Host: $MYSQL_HOST:$MYSQL_PORT" >> "$RESULT_FILE"

    echo "MySQL Version: $DB_VERSION" >> "$RESULT_FILE"
    echo "DB Product: $DB_PRODUCT" >> "$RESULT_FILE"
    echo "DB Version: $DB_VERSION" >> "$RESULT_FILE"
    echo "DB Version Comment: $DB_VERSION_COMMENT" >> "$RESULT_FILE"
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
    if [[ "$detail" =~ \[Risk:\ ([^]]+)\] ]]; then
        echo "Risk: ${BASH_REMATCH[1]}" >> "$RESULT_FILE"
    fi
    echo "--------------------------------------------------------------------------------" >> "$RESULT_FILE"

    # 화면 출력
    [ "$QUIET" = true ] && return
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

# MySQL 쿼리 실행 함수
execute_query() {
    local query="$1"
    $MYSQL_CMD $MYSQL_OPTS -e "$query" -sN 2>/dev/null
}

# MySQL 쿼리 실행 (테이블 형식)
execute_query_table() {
    local query="$1"
    $MYSQL_CMD $MYSQL_OPTS -e "$query" 2>/dev/null
}

#===============================================================================
# 취약점 점검 항목들
#===============================================================================

# MX-01: root 원격 접속 제한 (위험도: 상)
check_mx01() {
    local check_id="MX-01"
    local check_name="Root Remote Access Restriction"
    local risk_level="HIGH"

    # root 계정의 호스트 확인
    local root_hosts=$(execute_query "SELECT host FROM mysql.user WHERE user='root'")

    if [ -z "$root_hosts" ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] No root accounts found"
        return
    fi

    # localhost 또는 127.0.0.1만 허용하는지 확인
    local remote_access=$(echo "$root_hosts" | grep -vE "^localhost$|^127\.0\.0\.1$|^::1$")

    if [ -z "$remote_access" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Root access is restricted to localhost"
    else
        local hosts_list=$(echo "$root_hosts" | tr '\n' ', ' | sed 's/,$//')
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Root can access from: ${hosts_list}"
    fi
}

# MX-02: 불필요 계정 제거 (위험도: 상)
check_mx02() {
    local check_id="MX-02"
    local check_name="Unnecessary Accounts Removal"
    local risk_level="HIGH"

    # 모든 사용자 계정 조회
    local all_users=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user")
    local user_count=$(echo "$all_users" | wc -l)

    # 일반적으로 불필요한 계정들
    local unnecessary_accounts=""

    # mysql.session, mysql.sys는 MySQL 8.0+ 시스템 계정이므로 제외
    while IFS= read -r user; do
        if [[ "$user" != "root@"* && "$user" != "mysql.session@"* && "$user" != "mysql.sys@"* && "$user" != "mysql.infoschema@"* ]]; then
            unnecessary_accounts="${unnecessary_accounts}${user}, "
        fi
    done <<< "$all_users"

    if [ -z "$unnecessary_accounts" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Only essential accounts exist"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Total ${user_count} accounts (manual review required): ${unnecessary_accounts}"
    fi
}

# MX-03: 패스워드 설정 여부 (위험도: 상)
check_mx03() {
    local check_id="MX-03"
    local check_name="Password Configuration Check"
    local risk_level="HIGH"

    # 패스워드가 없는 계정 확인
    local no_password=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL")

    if [ -z "$no_password" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] All accounts have passwords"
    else
        local accounts=$(echo "$no_password" | tr '\n' ', ' | sed 's/,$//')
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Accounts without password: ${accounts}"
    fi
}

# MX-04: 패스워드 복잡성 (위험도: 상)
check_mx04() {
    local check_id="MX-04"
    local check_name="Password Complexity Policy"
    local risk_level="HIGH"

    # validate_password 플러그인 확인
    local validate_password=$(execute_query "SHOW VARIABLES LIKE 'validate_password%'" 2>/dev/null)

    if [ -z "$validate_password" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] validate_password plugin is not enabled"
        return
    fi

    # 주요 설정 확인
    local policy=$(execute_query "SHOW VARIABLES LIKE 'validate_password.policy'" | awk '{print $2}')
    local length=$(execute_query "SHOW VARIABLES LIKE 'validate_password.length'" | awk '{print $2}')

    if [ -n "$policy" ] && [ -n "$length" ] && [ "$length" -ge 8 ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Password policy: ${policy}, minimum length: ${length}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Weak password policy (policy: ${policy}, length: ${length})"
    fi
}

# MX-05: 권한 최소화 (위험도: 상)
check_mx05() {
    local check_id="MX-05"
    local check_name="Privilege Minimization"
    local risk_level="HIGH"

    # 모든 권한을 가진 계정 확인 (root 제외)
    local super_users=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE Super_priv='Y' AND user!='root'")

    if [ -z "$super_users" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No non-root users with SUPER privilege"
    else
        local users=$(echo "$super_users" | tr '\n' ', ' | sed 's/,$//')
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Users with SUPER privilege: ${users}"
    fi
}

# MX-06: DB 접근 제한 (위험도: 상)
check_mx06() {
    local check_id="MX-06"
    local check_name="Database Access Restriction"
    local risk_level="HIGH"

    # 와일드카드(%) 호스트를 가진 계정 확인
    local wildcard_hosts=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host='%'")

    if [ -z "$wildcard_hosts" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No accounts with wildcard host access"
    else
        local accounts=$(echo "$wildcard_hosts" | tr '\n' ', ' | sed 's/,$//')
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Accounts with wildcard (%) host: ${accounts}"
    fi
}

# MX-07: anonymous 계정 제거 (위험도: 상)
check_mx07() {
    local check_id="MX-07"
    local check_name="Anonymous Account Removal"
    local risk_level="HIGH"

    # anonymous 계정 확인
    local anonymous=$(execute_query "SELECT host FROM mysql.user WHERE user=''")

    if [ -z "$anonymous" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No anonymous accounts found"
    else
        local hosts=$(echo "$anonymous" | tr '\n' ', ' | sed 's/,$//')
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Anonymous accounts exist for hosts: ${hosts}"
    fi
}

# MX-08: test DB 제거 (위험도: 중)
check_mx08() {
    local check_id="MX-08"
    local check_name="Test Database Removal"
    local risk_level="MEDIUM"

    # test 데이터베이스 확인
    local test_db=$(execute_query "SHOW DATABASES LIKE 'test'")

    if [ -z "$test_db" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Test database does not exist"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Test database exists"
    fi
}

# MX-09: 파일 접근 제한 (위험도: 상)
check_mx09() {
    local check_id="MX-09"
    local check_name="File Access Restriction"
    local risk_level="HIGH"

    # secure_file_priv 설정 확인
    local secure_file_priv=$(execute_query "SHOW VARIABLES LIKE 'secure_file_priv'" | awk '{print $2}')

    if [ -z "$secure_file_priv" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] secure_file_priv is not set (unrestricted file access)"
    elif [ "$secure_file_priv" == "NULL" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] File operations are disabled (secure_file_priv=NULL)"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] secure_file_priv is set to: ${secure_file_priv}"
    fi
}

# MX-10: local infile 제한 (위험도: 상)
check_mx10() {
    local check_id="MX-10"
    local check_name="Local Infile Restriction"
    local risk_level="HIGH"

    # local_infile 설정 확인
    local local_infile=$(execute_query "SHOW VARIABLES LIKE 'local_infile'" | awk '{print $2}')

    if [ "$local_infile" == "OFF" ] || [ "$local_infile" == "0" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] local_infile is disabled"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] local_infile is enabled (current: ${local_infile})"
    fi
}

# MX-11: 로그 설정 (위험도: 중)
check_mx11() {
    local check_id="MX-11"
    local check_name="Error Log Configuration"
    local risk_level="MEDIUM"

    # log_error 설정 확인
    local log_error=$(execute_query "SHOW VARIABLES LIKE 'log_error'" | awk '{print $2}')

    if [ -n "$log_error" ] && [ "$log_error" != "stderr" ]; then
        # 로그 파일이 존재하는지 확인
        if [ -f "$log_error" ]; then
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Error log is configured: ${log_error}"
        else
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Error log path: ${log_error} (verify file exists)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Error log is not properly configured (current: ${log_error})"
    fi
}

# MX-12: general log (위험도: 하)
check_mx12() {
    local check_id="MX-12"
    local check_name="General Log Configuration"
    local risk_level="LOW"

    # general_log 설정 확인
    local general_log=$(execute_query "SHOW VARIABLES LIKE 'general_log'" | awk '{print $2}')
    local general_log_file=$(execute_query "SHOW VARIABLES LIKE 'general_log_file'" | awk '{print $2}')

    if [ "$general_log" == "ON" ] || [ "$general_log" == "1" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] General log is enabled: ${general_log_file}"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] General log is disabled (enable if needed for auditing)"
    fi
}

# MX-13: slow query log (위험도: 하)
check_mx13() {
    local check_id="MX-13"
    local check_name="Slow Query Log Configuration"
    local risk_level="LOW"

    # slow_query_log 설정 확인
    local slow_query_log=$(execute_query "SHOW VARIABLES LIKE 'slow_query_log'" | awk '{print $2}')
    local slow_query_log_file=$(execute_query "SHOW VARIABLES LIKE 'slow_query_log_file'" | awk '{print $2}')
    local long_query_time=$(execute_query "SHOW VARIABLES LIKE 'long_query_time'" | awk '{print $2}')

    if [ "$slow_query_log" == "ON" ] || [ "$slow_query_log" == "1" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Slow query log is enabled (file: ${slow_query_log_file}, threshold: ${long_query_time}s)"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Slow query log is disabled (recommended to enable for performance monitoring)"
    fi
}

# MX-14: 패치 버전 (위험도: 상)
check_mx14() {
    local check_id="MX-14"
    local check_name="MySQL Version and Patch Level"
    local risk_level="HIGH"

    # MySQL 버전 확인
    local version=$(execute_query "SELECT VERSION()")

    if [ -n "$version" ]; then
        # MariaDB인지 MySQL인지 확인
        if [[ "$version" =~ "MariaDB" ]]; then
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] MariaDB version: ${version} (verify if latest)"
        else
            log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] MySQL version: ${version} (verify if latest)"
        fi
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Cannot determine MySQL version"
    fi
}

# MX-15: skip networking (위험도: 중)
check_mx15() {
    local check_id="MX-15"
    local check_name="Skip Networking Configuration"
    local risk_level="MEDIUM"

    # skip_networking 설정 확인
    local skip_networking=$(execute_query "SHOW VARIABLES LIKE 'skip_networking'" | awk '{print $2}')

    if [ "$skip_networking" == "ON" ] || [ "$skip_networking" == "1" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] skip_networking is enabled (only local connections allowed)"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] skip_networking is disabled (network connections allowed - verify if needed)"
    fi
}

# MX-16: bind address (위험도: 중)
check_mx16() {
    local check_id="MX-16"
    local check_name="Bind Address Configuration"
    local risk_level="MEDIUM"

    # bind_address 설정 확인
    local bind_address=$(execute_query "SHOW VARIABLES LIKE 'bind_address'" | awk '{print $2}')

    if [ -z "$bind_address" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] bind_address is not set"
        return
    fi

    # 0.0.0.0 또는 ::는 모든 인터페이스에 바인딩
    if [ "$bind_address" == "0.0.0.0" ] || [ "$bind_address" == "*" ] || [ "$bind_address" == "::" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] bind_address is set to all interfaces (${bind_address}) - restrict to specific IP"
    elif [ "$bind_address" == "127.0.0.1" ] || [ "$bind_address" == "localhost" ] || [ "$bind_address" == "::1" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] bind_address is restricted to localhost (${bind_address})"
    else
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] bind_address is set to specific IP: ${bind_address}"
    fi
}

#===============================================================================
# Latest 2026 KISA DBMS mapping layer for MySQL/MariaDB (D-* codes)
#===============================================================================

check_d01() {
    local check_id="D-01"
    local check_name="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
    local risk_level="HIGH"
    local empty_root
    empty_root=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='root' AND (authentication_string='' OR authentication_string IS NULL)" 2>/dev/null)
    if [ -z "$empty_root" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Root/default account password is not empty"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Root/default accounts without password: $(echo "$empty_root" | tr '\n' ', ')"
    fi
}

check_d02() {
    local check_id="D-02"
    local check_name="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
    local risk_level="HIGH"
    local anonymous test_db
    anonymous=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user=''" 2>/dev/null)
    test_db=$(execute_query "SHOW DATABASES LIKE 'test'" 2>/dev/null)
    if [ -z "$anonymous" ] && [ -z "$test_db" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No anonymous account or test database found; review business accounts manually"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Unnecessary default objects found: anonymous=${anonymous:-none}, test_db=${test_db:-none}"
    fi
}

check_d03() {
    local check_id="D-03"
    local check_name="비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"
    local risk_level="HIGH"
    local validate length lifetime simple
    validate=$(execute_query "SHOW VARIABLES LIKE 'validate_password%'" 2>/dev/null)
    length=$(execute_query "SHOW VARIABLES LIKE 'validate_password.length'" 2>/dev/null | awk '{print $2}')
    lifetime=$(execute_query "SHOW VARIABLES LIKE 'default_password_lifetime'" 2>/dev/null | awk '{print $2}')
    simple=$(execute_query "SHOW VARIABLES LIKE 'simple_password_check%'" 2>/dev/null)
    if { [ -n "$validate" ] && [ "${length:-0}" -ge 8 ] 2>/dev/null; } || [ -n "$simple" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Password complexity policy found; default_password_lifetime=${lifetime:-not verified}"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Password complexity policy not verified"
    fi
}

check_d04() {
    local check_id="D-04"
    local check_name="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
    local risk_level="HIGH"
    local admins
    admins=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema') AND (Super_priv='Y' OR Grant_priv='Y')" 2>/dev/null)
    if [ -z "$admins" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No non-default accounts with SUPER/GRANT global admin privileges found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Accounts requiring admin privilege review: $(echo "$admins" | tr '\n' ', ')"
    fi
}

check_d06() {
    local check_id="D-06"
    local check_name="DB 사용자 계정을 개별적으로 부여하여 사용"
    local risk_level="MEDIUM"
    log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Shared-account usage cannot be proven from DB metadata alone; review account ownership and application mappings"
}

check_d07() {
    local check_id="D-07"
    local check_name="root 권한으로 서비스 구동 제한"
    local risk_level="MEDIUM"
    local root_proc
    root_proc=$(ps -eo user=,comm= 2>/dev/null | awk '$1=="root" && ($2=="mysqld" || $2=="mariadbd") {print $0}')
    if [ -z "$root_proc" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] mysqld/mariadbd is not running as OS root"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] DB process is running as root: ${root_proc}"
    fi
}

check_d08() {
    local check_id="D-08"
    local check_name="안전한 암호화 알고리즘 사용"
    local risk_level="HIGH"
    local weak_plugins plugins=""

    # MariaDB 10.4+: 인증 정보가 mysql.global_priv(JSON)에 저장됨
    local version_str
    version_str=$(execute_query "SELECT VERSION()" 2>/dev/null)
    if echo "$version_str" | grep -qi 'mariadb'; then
        plugins=$(execute_query \
            "SELECT DISTINCT JSON_UNQUOTE(JSON_EXTRACT(Priv, '$.plugin')) \
             FROM mysql.global_priv \
             WHERE JSON_EXTRACT(Priv, '$.plugin') IS NOT NULL" 2>/dev/null)
    fi
    # MySQL 또는 MariaDB 10.3- fallback
    [ -z "$plugins" ] && plugins=$(execute_query "SELECT DISTINCT plugin FROM mysql.user" 2>/dev/null)

    weak_plugins=$(echo "$plugins" | grep -Ei 'mysql_old_password|old_password' || true)
    if [ -n "$weak_plugins" ]; then
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Weak authentication plugin found: ${weak_plugins}"
    elif [ -n "$plugins" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No known weak authentication plugin found: $(echo "$plugins" | tr '\n' ', ')"
    else
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Authentication plugin information could not be verified"
    fi
}

check_d10() {
    local check_id="D-10"
    local check_name="원격에서 DB 서버로의 접속 제한"
    local risk_level="HIGH"
    local wildcard bind_address root_remote issues=""
    wildcard=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host='%'" 2>/dev/null)
    root_remote=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')" 2>/dev/null)
    bind_address=$(execute_query "SHOW VARIABLES LIKE 'bind_address'" 2>/dev/null | awk '{print $2}')
    [ -n "$wildcard" ] && issues="${issues}wildcard hosts: $(echo "$wildcard" | tr '\n' ', '); "
    [ -n "$root_remote" ] && issues="${issues}remote root: $(echo "$root_remote" | tr '\n' ', '); "
    [[ "$bind_address" == "0.0.0.0" || "$bind_address" == "*" || "$bind_address" == "::" ]] && issues="${issues}bind_address=${bind_address}; "
    if [ -z "$issues" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] DB remote access appears restricted (bind_address=${bind_address:-not set})"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] ${issues}"
    fi
}

check_d11() {
    local check_id="D-11"
    local check_name="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
    local risk_level="HIGH"
    local users
    users=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema') AND Select_priv='Y'" 2>/dev/null)
    if [ -z "$users" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No non-default accounts with global SELECT privilege found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Accounts with broad system-table-readable privileges require review: $(echo "$users" | tr '\n' ', ')"
    fi
}

check_d14() {
    local check_id="D-14"
    local check_name="데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"
    local risk_level="MEDIUM"
    local files=(/etc/my.cnf /etc/mysql/my.cnf /etc/my.cnf.d/mysql-server.cnf /etc/my.cnf.d/mariadb-server.cnf)
    local found=false issues=""
    for file in "${files[@]}"; do
        [ -f "$file" ] || continue
        found=true
        local mode owner
        mode=$(stat -c '%a' "$file" 2>/dev/null)
        owner=$(stat -c '%U:%G' "$file" 2>/dev/null)
        if [ "${mode: -1}" -gt 0 ] 2>/dev/null || [ "${mode: -2:1}" -gt 4 ] 2>/dev/null; then
            issues="${issues}${file}(owner=${owner},mode=${mode}); "
        fi
    done
    if [ "$found" = false ]; then
        log_result "$check_id" "$check_name" "N/A" "[Risk: ${risk_level}] Known MySQL/MariaDB configuration files were not found"
    elif [ -z "$issues" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] MySQL/MariaDB configuration file permissions are acceptable"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Unsafe configuration file permissions: ${issues}"
    fi
}

check_d21() {
    local check_id="D-21"
    local check_name="인가되지 않은 GRANT OPTION 사용 제한"
    local risk_level="MEDIUM"
    local grant_users
    grant_users=$(execute_query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema') AND Grant_priv='Y'" 2>/dev/null)
    if [ -z "$grant_users" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] No non-default accounts with global GRANT OPTION found"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Accounts with GRANT OPTION require authorization review: $(echo "$grant_users" | tr '\n' ', ')"
    fi
}

check_d25() {
    local check_id="D-25"
    local check_name="주기적 보안 패치 및 벤더 권고 사항 적용"
    local risk_level="HIGH"
    local version
    version=$(execute_query "SELECT VERSION()" 2>/dev/null)
    if [ -n "$version" ]; then
        log_result "$check_id" "$check_name" "PASS" "[Risk: ${risk_level}] Current version: ${version}; verify against current vendor security advisories"
    else
        log_result "$check_id" "$check_name" "FAIL" "[Risk: ${risk_level}] Cannot determine MySQL/MariaDB version"
    fi
}


#===============================================================================
# 메인 실행
#===============================================================================

main() {
    # 명령행 인자 파싱 (--version, --help는 여기서 처리)
    parse_args "$@"

    if [ "$QUIET" != true ]; then
        echo "================================================================================"
        echo "MySQL/MariaDB Security Vulnerability Assessment Script"
        echo "================================================================================"
        echo ""
    fi

    # Root 권한 확인 (경고만)
    check_root

    # MySQL/MariaDB 환경 확인
    check_mysql_environment

    # MySQL 연결 확인
    check_mysql_connection

    # 결과 파일 초기화
    init_result_file

    if [ "$QUIET" != true ]; then
        echo ""
        echo "Starting security assessment..."
        echo ""
    fi

    # 최신 2026 DBMS 기준 MySQL/MariaDB 취약점 점검 실행 (D-* codes)
    check_d01
    check_d02
    check_d03
    check_d04
    check_d06
    check_d07
    check_d08
    check_d10
    check_d11
    check_d14
    check_d21
    check_d25

    # 결과 요약
    echo "" >> "$RESULT_FILE"
    echo "================================================================================" >> "$RESULT_FILE"
    echo "Assessment Completed: $(date '+%Y-%m-%d %H:%M:%S')" >> "$RESULT_FILE"
    echo "================================================================================" >> "$RESULT_FILE"

    if [ "$QUIET" != true ]; then
        echo ""
        echo "================================================================================"
        echo -e "${GREEN}Assessment completed.${NC}"
        echo "Result file: ${SCRIPT_DIR}/${RESULT_FILE}"
        echo "================================================================================"
    fi
}

# 스크립트 실행
main "$@"
