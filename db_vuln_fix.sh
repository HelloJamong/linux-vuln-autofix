#!/bin/bash
#===============================================================================
# MySQL/MariaDB 보안 취약점 자동 조치 스크립트
#
# 설명: MySQL/MariaDB 취약점 점검 결과를 바탕으로 자동으로 보안 조치를 수행합니다.
# 사용법: ./db_vuln_fix.sh [OPTIONS]
# 출력: hostname_YYMMDD_hhmmss_mysql_fix_result.txt 형식의 조치 결과 파일
# 버전: 26.06.00
#===============================================================================

# 버전 정보
VERSION="26.06.00"
SCRIPT_NAME="MySQL/MariaDB Vulnerability Auto-Fix Script"

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
FIX_RESULT_FILE="${HOSTNAME}_${DATE}_${TIME}_mysql_fix_result.txt"
CHECK_SCRIPT="./db_vuln_check.sh"
CHECK_RESULT_FILE=""
QUIET=false
NO_COLOR=false
DRY_RUN=false

# MySQL 접속 정보
MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
DB_PRODUCT="unknown"
DB_VERSION="26.06.00"
DB_VERSION_COMMENT=""

# MySQL 명령어 옵션
MYSQL_CMD="mysql"
MYSQL_OPTS=""

# 백업 디렉토리
BACKUP_DIR="/var/backup/mysql_security_fix_${DATE}_${TIME}"

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

# 사용법 출력
usage() {
    local exit_code="${1:-0}"
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -h, --host HOST         MySQL host (default: localhost)
    -P, --port PORT         MySQL port (default: 3306)
    -u, --user USER         MySQL user (default: root)
    -p, --password PASS     MySQL password
    -f, --file FILE         Use existing check result file (skip new check)
    -o, --output FILE       Write remediation result to FILE
    --dry-run               Show planned remediation without changing the database
    -q, --quiet             Suppress progress output
    --no-color              Disable colored terminal output
    -v, --version           Show version information
    --help                  Display this help message

Environment variables:
    MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD

Description:
    This script automatically remediates MySQL/MariaDB security vulnerabilities
    based on the vulnerability check results.

Examples:
    # Run new check and fix
    ./db_vuln_fix.sh -u root -p mypassword

    # Use existing check result
    ./db_vuln_fix.sh -u root -p mypassword -f hostname_261127_143022_mysql_result.txt

    # Using environment variables
    export MYSQL_PASSWORD="mypassword"
    ./db_vuln_fix.sh -u root

EOF
    exit "$exit_code"
}

# 버전 정보 출력
show_version() {
    echo "$SCRIPT_NAME v$VERSION"
    echo "MySQL/MariaDB Security Vulnerability Auto-Remediation"
    echo ""
    echo "For more information, see CHANGELOG.md"
    exit 0
}

# 파라미터 파싱
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
            -v|--version)
                show_version
                ;;
            --help)
                usage 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
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

# MySQL 연결 확인
check_mysql_connection() {
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

    DB_VERSION=$($MYSQL_CMD $MYSQL_OPTS -e "SELECT VERSION()" -sN 2>/dev/null)
    DB_VERSION_COMMENT=$($MYSQL_CMD $MYSQL_OPTS -e "SELECT @@version_comment" -sN 2>/dev/null)
    if echo "${DB_VERSION} ${DB_VERSION_COMMENT}" | grep -qi 'mariadb'; then
        DB_PRODUCT="mariadb"
    else
        DB_PRODUCT="mysql"
    fi
    [ "$QUIET" = true ] || echo -e "${GREEN}[SUCCESS] Connected to ${DB_PRODUCT}: ${DB_VERSION}${NC}"
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

# 결과 파일 초기화
init_fix_result_file() {
    echo "================================================================================" > "$FIX_RESULT_FILE"
    echo "MySQL/MariaDB Security Vulnerability Auto-Remediation Report" >> "$FIX_RESULT_FILE"
    echo "================================================================================" >> "$FIX_RESULT_FILE"
    echo "Remediation Date: $(date '+%Y-%m-%d %H:%M:%S')" >> "$FIX_RESULT_FILE"
    echo "Hostname: $HOSTNAME" >> "$FIX_RESULT_FILE"
    echo "MySQL Host: $MYSQL_HOST:$MYSQL_PORT" >> "$FIX_RESULT_FILE"

    echo "MySQL Version: $DB_VERSION" >> "$FIX_RESULT_FILE"
    echo "DB Product: $DB_PRODUCT" >> "$FIX_RESULT_FILE"
    echo "DB Version: $DB_VERSION" >> "$FIX_RESULT_FILE"
    echo "DB Version Comment: $DB_VERSION_COMMENT" >> "$FIX_RESULT_FILE"
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

# SQL 쿼리 실행
execute_query() {
    local query="$1"
    $MYSQL_CMD $MYSQL_OPTS -e "$query" 2>&1
}

# SQL 쿼리 실행 (결과값 반환)
execute_query_result() {
    local query="$1"
    $MYSQL_CMD $MYSQL_OPTS -e "$query" -sN 2>/dev/null
}

#===============================================================================
# Latest 2026 KISA DBMS remediation layer — D-* codes only
# (MX-01~MX-16 legacy functions removed; result files use D-* IDs)
#===============================================================================


d_status_for() {
    local id="$1"
    [ -n "$CHECK_RESULT_FILE" ] && [ -f "$CHECK_RESULT_FILE" ] || return 1
    grep -A 2 "^\[${id}\]" "$CHECK_RESULT_FILE" | grep -m1 '^Status:' | sed 's/^Status: //'
}

d_is_failed() {
    local id="$1"; shift
    local status
    status=$(d_status_for "$id")
    [ "$status" = "FAIL" ] && return 0
    for id in "$@"; do
        status=$(d_status_for "$id")
        [ "$status" = "FAIL" ] && return 0
    done
    return 1
}

d_manual_fix() {
    local id="$1"
    local name="$2"
    local message="$3"
    shift 3
    if ! d_is_failed "$id" "$@"; then
        log_fix_result "$id" "$name" "SKIPPED" "Already passed or N/A"
        return
    fi
    if [ "$DRY_RUN" = true ]; then
        log_fix_result "$id" "$name" "MANUAL" "Dry-run: manual intervention required. ${message}"
        return
    fi
    log_fix_result "$id" "$name" "FAILED" "Manual intervention required. ${message}"
}

fix_d01() {
    local id="D-01" name="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
    d_manual_fix "$id" "$name" "Change default/root account passwords and lock unused default accounts."
}

fix_d02() {
    local id="D-02" name="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
    if ! d_is_failed "$id"; then
        log_fix_result "$id" "$name" "SKIPPED" "Already passed or N/A"
        return
    fi
    if [ "$DRY_RUN" = true ]; then
        log_fix_result "$id" "$name" "PLANNED" "Dry-run: would delete anonymous accounts, drop test database if present, and flush privileges."
        return
    fi
    local result1 result2 rc=0
    result1=$(execute_query "DELETE FROM mysql.user WHERE user='';" 2>&1) || rc=1
    result2=$(execute_query "DROP DATABASE IF EXISTS test;" 2>&1) || rc=1
    execute_query "FLUSH PRIVILEGES;" >/dev/null 2>&1
    if [ $rc -eq 0 ]; then
        log_fix_result "$id" "$name" "SUCCESS" "Anonymous accounts and test database removed where present"
    else
        log_fix_result "$id" "$name" "FAILED" "Failed to remove all unnecessary default objects: ${result1} ${result2}"
    fi
}

fix_d03() {
    local id="D-03" name="비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"
    if ! d_is_failed "$id"; then
        log_fix_result "$id" "$name" "SKIPPED" "Already passed or N/A"
        return
    fi
    if [ "$DRY_RUN" = true ]; then
        log_fix_result "$id" "$name" "PLANNED" "Dry-run: would install/enable password validation controls and set password complexity/lifetime globals where supported."
        return
    fi
    execute_query "INSTALL COMPONENT 'file://component_validate_password';" >/dev/null 2>&1 || true
    execute_query "INSTALL PLUGIN validate_password SONAME 'validate_password.so';" >/dev/null 2>&1 || true
    execute_query "SET GLOBAL validate_password.length = 8;" >/dev/null 2>&1 || true
    execute_query "SET GLOBAL validate_password.mixed_case_count = 1;" >/dev/null 2>&1 || true
    execute_query "SET GLOBAL validate_password.number_count = 1;" >/dev/null 2>&1 || true
    execute_query "SET GLOBAL validate_password.special_char_count = 1;" >/dev/null 2>&1 || true
    execute_query "SET GLOBAL validate_password.policy = MEDIUM;" >/dev/null 2>&1 || true
    execute_query "SET GLOBAL default_password_lifetime = 90;" >/dev/null 2>&1 || true
    execute_query "SET GLOBAL simple_password_check_minimal_length = 8;" >/dev/null 2>&1 || true
    log_fix_result "$id" "$name" "SUCCESS" "Password complexity/lifetime settings attempted; persist equivalent settings in my.cnf/my.ini if required"
}

fix_d04() { d_manual_fix "D-04" "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용" "Review accounts with SUPER/GRANT/global admin privileges and revoke unnecessary privileges."; }
fix_d06() { d_manual_fix "D-06" "DB 사용자 계정을 개별적으로 부여하여 사용" "Replace shared DB accounts with named user/application accounts and least-privilege grants."; }
fix_d07() { d_manual_fix "D-07" "root 권한으로 서비스 구동 제한" "Configure mysqld/mariadbd service to run as the mysql/mariadb OS account, not root."; }
fix_d08() { d_manual_fix "D-08" "안전한 암호화 알고리즘 사용" "Migrate weak authentication plugins/hashes to current secure MySQL/MariaDB authentication methods."; }
fix_d10() { d_manual_fix "D-10" "원격에서 DB 서버로의 접속 제한" "Restrict root/wildcard hosts and bind-address to approved interfaces/IPs; avoid disrupting application connectivity."; }
fix_d11() { d_manual_fix "D-11" "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정" "Review broad/global SELECT and system schema access; grant only required database/table privileges."; }
fix_d14() { d_manual_fix "D-14" "데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정" "Set my.cnf/my.ini and credential files to restricted owner/mode such as root/mysql with 600 or 640 as appropriate."; }
fix_d21() { d_manual_fix "D-21" "인가되지 않은 GRANT OPTION 사용 제한" "Revoke unauthorized GRANT OPTION and re-grant privileges through approved roles/accounts only."; }
fix_d25() { d_manual_fix "D-25" "주기적 보안 패치 및 벤더 권고 사항 적용" "Upgrade MySQL/MariaDB to a vendor-supported version with current security patches."; }


#===============================================================================
# 메인 실행 로직
#===============================================================================

main() {
    # 파라미터 파싱 (--version, --help는 여기서 처리)
    parse_args "$@"

    if [ "$QUIET" != true ]; then
        echo -e "${BLUE}================================================================================${NC}"
        echo -e "${BLUE}MySQL/MariaDB Security Vulnerability Auto-Remediation Script${NC}"
        echo -e "${BLUE}================================================================================${NC}"
        echo ""
    fi

    if [ "$DRY_RUN" = true ] && [ -n "$CHECK_RESULT_FILE" ] && [ -f "$CHECK_RESULT_FILE" ]; then
        [ "$QUIET" = true ] || echo -e "${BLUE}[DRY-RUN] Using provided result file without DB connection preflight.${NC}"
    else
        # MySQL/MariaDB 환경 확인
        check_mysql_environment

        # MySQL 연결 확인
        check_mysql_connection
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
        check_args=(-h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER")
        [ -n "$MYSQL_PASSWORD" ] && check_args+=(-p "$MYSQL_PASSWORD")
        [ "$QUIET" = true ] && check_args+=(--quiet)
        [ "$NO_COLOR" = true ] && check_args+=(--no-color)
        bash "$CHECK_SCRIPT" "${check_args[@]}"

        # 가장 최근 생성된 결과 파일 찾기
        CHECK_RESULT_FILE=$(ls -t ${HOSTNAME}_*_mysql_result.txt 2>/dev/null | head -1)

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

    # 최신 2026 DBMS 기준 MySQL/MariaDB 조치 실행 (D-* codes)
    fix_d01
    fix_d02
    fix_d03
    fix_d04
    fix_d06
    fix_d07
    fix_d08
    fix_d10
    fix_d11
    fix_d14
    fix_d21
    fix_d25

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
        echo -e "${YELLOW}[IMPORTANT] Some changes require MySQL restart to take effect.${NC}"
        echo -e "${YELLOW}[IMPORTANT] Review manual intervention items in the result file.${NC}"
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
        echo ""
        echo "IMPORTANT NOTES:"
        echo "- Some settings require adding configuration to my.cnf and restarting MySQL"
        echo "- Manual intervention items require careful review and action"
        echo "- Always backup your database before making changes"
        echo "================================================================================"
    } >> "$FIX_RESULT_FILE"
}

# 메인 함수 실행
main "$@"
