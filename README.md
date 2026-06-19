# 보안 취약점 점검 스크립트

Rocky Linux 8.10/9.x 및 MySQL/MariaDB 보안 취약점을 점검하고, 점검 결과를 바탕으로 조치 계획 또는 자동 조치를 수행하는 단일 스크립트 모음입니다.

**현재 버전: 26.05.01**

## 제공 스크립트

| 구분 | 파일 | 설명 |
|---|---|---|
| OS 점검 | `linux_vuln_check.sh` | Rocky Linux 8.10/9.x 보안 취약점 `U-01 ~ U-67` 점검 |
| OS 조치 | `linux_vuln_fix.sh` | OS 점검 결과 기반 조치 또는 dry-run 계획 생성 |
| DB 점검 | `db_vuln_check.sh` | MySQL/MariaDB 보안 취약점 `D-*` 12개 항목 점검 |
| DB 조치 | `db_vuln_fix.sh` | DB 점검 결과 기반 조치 또는 dry-run 계획 생성 |

## 요구사항

### OS 스크립트
- Rocky Linux 8.10 또는 Rocky Linux 9.x
- root 권한
- 기본 명령어: `bash`, `grep`, `awk`, `find`, `stat`, `systemctl` 등

### DB 스크립트
- MySQL 또는 MariaDB
- `mysql` 클라이언트
- 점검에 필요한 DB 접속 권한

## OS 취약점 점검

```bash
sudo ./linux_vuln_check.sh
```

주요 옵션:

```bash
sudo ./linux_vuln_check.sh --output result.txt
sudo ./linux_vuln_check.sh --quiet --no-color
./linux_vuln_check.sh --help
./linux_vuln_check.sh --version
```

출력 파일:

```text
hostname_YYMMDD_hhmmss_result.txt
```

## OS 취약점 조치

운영 환경에서는 먼저 dry-run으로 조치 계획을 확인하세요.

```bash
# 점검 후 조치 계획만 생성
sudo ./linux_vuln_fix.sh --dry-run

# 기존 점검 결과 파일로 조치 계획 생성
sudo ./linux_vuln_fix.sh --dry-run -f hostname_YYMMDD_hhmmss_result.txt

# 실제 조치 실행
sudo ./linux_vuln_fix.sh
```

주요 옵션:

```bash
sudo ./linux_vuln_fix.sh -f hostname_YYMMDD_hhmmss_result.txt
sudo ./linux_vuln_fix.sh --output fix_result.txt
sudo ./linux_vuln_fix.sh --dry-run --quiet --no-color
./linux_vuln_fix.sh --help
./linux_vuln_fix.sh --version
```

출력 파일:

```text
hostname_YYMMDD_hhmmss_fix_result.txt
```

백업 디렉터리:

```text
/var/backup/security_fix_YYMMDD_hhmmss/
```

## MySQL/MariaDB 취약점 점검

```bash
./db_vuln_check.sh -u root -p yourpassword
```

원격 DB 점검:

```bash
./db_vuln_check.sh -h db.example.com -P 3306 -u admin -p password
```

환경 변수 사용:

```bash
export MYSQL_PASSWORD="yourpassword"
./db_vuln_check.sh -u root
```

주요 옵션:

```bash
./db_vuln_check.sh --output mysql_result.txt
./db_vuln_check.sh --quiet --no-color
./db_vuln_check.sh --help
./db_vuln_check.sh --version
```

출력 파일:

```text
hostname_YYMMDD_hhmmss_mysql_result.txt
```

## MySQL/MariaDB 취약점 조치

운영 환경에서는 먼저 dry-run으로 실행될 SQL/조치 계획을 확인하세요.

```bash
# 점검 후 조치 계획만 생성
./db_vuln_fix.sh -u root -p yourpassword --dry-run

# 기존 점검 결과 파일로 조치 계획 생성
./db_vuln_fix.sh -u root -p yourpassword --dry-run -f hostname_YYMMDD_hhmmss_mysql_result.txt

# 실제 조치 실행
./db_vuln_fix.sh -u root -p yourpassword
```

환경 변수 사용:

```bash
export MYSQL_PASSWORD="yourpassword"
./db_vuln_fix.sh -u root --dry-run
```

주요 옵션:

```bash
./db_vuln_fix.sh -f hostname_YYMMDD_hhmmss_mysql_result.txt
./db_vuln_fix.sh --output mysql_fix_result.txt
./db_vuln_fix.sh --dry-run --quiet --no-color
./db_vuln_fix.sh --help
./db_vuln_fix.sh --version
```

출력 파일:

```text
hostname_YYMMDD_hhmmss_mysql_fix_result.txt
```

백업 디렉터리:

```text
/var/backup/mysql_security_fix_YYMMDD_hhmmss/
```

## 결과 상태

### 점검 결과

| 상태 | 의미 |
|---|---|
| `PASS` | 보안 설정이 적절함 |
| `FAIL` | 취약점 또는 조치 필요 항목 발견 |
| `N/A` | 해당 항목이 시스템에 적용되지 않거나 자동 판단 불가 |

### 조치 결과

| 상태 | 의미 |
|---|---|
| `SUCCESS` | 조치 성공 |
| `FAILED` | 조치 실패 |
| `SKIPPED` | 조치 대상 아님 |
| `PLANNED` | dry-run 모드에서 실행 예정으로 기록됨 |
| `MANUAL` | 수동 확인 또는 수동 조치 필요 |

## 주의사항

1. 운영 환경에서는 조치 스크립트 실행 전 반드시 `--dry-run` 결과를 확인하세요.
2. 조치 전 시스템 및 DB 백업을 별도로 확보하세요.
3. 일부 OS 조치는 SSH, 방화벽, 서비스 상태에 영향을 줄 수 있습니다.
4. 일부 DB 조치는 계정, 권한, 설정값에 영향을 줄 수 있습니다.
5. DB 비밀번호는 명령행에 노출될 수 있으므로 가능한 환경 변수 사용을 권장합니다.
6. `MANUAL` 또는 `Manual intervention required` 항목은 수동 조치 가이드를 확인하세요.

## 수동 조치 가이드

- [Linux 수동 조치 가이드](docs/linux_manual_fix_guide.md)
- [MySQL/MariaDB 수동 조치 가이드](docs/mysql_manual_fix_guide.md)
- [최신 상세가이드 기준 항목 매핑표](docs/latest_mapping_guide.md)

## 라이선스

MIT License. 자세한 내용은 [LICENSE](LICENSE)를 참조하세요.
