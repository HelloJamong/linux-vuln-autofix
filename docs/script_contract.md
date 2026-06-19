# 4개 단일 스크립트 기준 Contract

작성 기준: v26.05.01 현재 구현 및 2단계 CLI/result 표준화 기준.  
목적: 향후 Rocky Linux 8.10/9.x 및 MySQL/MariaDB 공통화를 진행할 때 깨지면 안 되는 CLI, 결과 파일, 상태값 기준선을 고정한다.

## 1. 최종 배포 단위

이 프로젝트의 최종 runtime 산출물은 다음 4개 단일 스크립트다.

| 구분 | 파일 | 현재 목적 | 현재 주요 근거 |
|---|---|---|---|
| OS 점검 | `linux_vuln_check.sh` | RHEL/Rocky Linux 9 기준 Linux 취약점 점검 | `README.md:45-61`, `linux_vuln_check.sh:2917-2984` |
| OS 조치 | `linux_vuln_fix.sh` | Linux 점검 결과 기반 자동 조치 | `README.md:70-120`, `linux_vuln_fix.sh:1763-1814` |
| DB 점검 | `db_vuln_check.sh` | MySQL/MariaDB D-* 취약점 점검 | `README.md:125-160`, `db_vuln_check.sh:763-775` |
| DB 조치 | `db_vuln_fix.sh` | MySQL/MariaDB 점검 결과 기반 자동/수동 조치 | `README.md:163-214`, `db_vuln_fix.sh:657-720` |

## 2. CLI Contract: 현재 기준

### 2.1 `linux_vuln_check.sh`

현재 지원:

```bash
./linux_vuln_check.sh --version
./linux_vuln_check.sh -v
./linux_vuln_check.sh --help
sudo ./linux_vuln_check.sh
sudo ./linux_vuln_check.sh --output hostname_YYMMDD_hhmmss_result.txt
sudo ./linux_vuln_check.sh --quiet --no-color
```

현재 `--help` 전용 usage 함수와 공통 옵션 파서를 제공한다.

현재 옵션:

| 옵션 | 의미 |
|---|---|
| `-o, --output FILE` | OS 점검 결과 파일 경로 지정 |
| `-q, --quiet` | 진행 출력 최소화 |
| `--no-color` | 터미널 색상 출력 비활성화 |
| `-h, --help` | 도움말 출력 |
| `-v, --version` | 버전 출력 |

Version 출력 기준:

```text
Linux Vulnerability Check Script v26.05.01
RHEL/Rocky Linux 9 Security Vulnerability Assessment

For more information, see CHANGELOG.md
```

### 2.2 `linux_vuln_fix.sh`

현재 지원:

```bash
sudo ./linux_vuln_fix.sh
sudo ./linux_vuln_fix.sh -f hostname_YYMMDD_hhmmss_result.txt
sudo ./linux_vuln_fix.sh --file hostname_YYMMDD_hhmmss_result.txt
./linux_vuln_fix.sh --help
./linux_vuln_fix.sh -h
./linux_vuln_fix.sh --output hostname_YYMMDD_hhmmss_fix_result.txt
./linux_vuln_fix.sh --dry-run --quiet --no-color
./linux_vuln_fix.sh --version
./linux_vuln_fix.sh -v
```

현재 옵션:

| 옵션 | 의미 |
|---|---|
| `-f, --file FILE` | 기존 OS 점검 결과 파일 사용 |
| `-o, --output FILE` | OS 조치 결과 파일 경로 지정 |
| `--dry-run` | 시스템 변경 없이 조치 계획만 기록 |
| `-q, --quiet` | 진행 출력 최소화 |
| `--no-color` | 터미널 색상 출력 비활성화 |
| `-h, --help` | 도움말 출력 |
| `-v, --version` | 버전 출력 |

### 2.3 `db_vuln_check.sh`

현재 지원:

```bash
./db_vuln_check.sh -u root -p password
./db_vuln_check.sh -h localhost -P 3306 -u root -p password
MYSQL_PASSWORD=password ./db_vuln_check.sh -u root
./db_vuln_check.sh --output hostname_YYMMDD_hhmmss_mysql_result.txt
./db_vuln_check.sh --quiet --no-color
./db_vuln_check.sh --help
./db_vuln_check.sh --version
./db_vuln_check.sh -v
```

현재 옵션:

| 옵션 | 의미 |
|---|---|
| `-h, --host HOST` | MySQL/MariaDB host, 기본값 `localhost` |
| `-P, --port PORT` | MySQL/MariaDB port, 기본값 `3306` |
| `-u, --user USER` | MySQL/MariaDB user, 기본값 `root` |
| `-p, --password PASS` | MySQL/MariaDB password |
| `-o, --output FILE` | DB 점검 결과 파일 경로 지정 |
| `-q, --quiet` | 진행 출력 최소화 |
| `--no-color` | 터미널 색상 출력 비활성화 |
| `--help` | 도움말 출력 |
| `-v, --version` | 버전 출력 |

현재 환경 변수:

- `MYSQL_HOST`
- `MYSQL_PORT`
- `MYSQL_USER`
- `MYSQL_PASSWORD`

### 2.4 `db_vuln_fix.sh`

현재 지원:

```bash
./db_vuln_fix.sh -u root -p password
./db_vuln_fix.sh -h localhost -P 3306 -u root -p password
./db_vuln_fix.sh -u root -p password -f hostname_YYMMDD_hhmmss_mysql_result.txt
MYSQL_PASSWORD=password ./db_vuln_fix.sh -u root
./db_vuln_fix.sh --output hostname_YYMMDD_hhmmss_mysql_fix_result.txt
./db_vuln_fix.sh --dry-run --quiet --no-color
./db_vuln_fix.sh --help
./db_vuln_fix.sh --version
./db_vuln_fix.sh -v
```

현재 옵션:

| 옵션 | 의미 |
|---|---|
| `-h, --host HOST` | MySQL/MariaDB host, 기본값 `localhost` |
| `-P, --port PORT` | MySQL/MariaDB port, 기본값 `3306` |
| `-u, --user USER` | MySQL/MariaDB user, 기본값 `root` |
| `-p, --password PASS` | MySQL/MariaDB password |
| `-f, --file FILE` | 기존 DB 점검 결과 파일 사용 |
| `-o, --output FILE` | DB 조치 결과 파일 경로 지정 |
| `--dry-run` | DB 변경 없이 조치 SQL/계획만 기록 |
| `-q, --quiet` | 진행 출력 최소화 |
| `--no-color` | 터미널 색상 출력 비활성화 |
| `--help` | 도움말 출력 |
| `-v, --version` | 버전 출력 |

현재 환경 변수:

- `MYSQL_HOST`
- `MYSQL_PORT`
- `MYSQL_USER`
- `MYSQL_PASSWORD`

## 3. Result File Contract: 현재 기준

### 3.1 OS 점검 결과

파일명:

```text
hostname_YYMMDD_hhmmss_result.txt
```

헤더 주요 필드:

```text
OS Version: ...
OS ID: rocky|rhel
OS VERSION_ID: 8.10|9.x
OS Major Version: 8|9
Capability systemctl: true|false
Capability systemd_runtime: true|false
Capability authselect: true|false
Capability faillock_conf: /etc/security/faillock.conf|none
Capability pam_auth_files: comma-separated paths|none
Capability firewall_backend: firewalld|nftables|iptables|none
Capability package_manager: dnf|yum|rpm|unknown
Capability time_sync: comma-separated capabilities|none
Capability crypto_policies: true|false
Capability selinux: Enforcing|Permissive|Disabled|unknown
Capability network_tool: ss|netstat|unknown
```

항목 형식:

```text
[U-01] 항목명
Status: PASS|FAIL|N/A
Detail: [Risk: HIGH|MEDIUM|LOW] 상세 내용
Risk: HIGH|MEDIUM|LOW
--------------------------------------------------------------------------------
```

현재 생성 근거:

- `linux_vuln_check.sh:72-80`
- `linux_vuln_check.sh:84-93`

### 3.2 OS 조치 결과

파일명:

```text
hostname_YYMMDD_hhmmss_fix_result.txt
```

헤더 주요 필드:

```text
OS Version: ...
OS ID: rocky|rhel|unknown
OS VERSION_ID: 8.10|9.x|unknown
OS Major Version: 8|9|unknown
Capability systemctl: true|false
Capability systemd_runtime: true|false
Capability authselect: true|false
Capability faillock_conf: /etc/security/faillock.conf|none
Capability pam_auth_files: comma-separated paths|none
Capability firewall_backend: firewalld|nftables|iptables|none
Capability package_manager: dnf|yum|rpm|unknown
Capability time_sync: comma-separated capabilities|none
Capability crypto_policies: true|false
Capability selinux: Enforcing|Permissive|Disabled|unknown
Capability network_tool: ss|netstat|unknown
Mode: APPLY|DRY-RUN
```

항목 형식:

```text
[U-01] 항목명
Status: SUCCESS|FAILED|SKIPPED|PLANNED|MANUAL
Detail: 상세 내용
--------------------------------------------------------------------------------
```

현재 생성 근거:

- `linux_vuln_fix.sh:162-171`
- `linux_vuln_fix.sh:175-184`

### 3.3 DB 점검 결과

파일명:

```text
hostname_YYMMDD_hhmmss_mysql_result.txt
```

항목 형식:

```text
[D-01] 항목명
Status: PASS|FAIL|N/A
Detail: [Risk: HIGH|MEDIUM|LOW] 상세 내용
Risk: HIGH|MEDIUM|LOW
--------------------------------------------------------------------------------
```

현재 생성 근거:

- `db_vuln_check.sh:187-198`
- `db_vuln_check.sh:202-211`

### 3.4 DB 조치 결과

파일명:

```text
hostname_YYMMDD_hhmmss_mysql_fix_result.txt
```

항목 형식:

```text
[D-01] 항목명
Status: SUCCESS|FAILED|SKIPPED|PLANNED|MANUAL
Detail: 상세 내용
--------------------------------------------------------------------------------
```

현재 생성 근거:

- `db_vuln_fix.sh:217-230`
- `db_vuln_fix.sh:233-242`

## 4. Status Contract

### 4.1 점검 상태값

| 상태 | 의미 |
|---|---|
| `PASS` | 현재 기준에서 양호 |
| `FAIL` | 현재 기준에서 취약 또는 조치 필요 |
| `N/A` | 미설치, 미적용, 수동 확인 필요 등 자동 판정 부적합 |

### 4.2 조치 상태값

| 상태 | 의미 |
|---|---|
| `SUCCESS` | 조치 성공 |
| `FAILED` | 조치 실패 또는 수동 조치 필요 |
| `SKIPPED` | 점검 결과가 PASS/N/A이거나 조치 대상 아님 |
| `PLANNED` | dry-run 모드에서 자동 조치 대상이지만 실제 변경은 수행하지 않음 |
| `MANUAL` | 수동 판단/수동 조치가 필요한 항목 |

## 5. Parser Compatibility Contract

현재 조치 스크립트는 점검 결과 파일에서 다음 방식으로 상태를 찾는다.

- `linux_vuln_fix.sh:205-213`
- `linux_vuln_fix.sh:1621-1630`
- `db_vuln_fix.sh:263-271`
- `db_vuln_fix.sh:572-575`

따라서 향후 결과 파일을 확장하더라도 다음 조건은 유지해야 한다.

1. 항목 시작 라인은 `^[ID]` 형태여야 한다.
2. 항목 시작 후 가까운 줄에 `Status: VALUE`가 있어야 한다.
3. 항목 시작 후 가까운 줄에 `Detail: VALUE`가 있어야 한다.
4. 기존 `Status:`와 `Detail:` 라인은 제거하거나 이름을 바꾸지 않는다.
5. 새 필드(`Risk:`, `Policy:` 등)는 추가만 한다. 현재 점검 결과의 `Risk:`는 `Detail:` 다음에 기록해 기존 `grep -A 2` 파서를 유지한다.

## 6. Baseline Fixtures

결과 파일 포맷 검증이 필요한 경우 실제 스크립트를 실행하여 결과 파일을 생성한 후 확인한다.
`tests/fixtures/` 디렉토리는 제거됨 — 실제 테스트 러너 없이 샘플 파일만 존재했으므로 삭제.
