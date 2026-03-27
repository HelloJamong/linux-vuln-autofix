# 보안 취약점 점검 스크립트

RHEL/Rocky Linux 9 및 MySQL/MariaDB의 보안 취약점을 점검하는 자동화 스크립트 모음입니다.

**현재 버전: 26.03.01** | [변경 이력 보기](CHANGELOG.md)

## 📋 프로젝트 구조

```
linux-vuln-autofix/
├── .github/
│   └── workflows/
│       └── release.yml                # 자동 릴리즈 워크플로우
├── docs/                              # 가이드 문서
│   ├── linux_manual_fix_guide.md      # Linux 수동 조치 가이드
│   └── mysql_manual_fix_guide.md      # MySQL 수동 조치 가이드
├── README.md                          # 프로젝트 설명 문서
├── CHANGELOG.md                       # 버전별 변경 이력
├── LICENSE                            # MIT 라이선스
├── linux_vuln_check.sh                # Linux 취약점 점검 스크립트
├── linux_vuln_fix.sh                  # Linux 취약점 자동 조치 스크립트
├── db_vuln_check.sh                   # MySQL/MariaDB 취약점 점검 스크립트
└── db_vuln_fix.sh                     # MySQL/MariaDB 취약점 자동 조치 스크립트
```

## 🔖 버전 정보

각 스크립트의 버전은 다음 명령어로 확인할 수 있습니다:

```bash
./linux_vuln_check.sh --version
./linux_vuln_fix.sh --version
./db_vuln_check.sh --version
./db_vuln_fix.sh --version
```

**버전 관리 정책**:
- 이 프로젝트는 [Calendar Versioning (CalVer)](https://calver.org/)을 따릅니다.
  - 형식: **YY.MM.NN** (예: 26.03.01 = 2026년 3월 첫 번째 릴리스)
- 모든 변경사항은 [CHANGELOG.md](CHANGELOG.md)에 기록됩니다.
- 최신 보안 취약점 대응을 위해 정기적으로 업데이트됩니다.

## 🔍 제공 스크립트

### 1. Linux 취약점 점검 스크립트 (linux_vuln_check.sh)

KISA 기준 Linux 보안 취약점(U-01 ~ U-74)을 점검합니다.

#### 사용법
```bash
sudo ./linux_vuln_check.sh
```

#### 출력
- 결과 파일: `hostname_YYMMDD_hhmmss_result.txt`

#### 점검 항목 (총 74개)
- **계정 관리** (U-01 ~ U-05): root 원격 접속, 패스워드 정책, 계정 잠금 등
- **파일 및 디렉토리 관리** (U-06 ~ U-15): 권한, 소유자, SUID/SGID 등
- **서비스 관리** (U-16 ~ U-42): 불필요한 서비스, 네트워크 보안, 웹 서비스 등
- **패치 및 로그 관리** (U-43 ~ U-72): 보안 패치, 로그 설정, 시스템 설정 등

#### 위험도 분류
- **HIGH (상)**: 보안에 중대한 영향을 미치는 항목
- **MEDIUM (중)**: 보안에 영향을 미칠 수 있는 항목
- **LOW (하)**: 권장 보안 설정 항목

---

### 2. Linux 취약점 자동 조치 스크립트 (linux_vuln_fix.sh)

취약점 점검 결과를 바탕으로 자동으로 보안 조치를 수행합니다.

#### 사용법
```bash
# 기본 사용 (점검 후 자동 조치)
sudo ./linux_vuln_fix.sh

# 기존 점검 결과 파일 사용
sudo ./linux_vuln_fix.sh -f hostname_261127_143022_result.txt

# 도움말
./linux_vuln_fix.sh --help
```

#### 옵션
- `-f, --file FILE`: 기존 점검 결과 파일 사용 (새로운 점검 생략)
- `-h, --help`: 도움말 표시

#### 출력
- 조치 결과 파일: `hostname_YYMMDD_hhmmss_fix_result.txt`
- 백업 디렉토리: `/var/backup/security_fix_YYMMDD_hhmmss/`

#### 주요 기능
- **자동 백업**: 변경되는 모든 설정 파일을 자동으로 백업
- **선택적 조치**: FAIL 항목만 선택적으로 조치 수행
- **상세 로깅**: 각 조치의 성공/실패 여부를 상세히 기록
- **안전 모드**: 위험한 작업(계정 삭제, SUID 파일 제거 등)은 수동 조치 권장

#### 자동 조치 항목 예시
- **U-01**: SSH root 로그인 차단 (`PermitRootLogin no`)
- **U-02**: 패스워드 복잡도 정책 설정
- **U-03**: 계정 잠금 정책 설정 (5회 실패 시 10분 잠금)
- **U-04, U-07, U-08**: 시스템 파일 권한 설정
- **U-17**: .rhosts 및 hosts.equiv 파일 제거
- **U-19 ~ U-29**: 불필요한 서비스 비활성화
- **U-49**: su 명령어 접근 제한 (wheel 그룹만)
- **U-50 ~ U-52**: 패스워드 정책 설정
- **U-58**: 세션 타임아웃 설정 (600초)
- **U-59**: 방화벽 활성화
- **U-63**: 로그인 경고 메시지 설정
- **U-67**: UMASK 설정 (022)
- **U-71**: Core dump 비활성화

#### 수동 조치 필요 항목
일부 항목은 환경에 따라 설정이 다르거나 위험성이 높아 수동 조치가 필요합니다:
- **U-05**: UID 0 계정 관리
- **U-06, U-13, U-15**: 파일 소유자 및 권한 검토
- **U-18, U-25**: 네트워크 접근 제어
- **U-43**: 보안 패치 적용
- **U-53 ~ U-57**: 계정 및 그룹 관리
- **U-73, U-74**: OpenSSL CVE 보안 패치 (CVE-2025-11187, CVE-2025-15467)

**📖 상세 가이드**: [Linux 수동 조치 가이드](docs/linux_manual_fix_guide.md)

---

### 3. MySQL/MariaDB 취약점 점검 스크립트 (db_vuln_check.sh)

MySQL/MariaDB 데이터베이스의 보안 취약점(MX-01 ~ MX-16)을 점검합니다.

#### 사용법
```bash
# 기본 사용 (localhost, root 계정)
./db_vuln_check.sh -u root -p yourpassword

# 원격 서버 점검
./db_vuln_check.sh -h db.example.com -u admin -p password

# 환경 변수 사용
export MYSQL_PASSWORD="mypassword"
./db_vuln_check.sh -u root

# 도움말
./db_vuln_check.sh --help
```

#### 옵션
- `-h, --host HOST`: MySQL 호스트 (기본값: localhost)
- `-P, --port PORT`: MySQL 포트 (기본값: 3306)
- `-u, --user USER`: MySQL 사용자 (기본값: root)
- `-p, --password PASS`: MySQL 패스워드
- `--help`: 도움말 표시

#### 출력
- 결과 파일: `hostname_YYMMDD_hhmmss_mysql_result.txt`

#### 점검 항목 (총 16개)
- **계정 및 인증** (MX-01 ~ MX-07): root 접속 제한, 계정 관리, 패스워드 정책
- **데이터베이스 보안** (MX-08 ~ MX-10): test DB 제거, 파일 접근 제한
- **로깅 및 모니터링** (MX-11 ~ MX-13): 에러 로그, general log, slow query log
- **네트워크 및 버전** (MX-14 ~ MX-16): 버전 관리, 네트워크 설정

---

### 4. MySQL/MariaDB 취약점 자동 조치 스크립트 (db_vuln_fix.sh)

취약점 점검 결과를 바탕으로 자동으로 MySQL/MariaDB 보안 조치를 수행합니다.

#### 사용법
```bash
# 기본 사용 (점검 후 자동 조치)
./db_vuln_fix.sh -u root -p yourpassword

# 기존 점검 결과 파일 사용
./db_vuln_fix.sh -u root -p yourpassword -f hostname_261127_143022_mysql_result.txt

# 환경 변수 사용
export MYSQL_PASSWORD="mypassword"
./db_vuln_fix.sh -u root

# 원격 서버 조치
./db_vuln_fix.sh -h db.example.com -u admin -p password
```

#### 옵션
- `-h, --host HOST`: MySQL 호스트 (기본값: localhost)
- `-P, --port PORT`: MySQL 포트 (기본값: 3306)
- `-u, --user USER`: MySQL 사용자 (기본값: root)
- `-p, --password PASS`: MySQL 패스워드
- `-f, --file FILE`: 기존 점검 결과 파일 사용 (새로운 점검 생략)
- `--help`: 도움말 표시

#### 출력
- 조치 결과 파일: `hostname_YYMMDD_hhmmss_mysql_fix_result.txt`
- 백업 디렉토리: `/var/backup/mysql_security_fix_YYMMDD_hhmmss/`

#### 주요 기능
- **자동 조치**: FAIL 항목만 선택적으로 조치 수행
- **상세 로깅**: 각 조치의 성공/실패 여부를 상세히 기록
- **안전 모드**: 위험한 작업(계정 삭제, 권한 변경 등)은 수동 조치 권장

#### 자동 조치 항목 예시
- **MX-01**: Root 원격 접속 제거
- **MX-02**: 익명 계정 삭제
- **MX-05**: 패스워드 복잡도 정책 설정
- **MX-08**: test 데이터베이스 제거
- **MX-13**: Slow query log 활성화

#### 수동 조치 필요 항목
일부 항목은 my.cnf 설정 변경 및 재시작이 필요하거나 환경에 따라 신중한 검토가 필요합니다:
- **MX-03, MX-04**: 계정 관리
- **MX-06, MX-07**: 권한 최소화
- **MX-09**: FILE 권한 검토
- **MX-10, MX-11, MX-16**: my.cnf 설정 필요 (secure_file_priv, log_error, bind-address)
- **MX-14**: MySQL/MariaDB 버전 업데이트

**📖 상세 가이드**: [MySQL 수동 조치 가이드](docs/mysql_manual_fix_guide.md)

---

## 🚀 실행 예시

### Linux 취약점 점검 및 조치
```bash
# 1. 점검 스크립트 실행
sudo ./linux_vuln_check.sh

# 2. 결과 확인
cat hostname_261127_143022_result.txt

# 3. 실패한 항목만 확인
grep "FAIL" hostname_261127_143022_result.txt

# 4. 자동 조치 수행 (점검 + 조치)
sudo ./linux_vuln_fix.sh

# 5. 조치 결과 확인
cat hostname_261127_143530_fix_result.txt

# 6. 조치 후 재점검
sudo ./linux_vuln_check.sh
```

### MySQL 취약점 점검 및 조치
```bash
# 1. 점검 스크립트 실행
./db_vuln_check.sh -u root -p mypassword

# 2. 결과 확인
cat hostname_261127_143530_mysql_result.txt

# 3. 실패한 항목만 확인
grep "FAIL" hostname_261127_143530_mysql_result.txt

# 4. 자동 조치 수행 (점검 + 조치)
./db_vuln_fix.sh -u root -p mypassword

# 5. 조치 결과 확인
cat hostname_261127_144530_mysql_fix_result.txt

# 6. 조치 후 재점검
./db_vuln_check.sh -u root -p mypassword
```

---

## 📊 점검 결과 형식

### Linux 점검 결과 예시
```
[U-01] Root Remote Login Restriction
Status: PASS
Detail: [Risk: HIGH] PermitRootLogin is set to no
--------------------------------------------------------------------------------
```

### MySQL 점검 결과 예시
```
[MX-01] Root Remote Access Restriction
Status: PASS
Detail: [Risk: HIGH] Root access is restricted to localhost
--------------------------------------------------------------------------------
```

### 상태 표시
- **PASS**: 보안 설정이 적절함
- **FAIL**: 보안 취약점이 발견됨 (조치 필요)
- **N/A**: 해당 항목이 시스템에 적용되지 않음

---

## 💡 요구사항

### Linux 점검 스크립트
- **운영체제**: RHEL 9 또는 Rocky Linux 9
- **권한**: root 권한 필요
- **의존성**: bash, systemctl, grep, awk

### MySQL 점검 스크립트
- **데이터베이스**: MySQL 5.7+ 또는 MariaDB 10.3+
- **권한**: MySQL 접속 권한 필요 (일반적으로 root 권한 권장)
- **의존성**: mysql 클라이언트

---

## ⚠️ 주의사항

1. **백업 필수**: 조치 스크립트 실행 전 반드시 시스템 및 데이터베이스를 백업하세요.
   - Linux: 중요 설정 파일은 자동으로 `/var/backup/security_fix_*/` 에 백업됩니다.
   - MySQL: 데이터베이스 백업은 수동으로 수행하세요 (`mysqldump` 사용).

2. **프로덕션 환경**: 운영 환경에서 실행 시 주의가 필요합니다. 먼저 테스트 환경에서 검증하세요.
   - 일부 조치는 서비스 재시작이 필요합니다.
   - 네트워크 설정 변경 시 원격 접속이 차단될 수 있습니다.

3. **MySQL 접속 정보**: MySQL 점검 및 조치 시 패스워드가 명령행에 노출될 수 있으므로, 환경 변수 사용을 권장합니다.
   ```bash
   export MYSQL_PASSWORD="yourpassword"
   ./db_vuln_check.sh -u root
   ./db_vuln_fix.sh -u root
   ```

4. **결과 파일 관리**: 점검 및 조치 결과 파일은 자동으로 `.gitignore`에 추가되어 Git에 커밋되지 않습니다.

5. **수동 조치 항목**: 일부 항목은 자동 조치가 불가능하거나 위험하여 수동 조치가 필요합니다.
   - 조치 결과 파일에서 "Manual intervention required" 항목을 확인하세요.
   - 특히 계정 삭제, 권한 변경, 설정 파일 수정은 신중하게 검토 후 수행하세요.

6. **MySQL 재시작**: 일부 MySQL 설정은 my.cnf 수정 후 재시작이 필요합니다.
   ```bash
   sudo systemctl restart mysqld
   # 또는
   sudo systemctl restart mariadb
   ```

---

## 🚀 릴리즈 프로세스

이 프로젝트는 GitHub Actions를 사용한 자동화된 릴리즈 워크플로우를 제공합니다.

### 새 버전 릴리즈 방법

1. **CHANGELOG.md 업데이트**
   ```markdown
   ## [v26.04.01] - 2026-04-15

   ### Added
   - 새로운 취약점 항목 추가

   ### Fixed
   - 버그 수정 내용
   ```

2. **Git 태그 생성 및 푸시**
   ```bash
   git tag v26.04.01
   git push origin v26.04.01
   ```

3. **자동 릴리즈 생성**
   - GitHub Actions가 자동으로 실행됩니다
   - 모든 스크립트의 버전이 자동으로 업데이트됩니다
   - 2개의 배포 파일이 생성됩니다:
     - `linux_vuln_scripts.zip`: Linux 점검/조치 스크립트 + 가이드
     - `db_vuln_scripts.zip`: MySQL/MariaDB 점검/조치 스크립트 + 가이드
   - CHANGELOG.md 기반 릴리즈 노트가 자동 생성됩니다

### 릴리즈 패키지 내용

**linux_vuln_scripts.zip**:
- `linux_vuln_check.sh` - Linux 취약점 점검 스크립트
- `linux_vuln_fix.sh` - Linux 취약점 자동 조치 스크립트
- `linux_manual_fix_guide.md` - 수동 조치 가이드
- `README.md` - 프로젝트 설명
- `LICENSE` - 라이선스 파일

**db_vuln_scripts.zip**:
- `db_vuln_check.sh` - MySQL/MariaDB 취약점 점검 스크립트
- `db_vuln_fix.sh` - MySQL/MariaDB 취약점 자동 조치 스크립트
- `mysql_manual_fix_guide.md` - 수동 조치 가이드
- `README.md` - 프로젝트 설명
- `LICENSE` - 라이선스 파일

---

## 📝 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

### 참고 자료

이 프로젝트는 KISA(한국인터넷진흥원)의 주요정보통신기반시설 취약점 분석·평가 가이드를 기반으로 작성 및 최신화되었습니다.

- [KISA 주요정보통신기반시설 취약점 분석·평가 가이드](https://www.kisa.or.kr/2060204/form?postSeq=12&lang_type=KO&page=1)

---
