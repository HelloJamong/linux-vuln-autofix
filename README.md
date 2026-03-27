# 보안 취약점 점검 스크립트

RHEL/Rocky Linux 9 및 MySQL/MariaDB의 보안 취약점을 점검하는 자동화 스크립트 모음입니다.

## 📋 프로젝트 구조

```
linux-vuln-autofix/
├── README.md                          # 프로젝트 설명 문서
├── linux_vuln_check.sh                # Linux 취약점 점검 스크립트
└── db_vuln_check.sh                   # MySQL/MariaDB 취약점 점검 스크립트
```

## 🔍 제공 스크립트

### 1. Linux 취약점 점검 스크립트 (linux_vuln_check.sh)

KISA 기준 Linux 보안 취약점(U-01 ~ U-72)을 점검합니다.

#### 사용법
```bash
sudo ./linux_vuln_check.sh
```

#### 출력
- 결과 파일: `hostname_YYMMDD_hhmmss_result.txt`

#### 점검 항목 (총 72개)
- **계정 관리** (U-01 ~ U-05): root 원격 접속, 패스워드 정책, 계정 잠금 등
- **파일 및 디렉토리 관리** (U-06 ~ U-15): 권한, 소유자, SUID/SGID 등
- **서비스 관리** (U-16 ~ U-42): 불필요한 서비스, 네트워크 보안, 웹 서비스 등
- **패치 및 로그 관리** (U-43 ~ U-72): 보안 패치, 로그 설정, 시스템 설정 등

#### 위험도 분류
- **HIGH (상)**: 보안에 중대한 영향을 미치는 항목
- **MEDIUM (중)**: 보안에 영향을 미칠 수 있는 항목
- **LOW (하)**: 권장 보안 설정 항목

---

### 2. MySQL/MariaDB 취약점 점검 스크립트 (db_vuln_check.sh)

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

## 🚀 실행 예시

### Linux 취약점 점검
```bash
# 1. 점검 스크립트 실행
sudo ./linux_vuln_check.sh

# 2. 결과 확인
cat hostname_261127_143022_result.txt

# 3. 결과 분석
grep "FAIL" hostname_261127_143022_result.txt
```

### MySQL 취약점 점검
```bash
# 1. 점검 스크립트 실행
./db_vuln_check.sh -u root -p mypassword

# 2. 결과 확인
cat hostname_261127_143530_mysql_result.txt

# 3. 실패한 항목만 확인
grep "FAIL" hostname_261127_143530_mysql_result.txt
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

1. **백업 권장**: 점검 스크립트는 시스템을 변경하지 않지만, 조치 전 반드시 백업을 수행하세요.

2. **프로덕션 환경**: 운영 환경에서 실행 시 주의가 필요합니다. 먼저 테스트 환경에서 검증하세요.

3. **MySQL 접속 정보**: MySQL 점검 시 패스워드가 명령행에 노출될 수 있으므로, 환경 변수 사용을 권장합니다.
   ```bash
   export MYSQL_PASSWORD="yourpassword"
   ./db_vuln_check.sh -u root
   ```

4. **결과 파일 관리**: 점검 결과 파일은 자동으로 `.gitignore`에 추가되어 Git에 커밋되지 않습니다.

---


## 📝 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

### 참고 자료

이 프로젝트는 KISA(한국인터넷진흥원)의 주요정보통신기반시설 취약점 분석·평가 가이드를 기반으로 작성 및 최신화되었습니다.

- [KISA 주요정보통신기반시설 취약점 분석·평가 가이드](https://www.kisa.or.kr/2060204/form?postSeq=12&lang_type=KO&page=1)

---
