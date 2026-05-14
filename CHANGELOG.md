# Changelog

이 프로젝트의 모든 주목할 만한 변경사항이 이 파일에 기록됩니다.

형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.0.0/)를 기반으로 하며,
이 프로젝트는 [Calendar Versioning (CalVer)](https://calver.org/)을 따릅니다.

## [Unreleased]

## [v26.05.01] - 2026-05-14

### Added
- **최신 상세가이드 기준 항목 매핑 문서** (`docs/latest_mapping_guide.md`)
  - Linux 기존 `U-*` 항목과 최신 `U-01~U-67` 항목 간 매핑표 추가
  - MySQL/MariaDB 기존 `MX-*` 항목과 최신 DBMS `D-*` 항목 간 매핑표 추가
  - 과거 기준에는 있었지만 최신 기준에서 제거·흡수·이관된 항목 목록 추가
  - 과거 기준에는 없었지만 최신 기준에서 신규로 추가된 항목 목록 추가

- **Linux 신규 점검 항목**
  - U-13: 안전한 비밀번호 암호화 알고리즘 사용 점검
  - U-17: 시스템 시작 스크립트 권한 설정 점검
  - U-51: DNS 서비스의 취약한 동적 업데이트 설정 금지 점검
  - U-52: Telnet 서비스 비활성화 점검
  - U-53: FTP 서비스 정보 노출 제한 점검
  - U-56: FTP 서비스 접근 제어 설정 점검
  - U-59: 안전한 SNMP 버전 사용 점검
  - U-61: SNMP Access Control 설정 점검
  - U-63: sudo 명령어 접근 관리 점검
  - U-65: NTP 및 시각 동기화 설정 점검
  - U-67: 로그 디렉터리 소유자 및 권한 설정 점검

- **MySQL/MariaDB 신규 DBMS 점검 항목**
  - D-06: DB 사용자 계정 개별 부여 점검
  - D-07: root 권한 서비스 구동 제한 점검
  - D-08: 안전한 암호화 알고리즘 사용 점검
  - D-11: DBA 이외 사용자의 시스템 테이블 접근 제한 점검
  - D-21: 인가되지 않은 GRANT OPTION 사용 제한 점검

### Changed
- **Linux 점검/조치 체계 최신화**
  - 기존 Linux 실행 체계를 최신 상세가이드 기준 `U-01~U-67`로 재정렬
  - 기존 점검/조치 함수는 가능한 범위에서 최신 항목에 매핑하여 재사용
  - 최신 기준에서 직접 대응되지 않는 웹 서비스·Apache·at 파일·개별 OpenSSL CVE 항목은 제거, 이관 또는 `U-64` 패치 관리 범주로 통합

- **MySQL/MariaDB 점검/조치 체계 최신화**
  - 기존 `MX-01~MX-16` 체계를 최신 DBMS `D-*` 체계로 재매핑
  - MySQL/MariaDB 대상 점검 항목을 `D-01`, `D-02`, `D-03`, `D-04`, `D-06`, `D-07`, `D-08`, `D-10`, `D-11`, `D-14`, `D-21`, `D-25`로 정리
  - MariaDB는 MySQL 호환 대상으로 간주하여 별도 코드 체계 없이 동일한 `D-*` 기준 적용
  - 기존 `MX-*` 결과 파일을 일부 fallback으로 해석할 수 있도록 조치 스크립트에 호환 매핑 유지

- **문서 최신화**
  - README의 Linux 점검 범위를 `U-01~U-74`에서 `U-01~U-67`로 변경
  - README의 DB 점검 범위를 기존 `MX-*`에서 최신 `D-*` 기준으로 변경
  - README에 KISA 최신 원문 게시글 링크 추가
    - `https://www.kisa.or.kr/2060204/form?postSeq=22&page=1`
    - KISA 게시글 등록일: `2025-12-24`

### Security
- 최신 KISA `주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드` 기준으로 Linux 및 MySQL/MariaDB 취약점 항목을 재정렬
- Linux 보안 점검 범위를 최신 UNIX/Linux 항목 67개 기준으로 정리
- MySQL/MariaDB 보안 점검 범위를 최신 DBMS 항목 중 MySQL 대상 12개 항목 기준으로 정리

## [v26.03.02] - 2026-03-27

### Added
- **Linux 취약점 점검 스크립트** (`linux_vuln_check.sh`)
  - U-73: OpenSSL CVE-2025-11187 보안 패치 점검
  - U-74: OpenSSL CVE-2025-15467 보안 패치 점검
  - Rocky Linux 백포트 정책을 고려한 RPM changelog 기반 CVE 패치 확인

- **수동 조치 가이드** (`docs/linux_manual_fix_guide.md`)
  - U-73 OpenSSL CVE-2025-11187 수동 조치 가이드 추가
  - U-74 OpenSSL CVE-2025-15467 수동 조치 가이드 추가
  - Rocky Linux 백포트 정책 설명 및 패치 확인 방법
  - OpenSSL 업데이트 후 서비스 재시작 절차

### Security
- **OpenSSL 보안 취약점 대응** (총 74개 항목으로 확대)
  - CVE-2025-11187: OpenSSL 보안 취약점 점검 및 조치
  - CVE-2025-15467: OpenSSL 보안 취약점 점검 및 조치
  - 백포트 환경에서의 보안 패치 검증 방법 제공

## [v26.03.01] - 2026-03-27

### Added
- **Linux 취약점 점검 스크립트** (`linux_vuln_check.sh`)
  - KISA 기준 Linux 보안 취약점 점검 (U-01 ~ U-72)
  - RHEL/Rocky Linux 9 환경 자동 검증
  - 상세한 점검 결과 파일 생성 (`hostname_YYMMDD_hhmmss_result.txt`)
  - 위험도 분류 (HIGH/MEDIUM/LOW)

- **Linux 취약점 자동 조치 스크립트** (`linux_vuln_fix.sh`)
  - 취약점 점검 결과 기반 자동 조치
  - RHEL/Rocky Linux 9 환경 자동 검증
  - 자동 백업 기능 (`/var/backup/security_fix_*/`)
  - 조치 전 점검 결과 파일 자동 생성 옵션
  - 기존 점검 결과 파일 재사용 옵션 (`-f, --file`)
  - 상세한 조치 결과 로깅

- **MySQL/MariaDB 취약점 점검 스크립트** (`db_vuln_check.sh`)
  - MySQL/MariaDB 보안 취약점 점검 (MX-01 ~ MX-16)
  - MySQL/MariaDB 환경 자동 검증 (클라이언트 및 서버 실행 확인)
  - 원격 서버 점검 지원
  - 환경 변수를 통한 안전한 패스워드 관리
  - 상세한 점검 결과 파일 생성 (`hostname_YYMMDD_hhmmss_mysql_result.txt`)

- **MySQL/MariaDB 취약점 자동 조치 스크립트** (`db_vuln_fix.sh`)
  - 취약점 점검 결과 기반 자동 조치
  - MySQL/MariaDB 환경 자동 검증
  - 원격 서버 조치 지원
  - 조치 전 점검 결과 파일 자동 생성 옵션
  - 기존 점검 결과 파일 재사용 옵션 (`-f, --file`)
  - 상세한 조치 결과 로깅

- **가이드 문서**
  - Linux 수동 조치 가이드 (`docs/linux_manual_fix_guide.md`)
    - 12개 수동 조치 필요 항목 상세 설명 (U-05, U-06, U-13, U-15, U-18, U-25, U-43, U-53~U-57)
    - 각 항목별 취약점 설명, 점검 방법, 조치 방법, 주의사항, 검증 방법 포함
  - MySQL 수동 조치 가이드 (`docs/mysql_manual_fix_guide.md`)
    - 9개 수동 조치 필요 항목 상세 설명 (MX-03, MX-04, MX-06, MX-07, MX-09, MX-10, MX-11, MX-14, MX-16)
    - 각 항목별 취약점 설명, 점검 방법, 조치 방법, 주의사항, 검증 방법 포함

- **환경 검증 기능**
  - Linux 스크립트: RHEL/Rocky Linux 9 환경 자동 확인
    - `/etc/os-release` 파일 기반 OS 종류 및 버전 검증
    - 미지원 환경에서 명확한 오류 메시지와 함께 종료
  - DB 스크립트: MySQL/MariaDB 설치 및 실행 상태 자동 확인
    - mysql 클라이언트 설치 여부 확인
    - MySQL/MariaDB 서버 실행 여부 확인 (프로세스, 소켓, systemd 서비스)
    - 미설치/미실행 시 설치/시작 방법 안내와 함께 종료

- **프로젝트 문서**
  - README.md: 프로젝트 전체 설명 및 사용 가이드
  - LICENSE: MIT 라이선스
  - .gitignore: 점검/조치 결과 파일 제외 설정

### Security
- **Linux 취약점 72개 항목 점검/조치**
  - 계정 관리 (U-01 ~ U-05): root 원격 접속, 패스워드 정책, 계정 잠금
  - 파일 및 디렉토리 관리 (U-06 ~ U-15): 권한, 소유자, SUID/SGID
  - 서비스 관리 (U-16 ~ U-42): 불필요한 서비스, 네트워크 보안
  - 패치 및 로그 관리 (U-43 ~ U-72): 보안 패치, 로그 설정

- **MySQL/MariaDB 취약점 16개 항목 점검/조치**
  - 계정 및 인증 (MX-01 ~ MX-07): root 접속 제한, 계정 관리, 패스워드 정책
  - 데이터베이스 보안 (MX-08 ~ MX-10): test DB 제거, 파일 접근 제한
  - 로깅 및 모니터링 (MX-11 ~ MX-13): 에러 로그, general log, slow query log
  - 네트워크 및 버전 (MX-14 ~ MX-16): 버전 관리, 네트워크 설정

---

## 버전 관리 정책

### 버전 번호 체계 (Calendar Versioning)

**YY.MM.NN** (예: 26.03.01)

- **YY**: 연도의 마지막 두 자리 (예: 26 = 2026년)
- **MM**: 월 (01-12)
- **NN**: 해당 월의 릴리스 번호 (01부터 시작)

**예시**:
- `26.03.01`: 2026년 3월의 첫 번째 릴리스
- `26.03.02`: 2026년 3월의 두 번째 릴리스
- `26.04.01`: 2026년 4월의 첫 번째 릴리스

### 변경사항 분류

- **Added**: 새로운 기능 추가
- **Changed**: 기존 기능 변경
- **Deprecated**: 곧 제거될 기능 (하위 호환성 유지)
- **Removed**: 제거된 기능
- **Fixed**: 버그 수정
- **Security**: 보안 취약점 관련 변경사항

### 업데이트 확인

각 스크립트의 버전은 다음 명령어로 확인할 수 있습니다:

```bash
./linux_vuln_check.sh --version
./linux_vuln_fix.sh --version
./db_vuln_check.sh --version
./db_vuln_fix.sh --version
```

---

## 참고사항

- 이 CHANGELOG는 사람이 읽기 쉽게 작성되었습니다.
- 모든 주목할 만한 변경사항은 여기에 기록됩니다.
- 각 버전의 릴리스 날짜는 YYYY-MM-DD 형식으로 표시됩니다.
- 최신 버전이 항상 파일 상단에 위치합니다.

[Unreleased]: https://github.com/yourusername/linux-vuln-autofix/compare/v26.05.01...HEAD
[v26.05.01]: https://github.com/yourusername/linux-vuln-autofix/compare/v26.03.02...v26.05.01
[v26.03.02]: https://github.com/yourusername/linux-vuln-autofix/compare/v26.03.01...v26.03.02
[v26.03.01]: https://github.com/yourusername/linux-vuln-autofix/releases/tag/v26.03.01
