# RHEL/Rocky Linux 9 보안 취약점 점검 및 조치 스크립트

해당 스크립트는 Linux 중 RHEL 및 Rocky Linux 9 버전에 최적화된 보안취약점 점검 및 조치 스크립트입니다.

## 프로젝트 구조

```
linux-vuln-autofix/
├── README.md              # 프로젝트 설명 문서
├── vuln_check.sh          # 취약점 점검 스크립트
├── vuln_fix.sh            # 취약점 조치 스크립트
├── backup_YYMMDD/         # 조치 시 생성되는 백업 디렉토리
└── logs/                  # 점검 결과 및 로그 저장 디렉토리
```

## 제공 스크립트

### 1. 취약점 점검 스크립트 (vuln_check.sh)

시스템의 보안 취약점을 점검하고 결과를 파일로 저장합니다.

**사용법:**
```bash
sudo ./vuln_check.sh
```

**출력:**
- 결과 파일: `hostname_YYMMDD_hhmmss_result.txt` 형식으로 제공됩니다.

**점검 항목:**
- U-01: root 계정 원격 접속 제한
- U-02: 패스워드 복잡성 설정
- U-03: 계정 잠금 임계값 설정
- U-04: 패스워드 최대 사용 기간 설정
- U-05: 패스워드 최소 사용 기간 설정
- U-06: /etc/passwd 파일 소유자 및 권한 설정
- U-07: /etc/shadow 파일 소유자 및 권한 설정
- U-08: /etc/hosts 파일 소유자 및 권한 설정
- U-09: UMASK 설정 관리
- U-10: 불필요한 서비스 비활성화

### 2. 취약점 조치 스크립트 (vuln_fix.sh)

점검이 완료된 결과 파일을 기반으로 취약점을 자동 조치합니다.

**사용법:**
```bash
sudo ./vuln_fix.sh
```

**주의사항:**
- 스크립트 실행 경로에 점검 결과 문서(`hostname_YYMMDD_hhmmss_result.txt`)가 없으면 동작하지 않습니다.
- 같은 날짜의 점검 결과 파일이 여러 개인 경우, 가장 최근 파일을 자동으로 사용합니다.
- 조치 전 원본 설정 파일을 `backup_YYMMDD/` 디렉토리에 자동 백업합니다.
- 조치 로그는 `hostname_YYMMDD_fix_log.txt` 파일로 저장됩니다.

**출력:**
- 조치 로그: `hostname_YYMMDD_fix_log.txt`
- 백업 디렉토리: `backup_YYMMDD/`

## 실행 순서

1. 점검 스크립트 실행
```bash
sudo ./vuln_check.sh
```

2. 점검 결과 확인
```bash
cat hostname_YYMMDD_result.txt
```

3. 조치 스크립트 실행
```bash
sudo ./vuln_fix.sh
```

4. 조치 결과 확인을 위해 다시 점검 스크립트 실행
```bash
sudo ./vuln_check.sh
```

## 요구사항

- 운영체제: RHEL 9 또는 Rocky Linux 9
- 권한: root 권한 필요
- 의존성: bash, systemctl
