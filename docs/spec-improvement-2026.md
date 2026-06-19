# Spec: linux-vuln-autofix 개선 및 최신화 (2026)

작성일: 2026-06-19  
최종 업데이트: 2026-06-19  
기준 버전: v26.05.01  
목표: Rocky Linux 8.10 / 9.x + MySQL/MariaDB 대상의 단일 점검 스크립트 + 단일 자동조치 스크립트를 완성한다.

---

## 진행 현황 (2026-06-19 기준)

### ✅ 완료

| 항목 | 내용 | 커밋 |
|---|---|---|
| L1-T1 | U-03 `CAP_FAILLOCK_CONF` 분기, Rocky 8 pam.d fallback | feat: Linux 점검... |
| L1-T2 | U-65 `CAP_TIME_SYNC` 기반 NTP 서비스 확인 | 동일 |
| L1-T3 | Rocky 8.10 기준 `linux_check_rocky8.fixture` 생성 | 동일 |
| L2-T1 | U-01 레거시 래퍼 → 직접 구현 (PermitRootLogin 파싱) | 동일 |
| L2-T2 | U-04 레거시 래퍼 → 직접 구현 (passwd shadow 확인) | 동일 |
| L2-T3 | U-14 root PATH/홈 직접 구현, check_u05 의미 불일치 해소 | 동일 |
| L3-T1 | U-28 `ip_forward=0`, `tcp_syncookies=1`, firewall 점검 신규 추가 | 동일 |
| L3-T2 | U-33 `.netrc` 스캔 + 소유자 없는 숨김 파일 직접 구현 | 동일 |

### 🔲 진행 필요

| 우선순위 | 항목 | 분류 | 내용 |
|---|---|---|---|
| HIGH | **Phase 1-A** | 헤더 | `linux_vuln_check.sh`, `linux_vuln_fix.sh` 헤더 주석 "RHEL/Rocky Linux 9" → "Rocky Linux 8.10/9.x" |
| HIGH | **Phase 1-B** | 문서 | `CHANGELOG.md` `yourusername` placeholder URL 교체 |
| HIGH | **GAP-L1 잔여** | OS 분기 | U-02 `CAP_AUTHSELECT` 없는 Rocky 8 환경 pwquality 로드 확인 |
| HIGH | **GAP-L1 잔여** | OS 분기 | U-13 `CAP_CRYPTO_POLICIES` 기반 hash algorithm 분기 |
| MEDIUM | **GAP-L2 잔여** | 레거시 전환 | U-23 SUID/SGID Rocky 8/9 기본 목록 차이 반영 |
| MEDIUM | **GAP-L2 잔여** | 레거시 전환 | U-30 UMASK login.defs/profile.d 직접 점검 |
| MEDIUM | **GAP-L2 잔여** | 레거시 전환 | U-62 /etc/motd, /etc/issue 경고 메시지 직접 점검 |
| MEDIUM | **GAP-D1** | DB | KISA 최신 가이드 D-05, D-09, D-12~D-24 범위 확인 및 구현/N/A 결정 |
| MEDIUM | **GAP-D2** | DB | MariaDB 10.x/11.x 암호화 플러그인 분기 (D-08) |
| MEDIUM | **GAP-D3** | DB | `db_vuln_fix.sh` MX-* fallback 코드 제거 |
| MEDIUM | **Phase 6** | CI | `.github/workflows/lint.yml` shellcheck + `bash -n` 추가 |
| LOW | **Phase 5** | 문서 | `linux_manual_fix_guide.md` U-01~U-67 기준 목차 갱신 |
| LOW | **Phase 5** | 문서 | `mysql_manual_fix_guide.md` D-* 체계 전면 갱신 |
| LOW | **Phase 1-C** | 문서 | `README.md` 지원 OS "Rocky Linux 8.10 및 9.x" 명시 |

### 레거시 매핑 잔존 현황

최초 50개 → 현재 **44개** (6개 직접 전환 완료)  
잔여 44개 중 의미 검증 필요 우선 항목: U-23, U-24, U-30, U-62

---

---

## 1. 현재 상태 요약 (As-Is)

### 산출물 구조

| 파일 | 라인 수 | 상태 |
|---|---|---|
| `linux_vuln_check.sh` | 3,455 | U-01~U-67 전항목 구현, 다수가 레거시 매핑 |
| `linux_vuln_fix.sh` | 2,346 | U-01~U-67 조치 계층 존재, 레거시 매핑 다수 |
| `db_vuln_check.sh` | 838 | D-01~D-25 중 12개 항목, MX→D 마이그레이션 완료 |
| `db_vuln_fix.sh` | 856 | D-* 조치 계층 존재, MX fallback 호환 유지 |

### 기 완료된 항목

- **OS 감지**: `check_os_environment()`가 Rocky 8.10 / 9.x 모두 허용
- **Capability profile**: systemctl, authselect, faillock, firewall, package manager 등 감지 후 결과 파일 헤더 기록
- **U-01~U-67 점검 계층**: 전항목 실행 루프 존재
- **D-01~D-25 중 12개**: D-01, D-02, D-03, D-04, D-06, D-07, D-08, D-10, D-11, D-14, D-21, D-25
- **CLI contract**: `--dry-run`, `--output`, `--quiet`, `--no-color`, `--version` 표준화
- **Result contract**: `[U-xx]`/`[D-xx]` + `Status:` + `Detail:` + `Risk:` 형식 고정
- **Fixture 기준선**: `tests/fixtures/results/` 4개 파일 존재 (Rocky 9.4 기준)
- **Release CI**: tag push 시 버전 자동 업데이트 + 릴리즈 패키지 생성

### 핵심 미완성 항목

1. **Rocky 8.10 실제 동작 미검증**: OS 감지만 허용, 실제 점검 로직이 8.10 환경에서 올바르게 분기되지 않음
2. **레거시 매핑 50개 항목**: `latest_run_legacy_check` 위임 상태 — 항목별 의미 불일치 가능
3. **점검 로직 보강 미완**: `docs/26-05-28_list.md`에 정리된 9개 보강 항목 미반영
4. **DB 항목 미완**: D-05, D-09, D-12, D-13, D-15~D-20, D-22~D-24 미구현 (최신 가이드 범위 확인 필요)
5. **스크립트 헤더 불일치**: 주석에 "RHEL/Rocky Linux 9" 표기 잔존
6. **수동 조치 가이드 구버전**: `linux_manual_fix_guide.md`(구 U 번호), `mysql_manual_fix_guide.md`(MX-* 체계) 미갱신
7. **Rocky 8.10 fixture 없음**: 테스트가 Rocky 9.4 기준만 존재
8. **Shellcheck/lint CI 없음**: PR 시 쉘 품질 자동 검증 없음
9. **CHANGELOG URL placeholder**: `yourusername/linux-vuln-autofix` 미교체

---

## 2. 목표 (To-Be)

단일 점검 스크립트(`linux_vuln_check.sh`, `db_vuln_check.sh`)와 단일 자동조치 스크립트(`linux_vuln_fix.sh`, `db_vuln_fix.sh`)가 아래 조건을 모두 만족한다.

```
Rocky Linux 8.10 ──┐
                    ├──▶  linux_vuln_check.sh  ──▶  result.txt
Rocky Linux 9.x  ──┘          │
                               │ (result.txt 참조)
                               ▼
                        linux_vuln_fix.sh  ──▶  fix_result.txt

MySQL / MariaDB  ──▶  db_vuln_check.sh    ──▶  mysql_result.txt
                             │
                             ▼
                      db_vuln_fix.sh      ──▶  mysql_fix_result.txt
```

---

## 3. 기술 스택 및 제약

- **언어**: Bash (POSIX 호환 기준, `#!/bin/bash`)
- **대상 OS**: Rocky Linux 8.10, Rocky Linux 9.x (RHEL 호환 허용)
- **대상 DB**: MySQL 8.x, MariaDB 10.x/11.x
- **배포 단위**: 단일 파일 스크립트 4개 (의존 파일 없음)
- **권한**: Linux 점검/조치는 root 필요, DB 점검/조치는 DB 접근 권한 계정 필요
- **외부 의존**: `mysql`, `dnf`/`rpm`, `systemctl`, `ss`/`netstat` — 모두 대상 OS 기본 제공
- **기준 문서**: KISA 2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드

---

## 4. CLI Contract (유지 기준)

기존 `docs/script_contract.md` 기준을 유지한다. 변경 없이 하위 호환.

```bash
# Linux 점검
sudo ./linux_vuln_check.sh [--output FILE] [--quiet] [--no-color]

# Linux 자동조치
sudo ./linux_vuln_fix.sh [-f result.txt] [--dry-run] [--output FILE]

# DB 점검
./db_vuln_check.sh -u root -p PASSWORD [--output FILE]

# DB 자동조치
./db_vuln_fix.sh -u root -p PASSWORD [-f mysql_result.txt] [--dry-run]
```

Result file contract (`[U-xx]`/`[D-xx]` + `Status:` + `Detail:` + `Risk:`) **변경 불가**.

---

## 5. 개선 항목 상세 (Gap Analysis)

### 5.1 Rocky 8.10 / 9.x 공통화 [Linux]

#### GAP-L1: 점검 함수의 OS 분기 부재

**현재**: capability profile은 감지되지만 실제 점검 함수가 `CAP_*` 값을 사용하지 않고 하드코딩된 경로/명령을 사용함.

**필요**: 아래 차이점에 대해 `CAP_*` 변수 기반 분기 적용.

| 항목 | Rocky 8.10 | Rocky 9.x |
|---|---|---|
| PAM faillock 설정 위치 | `/etc/pam.d/` 직접 또는 `/etc/security/faillock.conf` | `/etc/security/faillock.conf` (authselect 기반) |
| authselect profile 적용 | 선택적 | 기본 적용 |
| crypto-policies 경로 | `/etc/crypto-policies/` (존재 가능) | `/etc/crypto-policies/` |
| password hash 정책 | `libuser.conf` + `login.defs` | `login.defs` + `authselect` |
| 시간 동기화 | `chronyd` 또는 `ntpd` 혼재 가능 | `chronyd` 기본 |
| firewall backend | `firewalld` + `iptables` 혼재 | `firewalld` + `nftables` |

**영향 항목**: U-02, U-03, U-13, U-65

#### GAP-L2: 레거시 매핑 항목 정확도

**현재**: U-01, U-04~U-11, U-14~U-36, U-38~U-50, U-54~U-57, U-62, U-66 등 50개 이상이 레거시 함수 위임.

**필요**: 아래 우선순위 항목을 Rocky 8.10/9.x 실제 경로/명령 기준으로 직접 점검으로 전환.

| 우선순위 | 항목 | 이유 |
|---|---|---|
| HIGH | U-01 | SSH PermitRootLogin 직접 파싱으로 전환 필요 |
| HIGH | U-04 | /etc/shadow permission 직접 확인 |
| HIGH | U-14 | root PATH 분기 (Rocky 8/9 PATH 환경 차이) |
| MEDIUM | U-23 | SUID/SGID 목록이 Rocky 8/9 기본 패키지 차이 반영 필요 |
| MEDIUM | U-30 | UMASK login.defs/profile.d 경로 |
| MEDIUM | U-62 | /etc/issue, /etc/motd 경로 Rocky 9에서 변경됨 |

#### GAP-L3: 점검 로직 보강 (docs/26-05-28_list.md 미반영)

| 항목 | 현재 | 필요 |
|---|---|---|
| U-03 faillock deny | `deny == 5`로 고정 판정 가능성 | `deny <= 5`이면 PASS |
| U-02 minlen | `>= 8` 기준 | `>= 9` (KISA 기준), 대문자/소문자/숫자/특수문자 요건 추가 |
| U-02 PASS_MAX_DAYS | 현재 부분 점검 | `<= 90`, `PASS_MIN_DAYS >= 1` 추가 |
| U-12 TMOUT | TMOUT 값 존재 여부 | `<= 900`, `readonly TMOUT`, `export TMOUT` 확인 |
| U-37 cron 범위 | `/etc/crontab` 중심 | `cron.allow`, `cron.deny`, `cron.d/*`, `/var/spool/cron`, `/usr/bin/crontab` 추가 |
| U-60 SNMP | `community` 키워드 중심 | `rocommunity`, `rwcommunity`, `com2sec` 실제 문법 기준 |
| U-63 sudoers | NOPASSWD 점검 부분 | `/etc/sudoers.d/*` 전체 + NOPASSWD 허용 계정 목록 |
| U-28 (신규) | 미구현 | `net.ipv4.ip_forward=0` 런타임 + 영구 설정 점검 |
| U-28 (신규) | 미구현 | `net.ipv4.tcp_syncookies=1` 런타임 + 영구 설정 |
| U-33 .netrc | 미구현 | 홈 디렉토리 전체 `.netrc` 파일 존재 여부 |

### 5.2 MySQL/MariaDB 점검 최신화 [DB]

#### GAP-D1: 미구현 D-* 항목 확인

현재 `db_vuln_check.sh`에는 D-01~D-04, D-06~D-08, D-10~D-11, D-14, D-21, D-25 총 12개가 구현됨.  
최신 가이드에서 D-05, D-09, D-12, D-13, D-15~D-20, D-22~D-24 해당 여부 확인 후 구현 또는 N/A 처리 결정 필요.

| 코드 | 확인 필요 내용 |
|---|---|
| D-05 | 최신 가이드 내용 확인 (현재 매핑 가이드에 없음) |
| D-09, D-12~D-13 | 최신 가이드 내용 확인 |
| D-15~D-20, D-22~D-24 | 최신 가이드 내용 확인 |

#### GAP-D2: MariaDB 버전별 분기

**현재**: MySQL/MariaDB 동일 쿼리 사용.  
**필요**: MariaDB 10.x vs 11.x vs MySQL 8.x에서 일부 시스템 뷰/변수명 차이 반영.

| 차이점 | MySQL 8.x | MariaDB 10.x/11.x |
|---|---|---|
| 암호화 플러그인 | `caching_sha2_password` | `ed25519`, `mysql_native_password` |
| `validate_password` | 기본 활성화 | `validate_password` 플러그인 별도 설치 |
| `information_schema.PLUGINS` | 표준 | 동일 (호환) |

#### GAP-D3: DB 점검 결과 → 조치 파싱 정확도

**현재**: `db_vuln_fix.sh`에 MX-* fallback 호환 코드 잔존.  
**필요**: D-* 체계로 완전 전환, MX-* fallback 제거 또는 명시적 deprecation 표기.

### 5.3 코드 품질 및 운영 안전성

#### GAP-Q1: 스크립트 헤더 불일치

```bash
# 현재 (수정 필요)
# RHEL/Rocky Linux 9 보안 취약점 점검 스크립트  ← linux_vuln_check.sh:3
# RHEL/Rocky Linux 9 보안 취약점 자동 조치 스크립트  ← linux_vuln_fix.sh:3

# 목표
# Rocky Linux 8.10/9.x 보안 취약점 점검 스크립트
# Rocky Linux 8.10/9.x 보안 취약점 자동 조치 스크립트
```

#### GAP-Q2: Shellcheck CI 없음

PR/Push 시 `shellcheck` + `bash -n` 자동 실행이 없어 품질 회귀 탐지 불가.

#### GAP-Q3: Rocky 8.10 Fixture 없음

현재 `tests/fixtures/results/linux_check.fixture`는 Rocky 9.4 기준.  
Rocky 8.10 환경의 capability profile과 점검 결과 fixture가 없어 회귀 테스트 불가.

### 5.4 문서 최신화

| 문서 | 현재 | 필요 |
|---|---|---|
| `linux_manual_fix_guide.md` | 구 U 번호 기반, v26.03.01 기준 | U-01~U-67 기준 목차 갱신 |
| `mysql_manual_fix_guide.md` | MX-* 체계 (MX-03, MX-04 ...) | D-* 체계로 전면 갱신 |
| `CHANGELOG.md` | `yourusername` placeholder URL | 실제 저장소 URL로 교체 |
| `README.md` | "RHEL/Rocky Linux 9" 잔존 가능 | Rocky Linux 8.10/9.x 명시 |

---

## 6. 구현 계획 (Phase별)

### Phase 1: 헤더/주석/문서 정합성 정리 (빠른 승리)

**목적**: 잘못된 표기를 제거해 혼선 방지.

- [ ] `linux_vuln_check.sh` 헤더 주석 "RHEL/Rocky Linux 9" → "Rocky Linux 8.10/9.x"
- [ ] `linux_vuln_fix.sh` 헤더 주석 동일 수정
- [ ] `CHANGELOG.md` placeholder URL 수정
- [ ] `README.md` 지원 OS 표기 검토/수정

완료 기준:
```bash
grep -n "RHEL/Rocky Linux 9" linux_vuln_check.sh linux_vuln_fix.sh  # 결과 없음
grep "yourusername" CHANGELOG.md  # 결과 없음
```

### Phase 2: 점검 로직 보강 (GAP-L3)

**목적**: 현재 점검 기준의 오탐/미탐 보정.

우선순위 순으로 구현:

1. **U-03** `deny <= 5` 기준 수정 (현재 `== 5` 가능성)
2. **U-02** `minlen >= 9`, `PASS_MAX_DAYS <= 90`, `PASS_MIN_DAYS >= 1`, 문자 종류 복잡도
3. **U-12** `TMOUT <= 900`, `readonly`/`export` 확인, `/etc/profile.d/*.sh` 스캔
4. **U-37** cron 점검 범위 확장
5. **U-60** SNMP `rocommunity`/`rwcommunity`/`com2sec` 문법 추가
6. **U-63** `/etc/sudoers.d/*` 전체 스캔 + NOPASSWD 계정 목록화
7. **U-33** `.netrc` 파일 홈 디렉토리 전체 스캔 추가
8. **IP forwarding / TCP SYN cookies** 점검 추가 (U-28 범위 또는 신규 서브 점검)

각 항목 완료 기준: `bash -n linux_vuln_check.sh` 통과 + Rocky 9.4 fixture 재검증.

### Phase 3: Rocky 8.10 OS 분기 구현 (GAP-L1)

**목적**: capability profile 기반으로 8.10 / 9.x 실제 동작 분기.

1. U-02 pwquality: `CAP_AUTHSELECT` 분기로 Rocky 8 PAM 경로 처리
2. U-03 faillock: `CAP_FAILLOCK_CONF` 경로 기반 분기 (직접 conf vs pam.d inline)
3. U-13 hash algorithm: `CAP_CRYPTO_POLICIES` 유무 기반 분기
4. U-65 NTP: `CAP_TIME_SYNC` 값 기반 분기 (chronyd/ntpd)

Rocky 8.10 fixture 생성:
```
tests/fixtures/results/linux_check_rocky8.fixture
tests/fixtures/results/linux_fix_rocky8.fixture
```

완료 기준: Rocky 8.10 fixture에서 위 항목이 PASS/FAIL/N/A 올바른 판정 생성.

### Phase 4: DB 항목 최신화 (GAP-D1, D2, D3)

1. KISA 최신 가이드에서 D-05, D-09, D-12~D-24 해당 항목 확인
2. 해당 항목 구현 또는 명시적 N/A 처리
3. MariaDB 암호화 플러그인 분기 추가 (D-08)
4. MX-* fallback 코드 제거 또는 `# deprecated:` 주석 추가

완료 기준: `db_vuln_check.sh --version` + `bash -n` 통과, MX-* 잔존 여부 확인.

### Phase 5: 수동 조치 가이드 최신화 (GAP 5.4)

1. `linux_manual_fix_guide.md` — U-01~U-67 기준 목차 재작성
2. `mysql_manual_fix_guide.md` — D-* 체계로 전면 갱신

완료 기준: 목차의 항목 코드가 `D-xx` / `U-xx` 형식으로만 구성됨.

### Phase 6: CI 품질 게이트 추가 (GAP-Q2)

`.github/workflows/` 에 `lint.yml` 추가:

```yaml
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get install -y shellcheck
      - run: bash -n linux_vuln_check.sh linux_vuln_fix.sh db_vuln_check.sh db_vuln_fix.sh
      - run: shellcheck -S warning linux_vuln_check.sh linux_vuln_fix.sh db_vuln_check.sh db_vuln_fix.sh
```

완료 기준: PR 시 lint job 자동 실행, 주요 SC2xxx 경고 0개.

---

## 7. 성공 기준 (Success Criteria)

### 기능

- [ ] Rocky Linux 8.10에서 `linux_vuln_check.sh`가 U-01~U-67 전항목 실행 완료 (exit 0)
- [ ] Rocky Linux 9.x에서 `linux_vuln_check.sh`가 U-01~U-67 전항목 실행 완료 (exit 0)
- [ ] `linux_vuln_fix.sh --dry-run` 이 Rocky 8.10/9.x 양쪽에서 시스템 변경 없이 완료
- [ ] `db_vuln_check.sh`가 MySQL 8.x / MariaDB 10.x / 11.x에서 D-* 전항목 실행 완료
- [ ] 결과 파일 포맷이 기존 파서(`grep -A 2`)와 호환

### 정확도

- [ ] U-03 `deny <= 5`이면 PASS, `> 5`이면 FAIL
- [ ] U-02 `minlen >= 9`이면 PASS, `< 9`이면 FAIL
- [ ] U-12 `TMOUT <= 900` + `readonly` + `export` 모두 확인
- [ ] U-60 `rocommunity public` 패턴 FAIL 판정
- [ ] U-63 `NOPASSWD` 포함 sudoers 항목 FAIL 판정

### 안전성

- [ ] `--dry-run`에서 파일/서비스/DB 변경 없음 (확인: `strace` 또는 `auditd`)
- [ ] 모든 파일 변경 전 `/var/backup/security_fix_*/` 백업 수행
- [ ] SSH, firewall, service stop 조치는 `MANUAL` 또는 confirm 처리

### 품질

- [ ] `bash -n *.sh` 4개 모두 통과
- [ ] `shellcheck -S warning *.sh` 주요 경고 0개
- [ ] 스크립트 헤더에 "RHEL/Rocky Linux 9" 표기 없음
- [ ] `CHANGELOG.md`에 `yourusername` 없음

### 문서

- [ ] `linux_manual_fix_guide.md` 목차가 U-01~U-67 기준
- [ ] `mysql_manual_fix_guide.md` 목차가 D-* 기준
- [ ] `README.md` 지원 OS가 "Rocky Linux 8.10 및 9.x"로 명시

---

## 8. Boundaries

### Always do
- 결과 파일 포맷(`[U-xx]`, `Status:`, `Detail:`, `Risk:`) 유지
- CLI 옵션 하위 호환 유지
- 조치 전 백업 수행
- `bash -n` 통과 확인 후 커밋

### Ask first
- 새로운 CLI 옵션 추가
- 점검 항목 코드 번호 변경 (U-xx → 다른 번호)
- 기존 자동 조치를 `MANUAL`로 강등 또는 반대
- Rocky 8.9 이하 지원 확장

### Never do
- `dry-run`에서 실제 파일/서비스/DB 변경
- `--no-verify`, `--force` 없이 push 또는 배포
- 결과 파일의 `Status:` / `Detail:` 라인 제거 또는 이름 변경
- root 패스워드, DB 패스워드를 파일/로그에 평문 기록

---

## 9. Open Questions

1. **D-05, D-09, D-12~D-24**: 최신 KISA 가이드 PDF에서 해당 코드 항목 존재 여부 확인 필요. 없으면 N/A, 있으면 구현.
2. **IP forwarding / TCP SYN cookies**: 기존 U-28 범위로 합칠지 별도 서브 점검으로 분리할지 결정 필요.
3. **레거시 매핑 50개 항목 직접 전환 범위**: Phase 2에서 9개 우선 항목 외 나머지를 이번 개선 범위에 포함할지 후속 과제로 분리할지.
4. **CHANGELOG URL**: 실제 GitHub 저장소 URL 확인 필요 (현재 `yourusername` placeholder).
5. **Rocky 8.10 테스트 환경**: VM 또는 컨테이너 기반 실제 실행 테스트 가능 여부.
