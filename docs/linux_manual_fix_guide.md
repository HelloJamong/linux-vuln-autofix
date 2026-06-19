# Linux 보안 취약점 수동 조치 가이드

본 문서는 자동 조치가 불가능하거나 위험성이 높아 수동 조치가 필요한 Linux 보안 취약점 항목들에 대한 상세 가이드입니다.

---

## 목차

- [U-05: Root UID(0) 계정 중복 제거](#u-05-root-uid0-계정-중복-제거)
- [U-15: 파일 및 디렉토리 소유자 설정](#u-15-파일-및-디렉토리-소유자-설정)
- [U-23: SUID/SGID 파일 점검](#u-23-suidsgid-파일-점검)
- [U-25: World Writable 파일 점검](#u-25-world-writable-파일-점검)
- [U-28: 접속 IP 및 포트 제한](#u-28-네트워크-접근-제어)
- [U-40: NFS 접근 통제](#u-40-nfs-접근-제어)
- [U-66: 보안 패치 관리](#u-66-보안-패치-관리)
- [U-07: 불필요한 계정 제거](#u-07-불필요한-계정-제거)
- [U-08: 관리자 그룹 최소화](#u-08-관리자-그룹-최소화)
- [U-09: 계정이 존재하지 않는 GID 금지](#u-09-계정이-존재하지-않는-gid-금지)
- [U-10: 동일한 UID 금지](#u-10-동일한-uid-금지)
- [U-11: 사용자 Shell 점검](#u-11-사용자-shell-점검)
- [U-53: FTP 서비스 정보 노출 제한](#u-53-ftp-서비스-정보-노출-제한)
- [U-56: FTP 서비스 접근 제어 설정](#u-56-ftp-서비스-접근-제어-설정)

---

## U-05: Root UID(0) 계정 중복 제거

### 취약점 설명
UID가 0인 계정은 시스템에서 최고 권한을 가집니다. root 외에 UID 0을 가진 계정이 존재하면 보안상 위험합니다.

**위험도**: HIGH (상)

### 점검 방법
```bash
# UID 0인 계정 확인 (root 제외)
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd
```

### 조치 방법

#### 방법 1: 계정 삭제 (권장)
불필요한 UID 0 계정은 삭제합니다.
```bash
# 계정 삭제 (홈 디렉토리도 함께 삭제)
userdel -r <계정명>

# 계정 삭제 (홈 디렉토리 유지)
userdel <계정명>
```

#### 방법 2: UID 변경
필요한 계정이라면 UID를 변경합니다.
```bash
# UID 변경 (예: 1001로 변경)
usermod -u 1001 <계정명>

# 해당 계정 소유의 파일들도 UID 변경
find / -user <이전_UID> -exec chown <새_UID> {} \;
```

### 주의사항
- **반드시 백업 후 작업하세요.**
- 계정 삭제 전 해당 계정이 실행 중인 프로세스가 있는지 확인하세요.
- 계정 삭제 시 cron job, 서비스 등에 영향이 없는지 확인하세요.
- UID 변경 시 파일 소유권도 함께 변경해야 합니다.

### 검증
```bash
# 변경 후 확인
awk -F: '$3 == 0 {print $1}' /etc/passwd
# 결과: root만 출력되어야 함
```

---

## U-15: 파일 및 디렉토리 소유자 설정

### 취약점 설명
소유자나 그룹이 존재하지 않는 파일은 삭제된 계정의 파일이거나 잘못된 설정으로 인한 것입니다. 이러한 파일은 보안 위험이 될 수 있습니다.

**위험도**: MEDIUM (중)

### 점검 방법
```bash
# 소유자가 없는 파일 찾기
find / -xdev -nouser -print 2>/dev/null

# 그룹이 없는 파일 찾기
find / -xdev -nogroup -print 2>/dev/null

# 둘 다 찾기
find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null
```

### 조치 방법

#### 단계별 조치
1. **파일 검토**: 각 파일이 무엇인지, 왜 소유자가 없는지 확인
2. **필요성 판단**: 불필요한 파일은 삭제, 필요한 파일은 소유자 지정
3. **소유자 변경**: 적절한 소유자로 변경

```bash
# 파일 상세 정보 확인
ls -l <파일경로>

# 불필요한 파일 삭제
rm -f <파일경로>

# 소유자 변경 (파일이 필요한 경우)
chown root:root <파일경로>

# 또는 적절한 사용자:그룹으로 변경
chown <사용자>:<그룹> <파일경로>

# 디렉토리와 하위 파일 모두 변경
chown -R <사용자>:<그룹> <디렉토리경로>
```

### 주의사항
- **무분별한 root 소유권 부여는 위험합니다.**
- 각 파일의 용도를 파악한 후 적절한 소유자를 지정하세요.
- 시스템 파일이나 애플리케이션 파일의 경우 원래 소유자를 확인하세요.
- 변경 전 백업을 수행하세요.

### 예시
```bash
# 예: 삭제된 사용자(UID: 1005)의 파일 발견
ls -ln /home/olduser/data.txt
# -rw-r--r-- 1 1005 1005 1234 Nov 27 14:30 /home/olduser/data.txt

# 조치: 적절한 사용자로 소유권 변경
chown newuser:newuser /home/olduser/data.txt
```

---

## U-23: SUID/SGID 파일 점검

### 취약점 설명
SUID(Set User ID), SGID(Set Group ID) 비트가 설정된 파일은 실행 시 파일 소유자나 그룹의 권한으로 실행됩니다. 불필요하거나 악의적인 SUID/SGID 파일은 권한 상승 공격에 악용될 수 있습니다.

**위험도**: HIGH (상)

### 점검 방법
```bash
# SUID 파일 찾기 (4000)
find / -xdev -type f -perm -4000 -print 2>/dev/null

# SGID 파일 찾기 (2000)
find / -xdev -type f -perm -2000 -print 2>/dev/null

# SUID 또는 SGID 파일 모두 찾기
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
```

### 조치 방법

#### 1단계: 정상 SUID/SGID 파일 목록 확인
일반적으로 필요한 SUID 파일:
- `/usr/bin/passwd`
- `/usr/bin/su`
- `/usr/bin/sudo`
- `/usr/bin/mount`
- `/usr/bin/umount`
- `/usr/bin/ping`
- `/usr/sbin/unix_chkpwd`

#### 2단계: 불필요한 SUID/SGID 제거
```bash
# SUID 비트 제거
chmod u-s <파일경로>

# SGID 비트 제거
chmod g-s <파일경로>

# 둘 다 제거
chmod ug-s <파일경로>

# 또는 숫자 모드로 (예: 755)
chmod 755 <파일경로>
```

#### 3단계: 검토가 필요한 파일
```bash
# 각 파일의 용도 확인
rpm -qf <파일경로>  # 어느 패키지에 속하는지 확인
ls -l <파일경로>     # 권한 및 소유자 확인
```

### 주의사항
- **시스템 필수 파일의 SUID 제거 시 시스템이 작동하지 않을 수 있습니다.**
- passwd, su, sudo 등의 SUID는 정상적인 것입니다.
- 제거 전 해당 파일이 무엇인지 반드시 확인하세요.
- 테스트 환경에서 먼저 검증하세요.

### 예시
```bash
# 예: /tmp/suspicious 파일에 SUID 설정됨
ls -l /tmp/suspicious
# -rwsr-xr-x 1 root root 12345 Nov 27 14:30 /tmp/suspicious

# 조치 1: 파일 검토
file /tmp/suspicious
rpm -qf /tmp/suspicious  # 패키지에 속하지 않으면 의심

# 조치 2: SUID 제거 또는 파일 삭제
chmod u-s /tmp/suspicious
# 또는
rm -f /tmp/suspicious
```

---

## U-25: World Writable 파일 점검

### 취약점 설명
모든 사용자가 쓰기 가능한(world writable) 파일은 악의적인 사용자가 파일을 변조할 수 있어 보안 위험이 됩니다.

**위험도**: MEDIUM (중)

### 점검 방법
```bash
# World writable 파일 찾기 (sticky bit 제외)
find / -xdev -type f -perm -0002 ! -perm -1000 -print 2>/dev/null

# World writable 디렉토리 찾기
find / -xdev -type d -perm -0002 -print 2>/dev/null
```

### 조치 방법

#### 파일 권한 변경
```bash
# Others 쓰기 권한 제거
chmod o-w <파일경로>

# 또는 명시적으로 권한 설정 (예: 644)
chmod 644 <파일경로>

# 디렉토리의 경우 (예: 755)
chmod 755 <디렉토리경로>
```

#### Sticky Bit 설정 (디렉토리)
공유 디렉토리(예: /tmp)는 sticky bit를 설정하여 소유자만 삭제 가능하도록 합니다.
```bash
# Sticky bit 설정
chmod +t <디렉토리경로>

# 또는 숫자 모드로 (1755)
chmod 1755 <디렉토리경로>
```

### 주의사항
- **/tmp, /var/tmp 등은 world writable이 정상입니다** (sticky bit 있음)
- 애플리케이션 로그 디렉토리나 공유 디렉토리는 용도를 확인 후 조치하세요.
- 권한 변경 시 애플리케이션 동작에 영향이 없는지 확인하세요.

### 예시
```bash
# 예: /var/log/app/debug.log 파일이 world writable
ls -l /var/log/app/debug.log
# -rw-rw-rw- 1 app app 12345 Nov 27 14:30 /var/log/app/debug.log

# 조치: 적절한 권한으로 변경
chmod 640 /var/log/app/debug.log
# -rw-r----- 1 app app 12345 Nov 27 14:30 /var/log/app/debug.log
```

### 정상적인 World Writable 디렉토리
```bash
# /tmp, /var/tmp는 sticky bit가 있어야 함
ls -ld /tmp
# drwxrwxrwt 10 root root 4096 Nov 27 14:30 /tmp
# 마지막 't'가 sticky bit
```

---

## U-28: 접속 IP 및 포트 제한

### 취약점 설명
방화벽 설정이 없거나 부적절하면 불필요한 네트워크 포트가 노출되어 공격에 취약해집니다.

**위험도**: HIGH (상)

### 점검 방법
```bash
# 방화벽 상태 확인
systemctl status firewalld

# 현재 방화벽 규칙 확인
firewall-cmd --list-all

# 또는 iptables 사용 시
iptables -L -n -v
```

### 조치 방법

#### firewalld 사용 (RHEL/Rocky Linux 9 기본)

##### 1단계: 방화벽 활성화
```bash
# 방화벽 시작
systemctl start firewalld

# 부팅 시 자동 시작
systemctl enable firewalld

# 상태 확인
systemctl status firewalld
```

##### 2단계: 기본 정책 설정
```bash
# 기본 zone 확인
firewall-cmd --get-default-zone

# public zone을 기본으로 설정
firewall-cmd --set-default-zone=public

# 기본 정책: 들어오는 연결 거부, 나가는 연결 허용
```

##### 3단계: 필요한 서비스만 허용
```bash
# SSH 허용 (필수)
firewall-cmd --permanent --add-service=ssh

# HTTP/HTTPS 허용 (웹 서버인 경우)
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# 특정 포트 허용
firewall-cmd --permanent --add-port=8080/tcp

# 특정 IP에서만 접근 허용
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.100" accept'

# 설정 적용
firewall-cmd --reload
```

##### 4단계: 불필요한 서비스 제거
```bash
# 현재 허용된 서비스 확인
firewall-cmd --list-services

# 불필요한 서비스 제거
firewall-cmd --permanent --remove-service=<서비스명>

# 설정 적용
firewall-cmd --reload
```

#### 고급 설정 예시

##### SSH 포트 제한 (특정 IP만 허용)
```bash
# 기존 SSH 서비스 제거
firewall-cmd --permanent --remove-service=ssh

# 특정 IP 대역에서만 SSH 허용
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="22" protocol="tcp" accept'

# 설정 적용
firewall-cmd --reload
```

##### 포트 포워딩 설정
```bash
# 외부 8080 포트를 내부 80 포트로 포워딩
firewall-cmd --permanent --add-forward-port=port=8080:proto=tcp:toport=80

# 설정 적용
firewall-cmd --reload
```

### 주의사항
- **SSH 포트를 차단하면 원격 접속이 불가능해집니다.**
- 원격 서버에서 작업 시 SSH 규칙은 반드시 확인하세요.
- 설정 변경 후 `firewall-cmd --reload`로 적용해야 합니다.
- `--permanent` 옵션 없이 테스트 후 영구 적용하세요.

### 검증
```bash
# 방화벽 규칙 확인
firewall-cmd --list-all

# 특정 포트가 열려있는지 확인
firewall-cmd --query-port=22/tcp

# 외부에서 포트 스캔 (다른 서버에서)
nmap -p 1-65535 <서버IP>
```

---

## U-40: NFS 접근 통제

### 취약점 설명
NFS(Network File System) 설정이 부적절하면 권한 없는 사용자가 파일 시스템에 접근할 수 있습니다.

**위험도**: HIGH (상)

### 점검 방법
```bash
# NFS 서비스 확인
systemctl status nfs-server

# /etc/exports 파일 확인
cat /etc/exports

# 현재 export된 디렉토리 확인
exportfs -v
```

### 조치 방법

#### 1단계: /etc/exports 파일 검토
```bash
# 백업
cp /etc/exports /etc/exports.backup.$(date +%Y%m%d)

# 파일 편집
vi /etc/exports
```

#### 2단계: 안전한 설정 적용

##### 기본 원칙
- 특정 IP/네트워크만 허용
- read-only 옵션 사용
- no_root_squash 사용 금지
- sync 옵션 사용

##### 설정 예시
```bash
# 나쁜 예 (전체 네트워크에 읽기/쓰기 허용)
/data *(rw,no_root_squash)

# 좋은 예 1 (특정 IP만 허용)
/data 192.168.1.100(ro,sync,no_subtree_check)

# 좋은 예 2 (특정 네트워크만 허용, 읽기 전용)
/data 192.168.1.0/24(ro,sync,no_subtree_check,root_squash)

# 좋은 예 3 (여러 클라이언트 설정)
/data 192.168.1.100(rw,sync,no_subtree_check) 192.168.1.101(ro,sync,no_subtree_check)
```

#### 3단계: 설정 적용
```bash
# exports 파일 다시 읽기
exportfs -ra

# 또는 NFS 서비스 재시작
systemctl restart nfs-server

# 적용 확인
exportfs -v
```

### NFS 옵션 설명

| 옵션 | 설명 |
|------|------|
| `ro` | 읽기 전용 |
| `rw` | 읽기/쓰기 가능 |
| `sync` | 동기 쓰기 (권장) |
| `async` | 비동기 쓰기 (빠르지만 위험) |
| `root_squash` | root를 nobody로 매핑 (권장) |
| `no_root_squash` | root 권한 유지 (위험) |
| `all_squash` | 모든 사용자를 nobody로 매핑 |
| `no_subtree_check` | 서브트리 검사 비활성화 |

### 주의사항
- **no_root_squash는 매우 위험합니다.** 클라이언트의 root가 서버에서도 root 권한을 가집니다.
- 가능하면 ro(읽기 전용)를 사용하세요.
- IP 주소 또는 네트워크 대역을 명시적으로 지정하세요.
- sync 옵션을 사용하여 데이터 무결성을 보장하세요.

### 예시
```bash
# 현재 설정 (위험)
/shared *(rw,no_root_squash,async)

# 개선된 설정
/shared 192.168.1.0/24(rw,sync,root_squash,no_subtree_check)

# 설정 적용
exportfs -ra

# 확인
exportfs -v
# /shared  192.168.1.0/24(rw,sync,wdelay,hide,no_subtree_check,sec=sys,root_squash,no_all_squash)
```

### NFS가 불필요한 경우
```bash
# NFS 서비스 중지
systemctl stop nfs-server

# 부팅 시 자동 시작 비활성화
systemctl disable nfs-server

# /etc/exports 파일 비우기 또는 삭제
> /etc/exports
```

---

## U-66: 보안 패치 관리

### 취약점 설명
보안 패치가 적용되지 않은 시스템은 알려진 취약점에 노출되어 공격당할 수 있습니다.

**위험도**: HIGH (상)

### 점검 방법
```bash
# 사용 가능한 업데이트 확인
dnf check-update

# 보안 업데이트만 확인
dnf check-update --security

# 설치된 패키지 버전 확인
rpm -qa | grep <패키지명>
```

### 조치 방법

#### 1단계: 백업 및 준비
```bash
# 시스템 백업 (중요!)
# - 전체 시스템 백업
# - 또는 중요 데이터만 백업

# 현재 패키지 목록 저장
rpm -qa > /root/packages_before_update_$(date +%Y%m%d).txt

# 디스크 공간 확인
df -h
```

#### 2단계: 보안 패치 적용

##### 방법 1: 보안 패치만 적용 (권장)
```bash
# 보안 패치만 설치
dnf update --security -y

# 또는 특정 패키지만 업데이트
dnf update <패키지명> -y
```

##### 방법 2: 전체 업데이트
```bash
# 모든 패키지 업데이트
dnf update -y

# 또는 대화형 모드
dnf update
```

##### 방법 3: 특정 취약점 패치
```bash
# CVE 번호로 검색
dnf updateinfo list security cves

# 특정 CVE 패치
dnf update --cve=CVE-2024-XXXX -y
```

#### 3단계: 업데이트 후 작업
```bash
# 커널 업데이트 확인
rpm -q kernel

# 재부팅이 필요한지 확인
needs-restarting -r

# 재부팅 (필요 시)
reboot

# 또는 서비스만 재시작
needs-restarting -s
systemctl restart <서비스명>
```

### 자동 업데이트 설정 (선택사항)

#### dnf-automatic 설치 및 설정
```bash
# dnf-automatic 설치
dnf install dnf-automatic -y

# 설정 파일 편집
vi /etc/dnf/automatic.conf
```

설정 예시 (보안 패치 자동 적용):
```ini
[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes

[emitters]
emit_via = email
email_from = root@localhost
email_to = admin@example.com

[email]
email_host = localhost
```

활성화:
```bash
# 타이머 시작
systemctl enable --now dnf-automatic.timer

# 상태 확인
systemctl status dnf-automatic.timer
```

### 주의사항
- **운영 환경에서는 즉시 업데이트하지 마세요.**
- 먼저 테스트 환경에서 검증 후 적용하세요.
- 업데이트 전 반드시 백업하세요.
- 커널 업데이트 후에는 재부팅이 필요합니다.
- 서비스 중단 시간을 고려하여 점검 창을 설정하세요.
- 자동 업데이트 사용 시 테스트가 불가능하므로 신중히 결정하세요.

### 검증
```bash
# 업데이트된 패키지 확인
rpm -qa --last | head -20

# 재부팅 필요 여부 확인
needs-restarting -r

# 특정 취약점 패치 확인
dnf updateinfo info CVE-2024-XXXX
```

### 패치 관리 모범 사례
1. **정기적인 패치 적용**: 월 1회 이상 보안 패치 점검
2. **테스트 후 적용**: 테스트 환경에서 먼저 검증
3. **백업 필수**: 업데이트 전 반드시 백업
4. **롤백 계획**: 문제 발생 시 이전 버전으로 복구 방법 준비
5. **변경 기록**: 업데이트 내역과 영향 기록

---

## U-07: 불필요한 계정 제거

### 취약점 설명
불필요한 계정은 공격자가 악용할 수 있는 진입점이 될 수 있습니다.

**위험도**: LOW (하)

### 점검 방법
```bash
# 전체 사용자 계정 확인
cat /etc/passwd

# 로그인 가능한 계정만 확인
grep -v '/nologin\|/false' /etc/passwd

# 최근 로그인 기록 확인
lastlog

# 장기간 미사용 계정 확인 (90일 이상)
lastlog -b 90
```

### 조치 방법

#### 1단계: 계정 분류
```bash
# 시스템 계정 (UID < 1000, 일반적으로 유지)
awk -F: '$3 < 1000 {print $1}' /etc/passwd

# 사용자 계정 (UID >= 1000)
awk -F: '$3 >= 1000 {print $1}' /etc/passwd
```

#### 2단계: 불필요한 계정 확인
확인이 필요한 계정 예시:
- 퇴사자 계정
- 테스트 계정
- 임시 계정
- 중복 계정

```bash
# 각 계정의 마지막 로그인 확인
lastlog -u <계정명>

# 계정이 실행 중인 프로세스 확인
ps -u <계정명>

# 계정 소유 파일 확인
find / -user <계정명> -ls 2>/dev/null | head -20
```

#### 3단계: 계정 삭제
```bash
# 방법 1: 계정과 홈 디렉토리 모두 삭제
userdel -r <계정명>

# 방법 2: 계정만 삭제 (홈 디렉토리 유지)
userdel <계정명>

# 방법 3: 계정 잠금 (삭제 전 테스트)
usermod -L <계정명>
# 또는
passwd -l <계정명>
```

#### 4단계: 관련 파일 정리
```bash
# 계정 소유 파일 찾기
find / -user <삭제할_UID> -print 2>/dev/null

# 파일 소유자 변경 또는 삭제
chown root:root <파일경로>
# 또는
rm -rf <파일경로>

# cron job 확인 및 제거
crontab -u <계정명> -r
ls -la /var/spool/cron/<계정명>
```

### 보존해야 할 시스템 계정
다음 계정들은 시스템 운영에 필요하므로 삭제하지 마세요:
- root
- bin, daemon, adm, lp
- sync, shutdown, halt
- mail, operator
- nobody
- systemd-*, polkitd, chrony 등

### 주의사항
- **시스템 계정은 삭제하지 마세요.**
- 계정 삭제 전 해당 계정의 파일과 프로세스를 확인하세요.
- 중요한 파일이 있다면 백업 후 삭제하세요.
- 바로 삭제하기보다는 먼저 잠금 후 테스트하세요.
- 그룹 멤버십도 함께 확인하세요.

### 예시
```bash
# 예: testuser 계정 제거 과정

# 1. 계정 정보 확인
id testuser
lastlog -u testuser
ps -u testuser

# 2. 계정이 소유한 파일 확인
find / -user testuser 2>/dev/null

# 3. 먼저 계정 잠금 (테스트)
usermod -L testuser

# 4. 문제 없으면 계정 삭제
userdel -r testuser

# 5. 확인
id testuser  # 계정이 존재하지 않아야 함
```

---

## U-08: 관리자 그룹 최소화

### 취약점 설명
wheel, sudo 등 관리자 그룹에 불필요한 계정이 포함되어 있으면 권한 남용의 위험이 있습니다.

**위험도**: MEDIUM (중)

### 점검 방법
```bash
# wheel 그룹 구성원 확인
grep wheel /etc/group

# 또는
getent group wheel

# sudo 권한이 있는 사용자 확인
grep -v '^#' /etc/sudoers | grep -v '^$'

# /etc/sudoers.d/ 디렉토리 확인
ls -la /etc/sudoers.d/
cat /etc/sudoers.d/*
```

### 조치 방법

#### 1단계: 현재 관리자 계정 파악
```bash
# wheel 그룹 멤버 확인
lid -g wheel
# 또는
getent group wheel | cut -d: -f4

# 각 계정의 필요성 검토
```

#### 2단계: 불필요한 계정 제거
```bash
# wheel 그룹에서 계정 제거
gpasswd -d <계정명> wheel

# 확인
getent group wheel
```

#### 3단계: sudo 권한 검토
```bash
# sudoers 파일 편집 (안전한 편집기 사용)
visudo

# 또는 /etc/sudoers.d/ 파일 편집
visudo -f /etc/sudoers.d/<파일명>
```

sudo 설정 예시:
```bash
# 나쁜 예: 모든 wheel 그룹 멤버에게 무제한 sudo
%wheel  ALL=(ALL)       ALL

# 좋은 예 1: 특정 사용자만 sudo 허용
adminuser  ALL=(ALL)  ALL

# 좋은 예 2: 특정 명령만 허용
backupuser  ALL=(ALL)  NOPASSWD: /usr/bin/rsync, /usr/bin/tar

# 좋은 예 3: 로그 기록
Defaults    log_output
```

### 주의사항
- **자신의 계정을 wheel 그룹에서 제거하지 마세요.** (접근 불가)
- root 계정 접근이 가능한 상태에서 작업하세요.
- visudo를 사용하여 문법 오류를 방지하세요.
- 변경 후 다른 터미널에서 sudo 테스트하세요.

### 검증
```bash
# wheel 그룹 멤버 확인
getent group wheel

# 특정 사용자의 sudo 권한 테스트
su - <계정명>
sudo -l  # 사용 가능한 sudo 명령 확인
```

### 모범 사례
1. **최소 권한 원칙**: 꼭 필요한 계정만 관리자 그룹에 포함
2. **정기 검토**: 분기 1회 이상 관리자 계정 검토
3. **감사 로그**: sudo 사용 기록 모니터링
4. **명령 제한**: 가능하면 특정 명령만 허용

---

## U-09: 계정이 존재하지 않는 GID 금지

### 취약점 설명
/etc/passwd에 존재하지 않는 GID를 참조하는 계정은 시스템 오류나 보안 문제를 일으킬 수 있습니다.

**위험도**: LOW (하)

### 점검 방법
```bash
# /etc/passwd의 모든 GID 추출 및 확인
awk -F: '{print $4}' /etc/passwd | sort -u | while read gid; do
    if ! grep -q "^[^:]*:[^:]*:$gid:" /etc/group; then
        echo "Invalid GID: $gid"
        grep ":$gid:" /etc/passwd
    fi
done
```

### 조치 방법

#### 방법 1: 그룹 생성 (권장)
```bash
# 해당 GID로 그룹 생성
groupadd -g <GID> <그룹명>

# 예시
groupadd -g 1005 oldgroup
```

#### 방법 2: 계정의 GID 변경
```bash
# 계정의 기본 그룹 변경
usermod -g <새로운_GID> <계정명>

# 예시: GID를 users(100)로 변경
usermod -g 100 <계정명>
```

#### 방법 3: 계정 삭제 (불필요한 경우)
```bash
# 계정 삭제
userdel -r <계정명>
```

### 주의사항
- GID 변경 시 파일 소유권도 함께 변경해야 할 수 있습니다.
- 계정이 많은 파일을 소유하고 있는지 먼저 확인하세요.

### 예시
```bash
# 문제 발견: 계정 testuser의 GID 1005가 /etc/group에 없음
grep testuser /etc/passwd
# testuser:x:1001:1005:Test User:/home/testuser:/bin/bash

grep ":1005:" /etc/group
# (결과 없음)

# 조치 1: 그룹 생성
groupadd -g 1005 testgroup

# 확인
grep testuser /etc/passwd
id testuser
```

---

## U-10: 동일한 UID 금지

### 취약점 설명
동일한 UID를 가진 여러 계정이 존재하면 파일 소유권 혼란과 보안 문제가 발생할 수 있습니다.

**위험도**: MEDIUM (중)

### 점검 방법
```bash
# 중복 UID 찾기
awk -F: '{print $3}' /etc/passwd | sort | uniq -d

# 중복 UID를 가진 계정 확인
awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read uid; do
    echo "Duplicate UID: $uid"
    grep ":$uid:" /etc/passwd
done
```

### 조치 방법

#### 1단계: 중복 계정 확인
```bash
# UID가 중복된 계정들 확인
grep ":<중복_UID>:" /etc/passwd

# 각 계정의 사용 현황 확인
lastlog -u <계정명>
ps -u <계정명>
find / -user <중복_UID> 2>/dev/null | head -20
```

#### 2단계: UID 변경 또는 계정 삭제

##### 방법 1: 불필요한 계정 삭제
```bash
userdel -r <불필요한_계정명>
```

##### 방법 2: UID 변경
```bash
# 새로운 사용 가능한 UID 찾기
awk -F: '{print $3}' /etc/passwd | sort -n | tail -1
# 마지막 UID에 1을 더한 값 사용

# UID 변경
usermod -u <새로운_UID> <계정명>

# 해당 계정 소유의 파일 UID 변경
find / -user <이전_UID> -exec chown <새로운_UID> {} \;
```

### 주의사항
- **UID 변경 시 파일 소유권도 반드시 함께 변경하세요.**
- 시스템 계정(UID < 1000)의 UID는 변경하지 마세요.
- UID 변경 전 해당 계정의 프로세스를 종료하세요.
- 변경 전 백업하세요.

### 예시
```bash
# 문제: user1과 user2가 모두 UID 1001을 사용
grep ":1001:" /etc/passwd
# user1:x:1001:1001:User1:/home/user1:/bin/bash
# user2:x:1001:1002:User2:/home/user2:/bin/bash

# 조치: user2의 UID를 1003으로 변경

# 1. 사용 가능한 UID 확인
id 1003  # UID 1003이 사용되지 않는지 확인

# 2. UID 변경
usermod -u 1003 user2

# 3. 파일 소유권 변경
find / -user 1001 -exec chown 1003 {} \;

# 4. 확인
id user1
id user2
```

---

## U-11: 사용자 Shell 점검

### 취약점 설명
부적절한 shell이 설정된 계정은 보안 위험이 될 수 있습니다. 특히 서비스 계정에 로그인 shell이 설정된 경우 문제가 됩니다.

**위험도**: LOW (하)

### 점검 방법
```bash
# 모든 계정의 shell 확인
cat /etc/passwd | cut -d: -f1,7

# 로그인 가능한 shell을 가진 계정 확인
grep -v 'nologin\|false' /etc/passwd

# 유효한 shell 목록 확인
cat /etc/shells
```

### 조치 방법

#### 1단계: 계정 분류
```bash
# 일반 사용자 계정 (로그인 필요)
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1,$7}' /etc/passwd

# 시스템/서비스 계정 (로그인 불필요)
awk -F: '$3 < 1000 {print $1,$7}' /etc/passwd
```

#### 2단계: 부적절한 shell 변경

##### 서비스 계정의 shell을 nologin으로 변경
```bash
# 방법 1: usermod 사용
usermod -s /sbin/nologin <계정명>

# 방법 2: /usr/sbin/nologin (동일)
usermod -s /usr/sbin/nologin <계정명>

# 방법 3: /bin/false
usermod -s /bin/false <계정명>
```

##### 일반 사용자의 shell을 표준 shell로 변경
```bash
# bash로 변경
usermod -s /bin/bash <계정명>

# sh로 변경
usermod -s /bin/sh <계정명>
```

#### 3단계: 유효하지 않은 shell 수정
```bash
# /etc/shells에 없는 shell을 사용하는 계정 찾기
cat /etc/passwd | while IFS=: read user x uid gid gecos home shell; do
    if [ -n "$shell" ] && ! grep -q "^$shell$" /etc/shells; then
        echo "Invalid shell for $user: $shell"
    fi
done

# 적절한 shell로 변경
usermod -s /bin/bash <계정명>
```

### 주의사항
- **자신의 계정 shell을 잘못 변경하면 로그인할 수 없습니다.**
- root로 작업하거나 다른 터미널을 열어두고 작업하세요.
- 서비스 계정에는 /sbin/nologin 또는 /bin/false를 사용하세요.
- 일반 사용자에게는 /bin/bash 또는 /bin/sh를 사용하세요.

### 검증
```bash
# 변경 후 확인
grep <계정명> /etc/passwd

# 로그인 테스트 (일반 사용자의 경우)
su - <계정명>

# nologin 계정 테스트 (로그인 거부되어야 함)
su - <서비스_계정>
# This account is currently not available. (출력되어야 함)
```

### 예시
```bash
# 예: apache 계정이 /bin/bash shell을 사용 (부적절)
grep apache /etc/passwd
# apache:x:48:48:Apache:/usr/share/httpd:/bin/bash

# 조치: nologin으로 변경
usermod -s /sbin/nologin apache

# 확인
grep apache /etc/passwd
# apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
```

### 권장 Shell 설정

| 계정 유형 | 권장 Shell | 예시 |
|-----------|------------|------|
| root | /bin/bash | root |
| 일반 사용자 | /bin/bash | adminuser, devuser |
| 시스템 계정 | /sbin/nologin | bin, daemon, adm |
| 서비스 계정 | /sbin/nologin | apache, nginx, mysql |
| 잠긴 계정 | /bin/false | 또는 /sbin/nologin |

---

## U-53: FTP 서비스 정보 노출 제한

### 취약점 설명
FTP 서버의 배너 메시지에 소프트웨어 종류, 버전 등 서버 정보가 노출되면 공격자가 특정 취약점을 이용할 수 있습니다.

**위험도**: LOW (하)

### 점검 방법
```bash
# vsftpd 사용 시 배너 확인
grep -E "ftpd_banner|banner_file" /etc/vsftpd/vsftpd.conf 2>/dev/null

# ProFTPD 사용 시
grep -i "ServerIdent\|DisplayConnect" /etc/proftpd.conf 2>/dev/null

# FTP 서비스 실행 여부 확인
systemctl is-active vsftpd proftpd 2>/dev/null
```

### 조치 방법

#### FTP 서비스가 없는 경우
```bash
# FTP 서비스 미사용 확인 → N/A 처리 가능
systemctl status vsftpd
```

#### vsftpd 배너 변경
```bash
# /etc/vsftpd/vsftpd.conf 편집
ftpd_banner=FTP Service
# 또는 버전 정보가 없는 메시지로 변경

systemctl restart vsftpd
```

#### ProFTPD 배너 변경
```bash
# /etc/proftpd.conf 편집
ServerIdent off
# 또는
ServerIdent on "FTP Service"

systemctl restart proftpd
```

### 주의사항
- FTP 서비스를 사용하지 않는 경우 N/A로 처리합니다.
- 가능하면 FTP 대신 SFTP(SSH) 또는 FTPS를 사용하세요.

---

## U-56: FTP 서비스 접근 제어 설정

### 취약점 설명
FTP 서비스에 접근 제어가 설정되지 않으면 불특정 다수가 접근할 수 있어 보안 위험이 있습니다.

**위험도**: LOW (하)

### 점검 방법
```bash
# vsftpd 접근 제어 확인
grep -E "userlist_enable|userlist_deny|tcp_wrappers|chroot_local_user" \
    /etc/vsftpd/vsftpd.conf 2>/dev/null

# tcp_wrappers 설정 확인
grep -i ftp /etc/hosts.allow /etc/hosts.deny 2>/dev/null
```

### 조치 방법

#### FTP 서비스가 없는 경우
```bash
# FTP 서비스 미사용 → N/A 처리 가능
systemctl status vsftpd
```

#### vsftpd 접근 제어 설정
```bash
# /etc/vsftpd/vsftpd.conf 에 아래 설정 추가/수정

# 허용 사용자 목록 파일 사용
userlist_enable=YES
userlist_deny=NO          # YES: 목록 계정 차단 / NO: 목록 계정만 허용
userlist_file=/etc/vsftpd/user_list

# 로컬 사용자 chroot 적용
chroot_local_user=YES
allow_writeable_chroot=NO

systemctl restart vsftpd
```

#### 허용 사용자 목록 관리
```bash
# /etc/vsftpd/user_list 에 허용할 계정 추가
echo "ftpuser" >> /etc/vsftpd/user_list
```

### 주의사항
- FTP 서비스를 사용하지 않는 경우 N/A로 처리합니다.
- anonymous FTP는 반드시 비활성화하세요: `anonymous_enable=NO`

---

## U-73: OpenSSL CVE-2025-11187 보안 패치

### 취약점 설명
CVE-2025-11187은 OpenSSL의 중요 보안 취약점입니다. Rocky Linux는 백포트(backport) 정책을 사용하므로, 패키지 버전 번호만으로는 패치 여부를 확인할 수 없습니다. RPM 패키지의 changelog를 통해 CVE 패치 적용 여부를 확인해야 합니다.

**위험도**: HIGH (상)

### 점검 방법
```bash
# 현재 설치된 openssl 버전 확인
rpm -q openssl

# OpenSSL 패키지의 changelog에서 CVE-2025-11187 패치 확인
rpm -q --changelog openssl | grep -i "CVE-2025-11187"

# 사용 가능한 보안 업데이트 확인
yum check-update --security openssl

# 또는 dnf 사용
dnf check-update --security openssl

# 상세한 보안 공지 확인
yum updateinfo list security | grep openssl
```

### 조치 방법

#### 1단계: 백업
```bash
# OpenSSL 설정 백업
sudo cp -a /etc/pki /etc/pki.backup.$(date +%Y%m%d)

# 현재 버전 기록
rpm -q openssl > /root/openssl_version_before_update.txt
```

#### 2단계: 보안 업데이트 적용
```bash
# 보안 업데이트만 적용
sudo yum update --security openssl

# 또는 전체 openssl 업데이트
sudo yum update openssl

# dnf 사용 시
sudo dnf update --security openssl
```

#### 3단계: OpenSSL을 사용하는 서비스 재시작
```bash
# httpd (Apache) 재시작
sudo systemctl restart httpd

# nginx 재시작
sudo systemctl restart nginx

# postfix 재시작
sudo systemctl restart postfix

# sshd 재시작 (주의: 원격 접속 시 새 세션 열어두고 작업)
sudo systemctl restart sshd

# 모든 OpenSSL 관련 서비스 확인
sudo lsof | grep libssl
```

### 주의사항
- **프로덕션 환경에서는 반드시 유지보수 시간에 작업하세요.**
- sshd 재시작 시 기존 SSH 세션은 유지되지만, 새 세션을 먼저 열어두고 작업하세요.
- 웹 서버 재시작 시 잠시 서비스가 중단됩니다.
- 업데이트 후 시스템 재부팅을 권장합니다 (커널 업데이트가 함께 포함될 수 있음).

### 검증
```bash
# 업데이트 후 버전 확인
rpm -q openssl

# CVE 패치 적용 확인
rpm -q --changelog openssl | head -20

# OpenSSL 버전 및 빌드 정보
openssl version -a

# 업데이트 이력 확인
yum history list openssl

# 서비스 정상 동작 확인
sudo systemctl status httpd
sudo systemctl status nginx
sudo systemctl status sshd
```

### 예시
```bash
# 1. 현재 상태 확인
$ rpm -q openssl
openssl-3.0.7-16.el9_2

# 2. CVE 패치 확인 (패치 전 - 출력 없음)
$ rpm -q --changelog openssl | grep -i "CVE-2025-11187"
(출력 없음)

# 3. 보안 업데이트 적용
$ sudo yum update --security openssl
Updated:
  openssl-3.0.7-27.el9_3

# 4. CVE 패치 확인 (패치 후 - 출력 있음)
$ rpm -q --changelog openssl | grep -i "CVE-2025-11187"
- fix CVE-2025-11187 - Security vulnerability

# 5. 서비스 재시작
$ sudo systemctl restart httpd nginx
```

### Rocky Linux 백포트 정책
Rocky Linux는 RHEL과 마찬가지로 **백포트 보안 패치** 정책을 따릅니다:
- 버전 번호는 변경되지 않지만 보안 패치는 적용됨
- 예: `openssl-3.0.7-16` → `openssl-3.0.7-27` (메이저 버전 동일, 릴리스 번호만 증가)
- RPM changelog 또는 `yum updateinfo`로 CVE 패치 여부 확인 필요

---

## U-74: OpenSSL CVE-2025-15467 보안 패치

### 취약점 설명
CVE-2025-15467은 OpenSSL의 또 다른 중요 보안 취약점입니다. U-73과 마찬가지로 Rocky Linux의 백포트 정책으로 인해 패키지 버전만으로는 패치 여부를 확인할 수 없으며, RPM changelog를 통한 확인이 필요합니다.

**위험도**: HIGH (상)

### 점검 방법
```bash
# 현재 설치된 openssl 버전 확인
rpm -q openssl

# OpenSSL 패키지의 changelog에서 CVE-2025-15467 패치 확인
rpm -q --changelog openssl | grep -i "CVE-2025-15467"

# 사용 가능한 보안 업데이트 확인
yum check-update --security openssl

# 상세한 CVE 정보 확인
yum updateinfo info --security openssl
```

### 조치 방법

#### U-73과 동일한 OpenSSL 업데이트로 해결
CVE-2025-11187과 CVE-2025-15467은 동일한 OpenSSL 보안 업데이트에 포함되어 있을 가능성이 높습니다.

```bash
# U-73 조치를 수행하면 U-74도 함께 해결됨
sudo yum update --security openssl

# 두 CVE 모두 패치되었는지 확인
rpm -q --changelog openssl | grep -E "CVE-2025-11187|CVE-2025-15467"
```

#### 개별 확인이 필요한 경우
```bash
# CVE-2025-15467만 별도로 확인
rpm -q --changelog openssl | grep -i "CVE-2025-15467"

# Rocky Linux 보안 공지 확인
# https://errata.rockylinux.org/
```

### 주의사항
- U-73과 동일한 주의사항 적용
- 두 CVE는 보통 동일한 업데이트에 포함됨
- 하나의 보안 업데이트로 여러 CVE가 동시에 패치될 수 있음

### 검증
```bash
# 두 CVE 모두 패치 확인
rpm -q --changelog openssl | head -30 | grep -E "CVE-2025-11187|CVE-2025-15467"

# 또는 더 상세한 확인
for cve in CVE-2025-11187 CVE-2025-15467; do
    echo "Checking $cve..."
    rpm -q --changelog openssl | grep -i "$cve" || echo "$cve: Not found in changelog"
done
```

### 예시
```bash
# 통합 보안 업데이트 시나리오
$ sudo yum update --security openssl
Updated:
  openssl-3.0.7-27.el9_3

# 두 CVE 모두 확인
$ rpm -q --changelog openssl | head -30
* Wed Jan 15 2025 Sahana Prasad <sahana@redhat.com> - 3.0.7-27
- fix CVE-2025-11187 - Security vulnerability
- fix CVE-2025-15467 - Security vulnerability
- Resolves: RHEL-12345, RHEL-12346
```

### 보안 공지 확인 방법
```bash
# Red Hat/Rocky Linux 보안 공지 확인
yum updateinfo list security

# 특정 CVE 정보
yum updateinfo info CVE-2025-15467

# 또는 웹에서 확인
# Rocky Linux: https://errata.rockylinux.org/
# Red Hat: https://access.redhat.com/security/security-updates/
```

---

## 부록: 유용한 명령어 모음

### 계정 관리
```bash
# 모든 사용자 계정 목록
cut -d: -f1 /etc/passwd

# UID >= 1000인 사용자만
awk -F: '$3 >= 1000 {print $1}' /etc/passwd

# 로그인 가능한 계정
grep -v 'nologin\|false' /etc/passwd

# 최근 로그인 기록
lastlog

# 현재 로그인 사용자
who
w
```

### 파일 및 디렉토리 검색
```bash
# 특정 권한 파일 찾기
find / -perm 777 2>/dev/null

# 특정 소유자 파일 찾기
find / -user <계정명> 2>/dev/null

# 최근 수정된 파일
find / -mtime -7 2>/dev/null

# 크기가 큰 파일
find / -size +100M 2>/dev/null
```

### 시스템 정보
```bash
# OS 버전
cat /etc/redhat-release

# 커널 버전
uname -r

# 설치된 패키지
rpm -qa

# 실행 중인 서비스
systemctl list-units --type=service --state=running
```

### 로그 확인
```bash
# 인증 로그
tail -f /var/log/secure

# 시스템 로그
tail -f /var/log/messages

# 특정 사용자 로그인 실패
grep "Failed password" /var/log/secure | grep <사용자명>
```

---

## 참고 자료

- [KISA 주요정보통신기반시설 취약점 분석·평가 가이드](https://www.kisa.or.kr/2060204/form?postSeq=12&lang_type=KO&page=1)
- [CIS Red Hat Enterprise Linux 9 Benchmark](https://www.cisecurity.org/)
- RHEL 9 Security Guide

---

**문서 버전**: 1.0
**최종 수정일**: 2024-11-27
**작성자**: linux-vuln-autofix
