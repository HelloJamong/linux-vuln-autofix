# MySQL/MariaDB 보안 취약점 수동 조치 가이드

본 문서는 자동 조치가 불가능하거나 신중한 검토가 필요한 MySQL/MariaDB 보안 취약점 항목들에 대한 상세 가이드입니다.

---

## 목차

- [MX-03: 불필요한 기본 계정 제거](#mx-03-불필요한-기본-계정-제거)
- [MX-04: 패스워드 없는 계정 제거](#mx-04-패스워드-없는-계정-제거)
- [MX-06: 계정 권한 최소화](#mx-06-계정-권한-최소화)
- [MX-07: 불필요한 SUPER 권한 제거](#mx-07-불필요한-super-권한-제거)
- [MX-09: FILE 권한 제한](#mx-09-file-권한-제한)
- [MX-10: secure_file_priv 설정](#mx-10-secure_file_priv-설정)
- [MX-11: 에러 로그 활성화](#mx-11-에러-로그-활성화)
- [MX-14: MySQL/MariaDB 버전 업데이트](#mx-14-mysqlmariadb-버전-업데이트)
- [MX-16: 네트워크 바인딩 설정](#mx-16-네트워크-바인딩-설정)

---

## 접속 준비

모든 작업은 MySQL/MariaDB에 접속하여 수행합니다.

```bash
# MySQL/MariaDB 접속
mysql -u root -p

# 또는 원격 서버
mysql -h <호스트> -u root -p

# 또는 소켓 파일 지정
mysql -u root -p --socket=/var/lib/mysql/mysql.sock
```

**주의**: 모든 SQL 명령은 MySQL 프롬프트에서 실행합니다.

---

## MX-03: 불필요한 기본 계정 제거

### 취약점 설명
MySQL/MariaDB 설치 시 생성되는 기본 계정 중 불필요한 계정이 남아있으면 보안 위험이 됩니다.

**위험도**: MEDIUM (중)

### 점검 방법
```sql
-- MySQL 프롬프트에서 실행
SELECT user, host FROM mysql.user;

-- 또는 상세 정보
SELECT user, host, authentication_string FROM mysql.user ORDER BY user, host;
```

### 조치 방법

#### 1단계: 현재 계정 목록 확인
```sql
-- 모든 계정 확인
SELECT user, host FROM mysql.user;

-- 익명 계정 확인 (이미 자동 조치됨)
SELECT user, host FROM mysql.user WHERE user = '';

-- 기본 계정 확인
SELECT user, host FROM mysql.user WHERE user IN ('mysql.sys', 'mysql.session', 'mysql.infoschema');
```

#### 2단계: 불필요한 계정 제거

##### 제거하면 안 되는 시스템 계정
- `mysql.sys` (MySQL 8.0+)
- `mysql.session` (MySQL 8.0+)
- `mysql.infoschema` (MySQL 8.0+)
- `root`

##### 검토가 필요한 계정
- 테스트 계정
- 임시 계정
- 퇴사자 계정
- 중복 계정

```sql
-- 불필요한 계정 삭제
DROP USER '<계정명>'@'<호스트>';

-- 예시
DROP USER 'testuser'@'localhost';
DROP USER 'oldadmin'@'%';

-- 여러 계정 동시 삭제
DROP USER 'user1'@'localhost', 'user2'@'%';

-- 권한 테이블 즉시 적용
FLUSH PRIVILEGES;
```

#### 3단계: 계정별 권한 확인 후 삭제
```sql
-- 특정 계정의 권한 확인
SHOW GRANTS FOR '<계정명>'@'<호스트>';

-- 예시
SHOW GRANTS FOR 'appuser'@'localhost';

-- 권한이 불필요하면 삭제
DROP USER 'appuser'@'localhost';
FLUSH PRIVILEGES;
```

### 주의사항
- **root 계정을 삭제하지 마세요.**
- **mysql.sys, mysql.session, mysql.infoschema는 시스템 계정이므로 삭제하지 마세요.**
- 삭제 전 해당 계정을 사용하는 애플리케이션이 있는지 확인하세요.
- 계정 삭제 전 권한을 확인하여 중요한 계정인지 판단하세요.

### 검증
```sql
-- 삭제 후 계정 목록 확인
SELECT user, host FROM mysql.user;

-- 특정 계정이 삭제되었는지 확인
SELECT user, host FROM mysql.user WHERE user = '<삭제한_계정>';
-- 결과: Empty set (정상)
```

### 예시
```sql
-- 문제: 불필요한 테스트 계정 발견
mysql> SELECT user, host FROM mysql.user;
+------------------+-----------+
| user             | host      |
+------------------+-----------+
| root             | localhost |
| testuser         | localhost |
| oldapp           | %         |
| mysql.sys        | localhost |
+------------------+-----------+

-- 조치: testuser와 oldapp 계정 제거
mysql> DROP USER 'testuser'@'localhost';
Query OK, 0 rows affected (0.01 sec)

mysql> DROP USER 'oldapp'@'%';
Query OK, 0 rows affected (0.01 sec)

mysql> FLUSH PRIVILEGES;
Query OK, 0 rows affected (0.00 sec)

-- 검증
mysql> SELECT user, host FROM mysql.user;
+------------------+-----------+
| user             | host      |
+------------------+-----------+
| root             | localhost |
| mysql.sys        | localhost |
+------------------+-----------+
```

---

## MX-04: 패스워드 없는 계정 제거

### 취약점 설명
패스워드가 설정되지 않은 계정은 누구나 접속할 수 있어 매우 위험합니다.

**위험도**: HIGH (상)

### 점검 방법
```sql
-- MySQL 5.7
SELECT user, host FROM mysql.user WHERE password = '' OR password IS NULL;

-- MySQL 8.0+ / MariaDB 10.3+
SELECT user, host FROM mysql.user WHERE authentication_string = '' OR authentication_string IS NULL;

-- 또는 plugin 확인
SELECT user, host, plugin, authentication_string FROM mysql.user;
```

### 조치 방법

#### 방법 1: 패스워드 설정 (권장)
```sql
-- MySQL 5.7
SET PASSWORD FOR '<계정명>'@'<호스트>' = PASSWORD('새로운_패스워드');

-- MySQL 8.0+ / MariaDB 10.4+
ALTER USER '<계정명>'@'<호스트>' IDENTIFIED BY '새로운_패스워드';

-- 예시
ALTER USER 'appuser'@'localhost' IDENTIFIED BY 'StrongP@ssw0rd!';

-- 권한 테이블 적용
FLUSH PRIVILEGES;
```

#### 방법 2: 계정 삭제 (불필요한 경우)
```sql
DROP USER '<계정명>'@'<호스트>';
FLUSH PRIVILEGES;
```

#### 패스워드 정책 확인
```sql
-- 패스워드 정책 확인 (MySQL 8.0+)
SHOW VARIABLES LIKE 'validate_password%';

-- MariaDB
SHOW VARIABLES LIKE '%password%';
```

### 주의사항
- **강력한 패스워드를 사용하세요.** (대소문자, 숫자, 특수문자 조합, 8자 이상)
- 패스워드 변경 시 해당 계정을 사용하는 애플리케이션 설정도 함께 변경하세요.
- 서비스 중단을 방지하기 위해 점검 창을 활용하세요.

### 검증
```sql
-- 패스워드 없는 계정 재확인
SELECT user, host FROM mysql.user WHERE authentication_string = '' OR authentication_string IS NULL;
-- 결과: Empty set (정상)

-- 계정으로 로그인 테스트
-- 쉘에서 실행
mysql -u <계정명> -p
Enter password: [새_패스워드_입력]
```

### 예시
```sql
-- 문제: appuser 계정에 패스워드가 없음
mysql> SELECT user, host, authentication_string FROM mysql.user WHERE user='appuser';
+---------+-----------+-----------------------+
| user    | host      | authentication_string |
+---------+-----------+-----------------------+
| appuser | localhost |                       |
+---------+-----------+-----------------------+

-- 조치: 패스워드 설정
mysql> ALTER USER 'appuser'@'localhost' IDENTIFIED BY 'MySecureP@ss123';
Query OK, 0 rows affected (0.01 sec)

mysql> FLUSH PRIVILEGES;
Query OK, 0 rows affected (0.00 sec)

-- 검증
mysql> SELECT user, host, LENGTH(authentication_string) FROM mysql.user WHERE user='appuser';
+---------+-----------+-------------------------------+
| user    | host      | LENGTH(authentication_string) |
+---------+-----------+-------------------------------+
| appuser | localhost |                            41 |
+---------+-----------+-------------------------------+
```

---

## MX-06: 계정 권한 최소화

### 취약점 설명
필요 이상의 권한을 가진 계정은 권한 남용이나 공격에 악용될 수 있습니다. 최소 권한 원칙을 적용해야 합니다.

**위험도**: HIGH (상)

### 점검 방법
```sql
-- 모든 계정의 권한 확인
SELECT user, host FROM mysql.user;

-- 특정 계정의 권한 상세 확인
SHOW GRANTS FOR '<계정명>'@'<호스트>';

-- 전역 권한이 많은 계정 확인
SELECT user, host,
       Select_priv, Insert_priv, Update_priv, Delete_priv,
       Create_priv, Drop_priv, Grant_priv, Super_priv
FROM mysql.user
WHERE Super_priv='Y' OR Grant_priv='Y';
```

### 조치 방법

#### 1단계: 현재 권한 검토
```sql
-- 계정별 권한 확인
SHOW GRANTS FOR 'appuser'@'localhost';

-- 예시 결과 분석
-- GRANT ALL PRIVILEGES ON *.* TO 'appuser'@'localhost'
-- → 너무 많은 권한 (위험)
```

#### 2단계: 권한 제거 및 재설정

##### 모든 권한 제거 후 필요한 권한만 부여 (권장)
```sql
-- 기존 권한 모두 제거
REVOKE ALL PRIVILEGES, GRANT OPTION FROM '<계정명>'@'<호스트>';

-- 필요한 권한만 부여
-- 읽기 전용 권한
GRANT SELECT ON <데이터베이스>.* TO '<계정명>'@'<호스트>';

-- 애플리케이션 계정 (일반적인 경우)
GRANT SELECT, INSERT, UPDATE, DELETE ON <데이터베이스>.* TO '<계정명>'@'<호스트>';

-- 개발자 계정 (특정 DB만)
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER
ON <데이터베이스>.* TO '<계정명>'@'<호스트>';

-- 권한 적용
FLUSH PRIVILEGES;
```

##### 특정 권한만 제거
```sql
-- 위험한 권한 제거
REVOKE SUPER ON *.* FROM '<계정명>'@'<호스트>';
REVOKE FILE ON *.* FROM '<계정명>'@'<호스트>';
REVOKE GRANT OPTION ON *.* FROM '<계정명>'@'<호스트>';

-- 권한 적용
FLUSH PRIVILEGES;
```

#### 3단계: 데이터베이스별 권한 설정
```sql
-- 특정 데이터베이스에만 권한 부여
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp_db.* TO 'appuser'@'localhost';

-- 특정 테이블에만 권한 부여
GRANT SELECT, INSERT, UPDATE ON myapp_db.users TO 'appuser'@'localhost';

-- 특정 컬럼에만 권한 부여
GRANT SELECT (id, name), UPDATE (name) ON myapp_db.users TO 'appuser'@'localhost';

FLUSH PRIVILEGES;
```

### 권한 유형별 설명

| 권한 | 설명 | 필요 계정 |
|------|------|-----------|
| `SELECT` | 데이터 조회 | 모든 애플리케이션 |
| `INSERT` | 데이터 추가 | 쓰기가 필요한 애플리케이션 |
| `UPDATE` | 데이터 수정 | 쓰기가 필요한 애플리케이션 |
| `DELETE` | 데이터 삭제 | 삭제가 필요한 애플리케이션 |
| `CREATE` | 테이블/DB 생성 | 관리자, 배포 계정 |
| `DROP` | 테이블/DB 삭제 | 관리자만 |
| `ALTER` | 테이블 구조 변경 | 관리자, 배포 계정 |
| `INDEX` | 인덱스 생성/삭제 | 관리자, DBA |
| `SUPER` | 슈퍼 권한 | DBA만 |
| `FILE` | 파일 읽기/쓰기 | 백업 계정만 |
| `GRANT OPTION` | 권한 부여 가능 | DBA만 |

### 주의사항
- **권한 변경 전 반드시 백업하세요.**
- 애플리케이션이 필요로 하는 최소 권한을 파악하세요.
- 권한 변경 후 애플리케이션이 정상 동작하는지 확인하세요.
- 운영 환경에서는 테스트 후 적용하세요.

### 검증
```sql
-- 변경 후 권한 확인
SHOW GRANTS FOR '<계정명>'@'<호스트>';

-- 권한 테스트 (해당 계정으로 접속하여)
-- 허용된 작업
SELECT * FROM myapp_db.users LIMIT 1;  -- 성공해야 함

-- 거부되어야 할 작업
DROP DATABASE myapp_db;  -- ERROR 1044 (42000): Access denied
```

### 예시
```sql
-- 문제: appuser가 전체 데이터베이스에 대해 모든 권한 보유
mysql> SHOW GRANTS FOR 'appuser'@'localhost';
+---------------------------------------------------------------+
| Grants for appuser@localhost                                  |
+---------------------------------------------------------------+
| GRANT ALL PRIVILEGES ON *.* TO 'appuser'@'localhost'          |
+---------------------------------------------------------------+

-- 조치: 필요한 권한만 부여
mysql> REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'appuser'@'localhost';
Query OK, 0 rows affected (0.00 sec)

mysql> GRANT SELECT, INSERT, UPDATE, DELETE ON myapp_db.* TO 'appuser'@'localhost';
Query OK, 0 rows affected (0.01 sec)

mysql> FLUSH PRIVILEGES;
Query OK, 0 rows affected (0.00 sec)

-- 검증
mysql> SHOW GRANTS FOR 'appuser'@'localhost';
+-------------------------------------------------------------------------+
| Grants for appuser@localhost                                            |
+-------------------------------------------------------------------------+
| GRANT USAGE ON *.* TO 'appuser'@'localhost'                             |
| GRANT SELECT, INSERT, UPDATE, DELETE ON `myapp_db`.* TO 'appuser'@'...' |
+-------------------------------------------------------------------------+
```

---

## MX-07: 불필요한 SUPER 권한 제거

### 취약점 설명
SUPER 권한은 시스템 변수 설정, 로그 관리, 복제 제어 등 강력한 권한입니다. 불필요한 계정에 SUPER 권한이 있으면 위험합니다.

**위험도**: HIGH (상)

### 점검 방법
```sql
-- SUPER 권한을 가진 계정 확인
SELECT user, host, Super_priv FROM mysql.user WHERE Super_priv = 'Y';

-- 특정 계정의 SUPER 권한 확인
SHOW GRANTS FOR '<계정명>'@'<호스트>';
```

### 조치 방법

#### SUPER 권한이 필요한 경우
- DBA 계정
- 복제(Replication) 관리 계정
- 백업 관리 계정 (일부 경우)

#### SUPER 권한 제거
```sql
-- SUPER 권한 제거
REVOKE SUPER ON *.* FROM '<계정명>'@'<호스트>';

-- 권한 적용
FLUSH PRIVILEGES;

-- 예시
REVOKE SUPER ON *.* FROM 'appuser'@'localhost';
FLUSH PRIVILEGES;
```

#### SUPER 대신 필요한 권한만 부여
```sql
-- 복제가 필요한 경우
GRANT REPLICATION SLAVE ON *.* TO '<계정명>'@'<호스트>';
GRANT REPLICATION CLIENT ON *.* TO '<계정명>'@'<호스트>';

-- 백업이 필요한 경우
GRANT SELECT, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER ON *.* TO '<계정명>'@'<호스트>';

FLUSH PRIVILEGES;
```

### 주의사항
- **root 계정의 SUPER 권한은 유지하세요.**
- 복제 환경에서는 복제 계정에 REPLICATION SLAVE 권한이 필요합니다.
- 권한 제거 전 해당 계정의 용도를 확인하세요.

### 검증
```sql
-- SUPER 권한 제거 확인
SELECT user, host, Super_priv FROM mysql.user WHERE user='<계정명>';
-- Super_priv가 'N'이어야 함

-- 권한 상세 확인
SHOW GRANTS FOR '<계정명>'@'<호스트>';
-- SUPER가 없어야 함
```

### 예시
```sql
-- 문제: appuser에 SUPER 권한이 있음
mysql> SELECT user, host, Super_priv FROM mysql.user WHERE user='appuser';
+---------+-----------+------------+
| user    | host      | Super_priv |
+---------+-----------+------------+
| appuser | localhost | Y          |
+---------+-----------+------------+

-- 조치: SUPER 권한 제거
mysql> REVOKE SUPER ON *.* FROM 'appuser'@'localhost';
Query OK, 0 rows affected (0.00 sec)

mysql> FLUSH PRIVILEGES;
Query OK, 0 rows affected (0.00 sec)

-- 검증
mysql> SELECT user, host, Super_priv FROM mysql.user WHERE user='appuser';
+---------+-----------+------------+
| user    | host      | Super_priv |
+---------+-----------+------------+
| appuser | localhost | N          |
+---------+-----------+------------+
```

---

## MX-09: FILE 권한 제한

### 취약점 설명
FILE 권한은 서버의 파일 시스템에 접근하여 파일을 읽거나 쓸 수 있는 강력한 권한입니다. 악용 시 시스템 파일 유출이나 악성 코드 삽입이 가능합니다.

**위험도**: HIGH (상)

### 점검 방법
```sql
-- FILE 권한을 가진 계정 확인
SELECT user, host, File_priv FROM mysql.user WHERE File_priv = 'Y';

-- 특정 계정의 FILE 권한 확인
SHOW GRANTS FOR '<계정명>'@'<호스트>';
```

### 조치 방법

#### FILE 권한이 필요한 경우
- 백업/복원 작업 계정 (mysqldump, LOAD DATA)
- 데이터 가져오기/내보내기 계정

#### FILE 권한 제거
```sql
-- FILE 권한 제거
REVOKE FILE ON *.* FROM '<계정명>'@'<호스트>';

-- 권한 적용
FLUSH PRIVILEGES;

-- 예시
REVOKE FILE ON *.* FROM 'appuser'@'localhost';
FLUSH PRIVILEGES;
```

#### FILE 권한 사용 예시 (위험성 이해)
```sql
-- 시스템 파일 읽기 (위험!)
SELECT LOAD_FILE('/etc/passwd');

-- 파일 쓰기 (위험!)
SELECT 'malicious code' INTO OUTFILE '/tmp/backdoor.php';
```

### 주의사항
- **일반 애플리케이션 계정에는 FILE 권한이 필요 없습니다.**
- FILE 권한은 root나 백업 전용 계정만 가져야 합니다.
- secure_file_priv 설정과 함께 사용하세요 (MX-10 참조).

### 검증
```sql
-- FILE 권한 제거 확인
SELECT user, host, File_priv FROM mysql.user WHERE user='<계정명>';
-- File_priv가 'N'이어야 함

-- 테스트 (FILE 권한이 없으면 실패해야 함)
SELECT LOAD_FILE('/etc/hosts');
-- ERROR 1227 (42000): Access denied (정상)
```

### 예시
```sql
-- 문제: 일반 애플리케이션 계정에 FILE 권한이 있음
mysql> SELECT user, host, File_priv FROM mysql.user WHERE user='webapp';
+--------+-----------+-----------+
| user   | host      | File_priv |
+--------+-----------+-----------+
| webapp | localhost | Y         |
+--------+-----------+-----------+

-- 조치: FILE 권한 제거
mysql> REVOKE FILE ON *.* FROM 'webapp'@'localhost';
Query OK, 0 rows affected (0.00 sec)

mysql> FLUSH PRIVILEGES;
Query OK, 0 rows affected (0.00 sec)

-- 검증
mysql> SELECT user, host, File_priv FROM mysql.user WHERE user='webapp';
+--------+-----------+-----------+
| user   | host      | File_priv |
+--------+-----------+-----------+
| webapp | localhost | N         |
+--------+-----------+-----------+
```

---

## MX-10: secure_file_priv 설정

### 취약점 설명
secure_file_priv가 설정되지 않으면 LOAD DATA, SELECT INTO OUTFILE 등으로 임의의 파일 시스템 위치에 접근할 수 있습니다.

**위험도**: HIGH (상)

### 점검 방법
```sql
-- secure_file_priv 설정 확인
SHOW VARIABLES LIKE 'secure_file_priv';

-- 결과 해석:
-- NULL 또는 빈 값: 제한 없음 (위험)
-- 특정 디렉토리: 해당 디렉토리로만 제한 (안전)
-- /var/lib/mysql-files/: 권장 설정
```

### 조치 방법

#### 주의: 런타임 변경 불가
secure_file_priv는 **서버 시작 시에만 설정 가능**하며 런타임 변경이 불가능합니다.

#### 1단계: my.cnf 파일 편집
```bash
# MySQL 설정 파일 위치 확인
mysql --help | grep "Default options" -A 1

# 일반적인 위치:
# - /etc/my.cnf
# - /etc/mysql/my.cnf
# - /etc/mysql/mysql.conf.d/mysqld.cnf

# 백업
sudo cp /etc/my.cnf /etc/my.cnf.backup.$(date +%Y%m%d)

# 편집
sudo vi /etc/my.cnf
```

#### 2단계: 설정 추가
```ini
[mysqld]
# 파일 접근을 특정 디렉토리로 제한
secure_file_priv = /var/lib/mysql-files/

# 또는 완전히 비활성화 (LOAD DATA, SELECT INTO OUTFILE 사용 불가)
# secure_file_priv = NULL
```

#### 3단계: 디렉토리 생성 및 권한 설정
```bash
# 디렉토리 생성
sudo mkdir -p /var/lib/mysql-files/

# 소유자 변경 (MySQL 사용자)
sudo chown mysql:mysql /var/lib/mysql-files/

# 권한 설정 (MySQL만 접근 가능)
sudo chmod 750 /var/lib/mysql-files/

# 확인
ls -ld /var/lib/mysql-files/
# drwxr-x--- 2 mysql mysql 4096 Nov 27 14:30 /var/lib/mysql-files/
```

#### 4단계: MySQL 재시작
```bash
# MySQL 재시작
sudo systemctl restart mysqld

# 또는 MariaDB
sudo systemctl restart mariadb

# 상태 확인
sudo systemctl status mysqld
```

#### 5단계: 설정 확인
```sql
-- MySQL 접속 후 확인
SHOW VARIABLES LIKE 'secure_file_priv';

-- 결과 예시:
-- +------------------+-----------------------+
-- | Variable_name    | Value                 |
-- +------------------+-----------------------+
-- | secure_file_priv | /var/lib/mysql-files/ |
-- +------------------+-----------------------+
```

### 사용 예시
```sql
-- 설정 후 파일 작업은 지정된 디렉토리에서만 가능
SELECT * FROM users INTO OUTFILE '/var/lib/mysql-files/users_export.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';

-- 다른 위치는 거부됨
SELECT * FROM users INTO OUTFILE '/tmp/users.csv';
-- ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option
```

### 주의사항
- **MySQL 재시작이 필요합니다.** 서비스 중단 시간을 고려하세요.
- 재시작 전 설정 파일 문법을 확인하세요.
- 기존에 다른 디렉토리를 사용하던 애플리케이션은 수정이 필요합니다.

### 검증
```bash
# MySQL 서비스 상태
sudo systemctl status mysqld

# 설정 파일 문법 검사
mysqld --help --verbose 2>&1 | grep "secure-file-priv"

# MySQL에서 확인
mysql -u root -p -e "SHOW VARIABLES LIKE 'secure_file_priv';"
```

---

## MX-11: 에러 로그 활성화

### 취약점 설명
에러 로그가 활성화되지 않으면 시스템 오류, 보안 이벤트, 비정상적인 접근 시도 등을 추적할 수 없습니다.

**위험도**: MEDIUM (중)

### 점검 방법
```sql
-- 에러 로그 설정 확인
SHOW VARIABLES LIKE 'log_error';

-- 결과 해석:
-- 빈 값 또는 stderr: 콘솔로만 출력 (권장하지 않음)
-- 파일 경로: 파일로 저장 (권장)
```

### 조치 방법

#### 주의: my.cnf 설정 필요
log_error는 설정 파일에서만 지정 가능합니다.

#### 1단계: my.cnf 파일 편집
```bash
# 백업
sudo cp /etc/my.cnf /etc/my.cnf.backup.$(date +%Y%m%d)

# 편집
sudo vi /etc/my.cnf
```

#### 2단계: 설정 추가
```ini
[mysqld]
# 에러 로그 활성화
log_error = /var/log/mysql/error.log

# 또는 MariaDB
log_error = /var/log/mariadb/error.log

# 로그 레벨 설정 (선택사항, MySQL 8.0+)
log_error_verbosity = 2
# 1 = ERROR only
# 2 = ERROR + WARNING (기본값)
# 3 = ERROR + WARNING + INFORMATION
```

#### 3단계: 로그 디렉토리 생성
```bash
# MySQL
sudo mkdir -p /var/log/mysql/

# 소유자 변경
sudo chown -R mysql:mysql /var/log/mysql/

# 권한 설정
sudo chmod 750 /var/log/mysql/

# 로그 파일 생성 (선택사항)
sudo touch /var/log/mysql/error.log
sudo chown mysql:mysql /var/log/mysql/error.log
sudo chmod 640 /var/log/mysql/error.log
```

#### 4단계: MySQL 재시작
```bash
# MySQL 재시작
sudo systemctl restart mysqld

# 또는 MariaDB
sudo systemctl restart mariadb

# 상태 확인
sudo systemctl status mysqld
```

#### 5단계: 설정 확인
```sql
-- MySQL 접속 후 확인
SHOW VARIABLES LIKE 'log_error';

-- 결과 예시:
-- +---------------+------------------------+
-- | Variable_name | Value                  |
-- +---------------+------------------------+
-- | log_error     | /var/log/mysql/error.log |
-- +---------------+------------------------+
```

### 로그 로테이션 설정
```bash
# logrotate 설정 파일 생성
sudo vi /etc/logrotate.d/mysql

# 내용 추가:
/var/log/mysql/*.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/bin/mysqladmin -u root -p'password' flush-logs
    endscript
}
```

### 로그 모니터링
```bash
# 실시간 로그 확인
sudo tail -f /var/log/mysql/error.log

# 최근 에러 확인
sudo tail -100 /var/log/mysql/error.log | grep -i error

# 특정 날짜 로그 확인
sudo grep "2024-11-27" /var/log/mysql/error.log
```

### 주의사항
- **MySQL 재시작이 필요합니다.**
- 로그 디렉토리의 디스크 공간을 모니터링하세요.
- 로그 로테이션을 설정하여 디스크 공간을 관리하세요.
- 보안상 로그 파일 권한은 640 이하로 설정하세요.

### 검증
```bash
# 로그 파일 존재 확인
ls -l /var/log/mysql/error.log

# 로그 파일에 내용이 기록되는지 확인
sudo tail -20 /var/log/mysql/error.log

# MySQL 재시작 로그 확인
sudo systemctl restart mysqld
sudo tail -20 /var/log/mysql/error.log
```

---

## MX-14: MySQL/MariaDB 버전 업데이트

### 취약점 설명
오래된 MySQL/MariaDB 버전은 알려진 보안 취약점에 노출되어 있습니다. 정기적인 업데이트가 필요합니다.

**위험도**: HIGH (상)

### 점검 방법
```sql
-- MySQL/MariaDB 버전 확인
SELECT VERSION();

-- 또는
SHOW VARIABLES LIKE 'version';
```

```bash
# 쉘에서 확인
mysql --version

# RPM 패키지 버전 확인
rpm -q mysql-server
# 또는
rpm -q mariadb-server
```

### 조치 방법

#### 주의사항 (업데이트 전)
- **반드시 전체 데이터베이스 백업을 수행하세요.**
- 테스트 환경에서 먼저 검증하세요.
- 업데이트 노트를 확인하여 호환성 이슈를 파악하세요.
- 서비스 중단 시간을 고려하세요.

#### 1단계: 백업
```bash
# 전체 데이터베이스 백업
sudo mysqldump -u root -p --all-databases --single-transaction --routines --triggers > /backup/mysql_full_backup_$(date +%Y%m%d).sql

# 또는 특정 데이터베이스만
sudo mysqldump -u root -p mydb > /backup/mydb_$(date +%Y%m%d).sql

# 설정 파일 백업
sudo cp -r /etc/my.cnf /etc/my.cnf.backup.$(date +%Y%m%d)
sudo cp -r /etc/mysql /etc/mysql.backup.$(date +%Y%m%d)

# 데이터 디렉토리 백업 (선택사항, 용량 주의)
sudo rsync -av /var/lib/mysql/ /backup/mysql_data_$(date +%Y%m%d)/
```

#### 2단계: 현재 버전 및 저장소 확인
```bash
# MySQL 버전
mysql --version

# 설치된 패키지
rpm -qa | grep -i mysql
# 또는
rpm -qa | grep -i mariadb

# 저장소 확인
dnf repolist
```

#### 3단계: MySQL/MariaDB 업데이트

##### MySQL 업데이트
```bash
# 사용 가능한 업데이트 확인
sudo dnf check-update mysql-server

# MySQL 업데이트
sudo dnf update mysql-server mysql-client

# 또는 모든 MySQL 관련 패키지
sudo dnf update mysql\*
```

##### MariaDB 업데이트
```bash
# 사용 가능한 업데이트 확인
sudo dnf check-update mariadb-server

# MariaDB 업데이트
sudo dnf update mariadb-server mariadb-client

# 또는 모든 MariaDB 관련 패키지
sudo dnf update mariadb\*
```

#### 4단계: MySQL 업그레이드 실행
```bash
# MySQL 서비스 중지
sudo systemctl stop mysqld

# 업그레이드 실행 (MySQL 8.0+)
sudo mysql_upgrade -u root -p

# 또는 MariaDB
sudo mysql_upgrade -u root -p

# MySQL 서비스 시작
sudo systemctl start mysqld

# 상태 확인
sudo systemctl status mysqld
```

#### 5단계: 검증
```bash
# 버전 확인
mysql --version

# MySQL 접속 테스트
mysql -u root -p -e "SELECT VERSION();"

# 데이터베이스 확인
mysql -u root -p -e "SHOW DATABASES;"

# 애플리케이션 연결 테스트
# 각 애플리케이션에서 DB 연결 확인
```

### 메이저 버전 업그레이드 (5.7 → 8.0)

메이저 버전 업그레이드는 더 신중하게 진행해야 합니다.

```bash
# 1. 백업 (필수!)
sudo mysqldump -u root -p --all-databases > /backup/mysql_pre_upgrade.sql

# 2. MySQL 5.7 중지
sudo systemctl stop mysqld

# 3. MySQL 8.0 저장소 추가
sudo dnf install https://dev.mysql.com/get/mysql80-community-release-el9-1.noarch.rpm

# 4. MySQL 8.0 설치
sudo dnf module disable mysql
sudo dnf install mysql-community-server

# 5. MySQL 시작
sudo systemctl start mysqld

# 6. 임시 root 패스워드 확인 (MySQL 8.0 처음 설치 시)
sudo grep 'temporary password' /var/log/mysqld.log

# 7. mysql_upgrade 실행
sudo mysql_upgrade -u root -p

# 8. 재시작
sudo systemctl restart mysqld
```

### 주의사항
- **업데이트 전 반드시 백업하세요.**
- 메이저 버전 업그레이드는 호환성 문제가 있을 수 있습니다.
- 테스트 환경에서 먼저 검증하세요.
- 업데이트 후 애플리케이션 동작을 확인하세요.
- 롤백 계획을 준비하세요.

### 롤백 (문제 발생 시)
```bash
# 1. MySQL 중지
sudo systemctl stop mysqld

# 2. 이전 버전 재설치
sudo dnf downgrade mysql-server-<이전버전>

# 3. 백업 복원
mysql -u root -p < /backup/mysql_full_backup_20241127.sql

# 4. MySQL 시작
sudo systemctl start mysqld
```

---

## MX-16: 네트워크 바인딩 설정

### 취약점 설명
MySQL이 모든 네트워크 인터페이스(0.0.0.0)에서 수신하면 외부에서 접근 가능하여 보안 위험이 증가합니다.

**위험도**: HIGH (상)

### 점검 방법
```sql
-- bind-address 설정 확인
SHOW VARIABLES LIKE 'bind_address';

-- 결과 해석:
-- 0.0.0.0 또는 *: 모든 인터페이스에서 수신 (위험)
-- 127.0.0.1: localhost만 수신 (안전, 로컬만)
-- 특정 IP: 해당 IP에서만 수신 (안전)
```

```bash
# 네트워크 연결 상태 확인
sudo netstat -tlnp | grep mysql
# 또는
sudo ss -tlnp | grep mysql

# 결과 해석:
# 0.0.0.0:3306: 모든 인터페이스
# 127.0.0.1:3306: localhost만
# 192.168.1.100:3306: 특정 IP만
```

### 조치 방법

#### 주의: my.cnf 설정 필요
bind-address는 설정 파일에서만 지정 가능합니다.

#### 1단계: my.cnf 파일 편집
```bash
# 백업
sudo cp /etc/my.cnf /etc/my.cnf.backup.$(date +%Y%m%d)

# 편집
sudo vi /etc/my.cnf
```

#### 2단계: 설정 변경

##### 시나리오 1: localhost만 접속 (권장 - 웹서버와 동일 서버)
```ini
[mysqld]
# localhost만 접속 허용
bind-address = 127.0.0.1
```

##### 시나리오 2: 특정 내부 네트워크 IP에서만 접속
```ini
[mysqld]
# 내부 IP에서만 수신
bind-address = 192.168.1.100
```

##### 시나리오 3: 모든 인터페이스 (방화벽 필수)
```ini
[mysqld]
# 모든 인터페이스에서 수신 (권장하지 않음)
bind-address = 0.0.0.0
```

##### 시나리오 4: IPv6 사용
```ini
[mysqld]
# IPv6 localhost
bind-address = ::1

# 또는 모든 IPv6
bind-address = ::
```

#### 3단계: MySQL 재시작
```bash
# MySQL 재시작
sudo systemctl restart mysqld

# 또는 MariaDB
sudo systemctl restart mariadb

# 상태 확인
sudo systemctl status mysqld
```

#### 4단계: 설정 확인
```sql
-- MySQL 접속 후 확인
SHOW VARIABLES LIKE 'bind_address';

-- 결과 예시:
-- +---------------+-----------+
-- | Variable_name | Value     |
-- +---------------+-----------+
-- | bind_address  | 127.0.0.1 |
-- +---------------+-----------+
```

```bash
# 네트워크 포트 확인
sudo netstat -tlnp | grep mysql
# tcp  0  0 127.0.0.1:3306  0.0.0.0:*  LISTEN  12345/mysqld
```

### 방화벽 설정 (bind-address가 0.0.0.0인 경우)
```bash
# 방화벽 활성화 확인
sudo firewall-cmd --state

# MySQL 포트 차단 (기본)
sudo firewall-cmd --permanent --remove-service=mysql

# 특정 IP에서만 MySQL 접속 허용
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="3306" protocol="tcp" accept'

# 설정 적용
sudo firewall-cmd --reload

# 확인
sudo firewall-cmd --list-all
```

### 주의사항
- **MySQL 재시작이 필요합니다.**
- localhost로 설정 시 원격 접속이 불가능합니다.
- 원격 접속이 필요한 경우 방화벽으로 IP를 제한하세요.
- 변경 후 애플리케이션 연결을 확인하세요.

### 검증
```bash
# 포트 확인
sudo ss -tlnp | grep 3306

# localhost 설정 확인
mysql -h 127.0.0.1 -u root -p  # 성공해야 함
mysql -h <외부IP> -u root -p    # 실패해야 함 (localhost 설정 시)

# 원격에서 테스트 (다른 서버에서)
telnet <서버IP> 3306
# Connection refused (정상, localhost 설정 시)
```

### 예시
```bash
# 현재 설정: 모든 인터페이스에서 수신 (위험)
$ sudo netstat -tlnp | grep mysql
tcp  0  0 0.0.0.0:3306  0.0.0.0:*  LISTEN  12345/mysqld

# my.cnf 수정
sudo vi /etc/my.cnf
# [mysqld]
# bind-address = 127.0.0.1

# MySQL 재시작
sudo systemctl restart mysqld

# 확인
$ sudo netstat -tlnp | grep mysql
tcp  0  0 127.0.0.1:3306  0.0.0.0:*  LISTEN  12345/mysqld

# MySQL에서 확인
mysql> SHOW VARIABLES LIKE 'bind_address';
+---------------+-----------+
| Variable_name | Value     |
+---------------+-----------+
| bind_address  | 127.0.0.1 |
+---------------+-----------+
```

---

## 부록: 유용한 명령어 모음

### 계정 및 권한 관리
```sql
-- 모든 사용자 확인
SELECT user, host FROM mysql.user;

-- 특정 사용자 권한 확인
SHOW GRANTS FOR 'username'@'host';

-- 현재 사용자 확인
SELECT USER(), CURRENT_USER();

-- 권한 정보 상세 확인
SELECT * FROM mysql.user WHERE user='username'\G
```

### 데이터베이스 정보
```sql
-- 모든 데이터베이스 목록
SHOW DATABASES;

-- 데이터베이스 크기
SELECT
    table_schema AS 'Database',
    ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.tables
GROUP BY table_schema;

-- 테이블 목록
SHOW TABLES FROM database_name;

-- 테이블 구조
DESCRIBE table_name;
```

### 시스템 변수
```sql
-- 모든 시스템 변수
SHOW VARIABLES;

-- 특정 변수 검색
SHOW VARIABLES LIKE '%log%';

-- 변수 값 설정 (동적 변수만)
SET GLOBAL max_connections = 200;
```

### 연결 및 프로세스
```sql
-- 현재 연결 확인
SHOW PROCESSLIST;

-- 또는 상세
SELECT * FROM information_schema.processlist;

-- 특정 프로세스 종료
KILL <process_id>;
```

### 백업 및 복원
```bash
# 전체 백업
mysqldump -u root -p --all-databases > all_databases.sql

# 특정 DB 백업
mysqldump -u root -p database_name > database_name.sql

# 복원
mysql -u root -p database_name < database_name.sql
```

---

## 참고 자료

- [MySQL 8.0 Security Guide](https://dev.mysql.com/doc/refman/8.0/en/security.html)
- [MariaDB Security Documentation](https://mariadb.com/kb/en/security/)
- [KISA 주요정보통신기반시설 취약점 분석·평가 가이드](https://www.kisa.or.kr/2060204/form?postSeq=12&lang_type=KO&page=1)
- [CIS MySQL Benchmark](https://www.cisecurity.org/)

---

**문서 버전**: 1.0
**최종 수정일**: 2024-11-27
**작성자**: linux-vuln-autofix
