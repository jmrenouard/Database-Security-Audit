# Security Audit Checks, Ports, Catalogs & Hardening

## Default Service Ports & TLS Controls

| Engine | Default Port | Transport Security Setting | Recommended Setting |
| :--- | :--- | :--- | :--- |
| **MySQL / MariaDB** | `3306/tcp` | `require_secure_transport` | `ON` (bind `127.0.0.1` or private subnet) |
| **PostgreSQL** | `5432/tcp` | `ssl` / client `sslmode` | `ssl = on`, client `sslmode=verify-full` |

## Catalog Schema Differences by Version

| Audit Goal | Legacy Versions | Current Versions (`MySQL 8.0+`, `PostgreSQL 13–17`) |
| :--- | :--- | :--- |
| **MySQL password hashes** | `mysql.user.password` (`<= 5.6`) | `mysql.user.plugin`, `mysql.user.authentication_string` (`5.7+` / `8.0+`) |
| **MySQL password change** | `SET PASSWORD ... = PASSWORD(...)` | `ALTER USER 'u'@'h' IDENTIFIED BY '...'` |
| **MySQL stored routines** | `mysql.proc` (`<= 5.7`) | `information_schema.ROUTINES` (`definer`, `security_type`) |
| **PostgreSQL auth hashes** | `pg_shadow` (`md5...`) | `pg_authid.rolpassword` (`SCRAM-SHA-256$...` by default) |
| **PostgreSQL HBA rules** | OS file `/etc/postgresql/*/main/pg_hba.conf` | SQL view `pg_hba_file_rules` |

## High-Risk Privileges and Default Roles

| Engine | Privilege / Role | Security Impact | Hardening Control |
| :--- | :--- | :--- | :--- |
| **MySQL** | `SUPER` / `SYSTEM_VARIABLES_ADMIN` | Global variable changes, bypass `read_only`, kill threads | Restrict strictly to DBAs |
| **MySQL** | `FILE` | Server read (`LOAD_FILE`) and write (`INTO DUMPFILE`) | Revoke `FILE`; set `secure_file_priv` and `local_infile=OFF` |
| **MySQL** | `PROCESS` | Exposes live queries (`SHOW FULL PROCESSLIST`) | Grant only to monitoring accounts |
| **MySQL** | `PROXY` (`mysql.proxies_priv`) | Identity impersonation across authentication plugins | Audit `proxies_priv`; avoid anonymous `''@'%'` accounts |
| **PostgreSQL** | `rolsuper` / `rolbypassrls` | Bypasses all ACLs and Row-Level Security | Separate service owner vs application roles (`NOSUPERUSER`) |
| **PostgreSQL** | `pg_execute_server_program` | OS execution via `COPY ... FROM/TO PROGRAM` | Revoke from all non-admin roles |
| **PostgreSQL** | `pg_read_server_files` / `pg_write_server_files` | Server filesystem reads/writes via `COPY` / `pg_read_file` | Revoke unless explicitly audited for ETL |
| **PostgreSQL** | Untrusted PLs (`plpython3u`, `plperlu`) | Direct OS syscalls inside user functions | Disable untrusted extensions; enforce superuser-only creation |

## Non-Destructive Nmap Discovery & Audit Scripts

| Script | Engine | Purpose |
| :--- | :--- | :--- |
| `mysql-info` | MySQL (`3306`) | Banner, protocol version, SSL/compression capability flags |
| `mysql-empty-password` | MySQL (`3306`) | Detects empty `root` or anonymous account passwords |
| `mysql-audit` | MySQL (`3306`) | Evaluates CIS MySQL baseline checks via `mysql-cis.audit` |
| `mysql-users` / `mysql-databases` | MySQL (`3306`) | Authenticated enumeration of accounts and schemas |
| `pgsql-brute` | PostgreSQL (`5432`) | Authorized credential strength verification |
