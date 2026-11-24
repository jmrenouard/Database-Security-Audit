# Tutorial 1: Isolated MySQL and PostgreSQL Security Audit Lab

> [!CAUTION]
> **Isolated Lab Only:** Bind temporary containers strictly to `127.0.0.1` on ephemeral ports so no database service is exposed on external networks.

In this tutorial, you provision isolated local `mysql:8.0` and `postgres:16-alpine` containers, execute non-destructive privilege and authentication checks, and tear down the lab.

## Prerequisites

- Docker Engine (`20.10` or newer) running locally
- Local `mysql` and `psql` clients (or `docker exec`)

## Step 1: Launch Isolated Loopback Containers

Start ephemeral MySQL `8.0` and PostgreSQL `16` containers bound strictly to `127.0.0.1`:

```bash
docker run -d --name sec-audit-mysql --rm \
  -p 127.0.0.1:33306:3306 \
  -e MYSQL_ROOT_PASSWORD=LabAuditPassword_2026 \
  mysql:8.0

docker run -d --name sec-audit-pg --rm \
  -p 127.0.0.1:35432:5432 \
  -e POSTGRES_PASSWORD=LabAuditPassword_2026 \
  postgres:16-alpine
```

Wait until both engines report healthy readiness (`docker exec ...`).

## Step 2: Run Non-Destructive MySQL Catalog Audits

Inspect user accounts, wildcard hosts (`%`), authentication plugins (`caching_sha2_password` vs `mysql_native_password`), `SUPER`/`FILE`/`PROCESS` privileges, and stored routine security contexts:

```bash
docker exec -i sec-audit-mysql mysql -uroot -pLabAuditPassword_2026 <<'SQL'
SELECT user, host, plugin, account_locked
FROM mysql.user
ORDER BY user, host;

SELECT grantee, privilege_type, is_grantable
FROM information_schema.user_privileges
WHERE privilege_type IN ('SUPER', 'FILE', 'PROCESS', 'CREATE USER')
ORDER BY grantee, privilege_type;

SELECT @@secure_file_priv, @@local_infile, @@require_secure_transport;

SELECT routine_schema, routine_name, definer, security_type
FROM information_schema.ROUTINES;
SQL
```

Expected findings in a stock `mysql:8.0` container:

- `root@%` exists by default alongside `root@localhost` (flag wildcard host `%` if remote root login is not required).
- `plugin` shows `caching_sha2_password` (`MySQL 8.0` default) instead of legacy `mysql_native_password`.

## Step 3: Run Non-Destructive PostgreSQL Catalog Audits

Inspect PostgreSQL roles, superuser and bypass-RLS attributes, `SCRAM-SHA-256` password hashes in `pg_authid`, default dangerous role memberships (`pg_execute_server_program`, `pg_read_server_files`, `pg_write_server_files`), and installed extensions:

```bash
docker exec -i sec-audit-pg psql -U postgres <<'SQL'
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolcanlogin
FROM pg_roles
WHERE rolcanlogin OR rolname LIKE 'pg_%'
ORDER BY rolname;

SELECT rolname, left(rolpassword, 13) AS hash_prefix
FROM pg_authid
WHERE rolcanlogin;

SELECT r.rolname AS default_role, m.rolname AS member_role
FROM pg_auth_members am
JOIN pg_roles r ON r.oid = am.roleid
JOIN pg_roles m ON m.oid = am.member
WHERE r.rolname IN ('pg_execute_server_program', 'pg_read_server_files', 'pg_write_server_files');

SHOW password_encryption;
SHOW ssl;
SQL
```

Expected findings in a stock `postgres:16-alpine` container:

- `hash_prefix` starts with `SCRAM-SHA-256$` and `password_encryption` prints `scram-sha-256`.
- Zero unprivileged accounts hold `pg_execute_server_program`, `pg_read_server_files`, or `pg_write_server_files`.

## Step 4: Tear Down the Ephemeral Lab

Stop and automatically remove both containers (`--rm` deletes writable container layers):

```bash
docker stop sec-audit-mysql sec-audit-pg
```

## Next Steps

- Execute operational checks in [How-To: Audit MySQL Security Configuration](../02-how-to-guides/audit-mysql-security.md) and [Audit PostgreSQL Security Configuration](../02-how-to-guides/audit-postgresql-security.md).
- Compare legacy vs modern catalog tables in [Security Audit Checks, Catalogs & Hardening Reference](../03-reference/security-audit-checks-and-ports.md).
