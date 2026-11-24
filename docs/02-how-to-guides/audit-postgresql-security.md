# Audit PostgreSQL Security Configuration

WARNING: Obtain written authorization before you scan or query any PostgreSQL instance. Unauthorized scans violate security policy and law.

## Prerequisites

- Confirm approved host addresses and ports in your engagement scope.
- Install the `psql` client (`PostgreSQL 13` or newer) and `nmap`.
- Connect with TLS verification enabled (`sslmode=verify-full`) when outside an isolated loopback lab.

## Procedure

### Step 1: Verify Version, Password Hashing, and TLS

1. Check the exposed service version on the approved target port `5432`.

```bash
nmap -Pn -sV -p 5432 127.0.0.1
```

2. Connect with `psql` and inspect password encryption and TLS parameters.

```sql
SELECT version();
SHOW password_encryption;
SHOW ssl;
```

NOTE: PostgreSQL `14` and newer set `password_encryption` to `scram-sha-256` by default.

### Step 2: Inspect Authentication Rules and Login Hashes

1. Review client authentication entries inside `pg_hba_file_rules` for permissive `trust` or unencrypted `md5` rules.

```sql
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
ORDER BY line_number;
```

2. Check `pg_authid` as a privileged auditor to detect empty or legacy `md5` password hashes.

```sql
SELECT rolname, rolsuper, rolbypassrls, left(rolpassword, 13) AS hash_prefix
FROM pg_authid
WHERE rolcanlogin
ORDER BY rolname;
```

### Step 3: Check Dangerous Default Roles, Languages, and DBlinks

1. List members of `pg_execute_server_program`, `pg_read_server_files`, and `pg_write_server_files`.

```sql
SELECT r.rolname AS default_role, m.rolname AS member_role
FROM pg_auth_members am
JOIN pg_roles r ON r.oid = am.roleid
JOIN pg_roles m ON m.oid = am.member
WHERE r.rolname IN ('pg_execute_server_program', 'pg_read_server_files', 'pg_write_server_files');
```

2. Inspect untrusted procedural languages and views that reference `dblink` credentials.

```sql
SELECT lanname, lanpltrusted FROM pg_language WHERE lanpltrusted = false;
SELECT table_schema, table_name FROM information_schema.views WHERE view_definition ILIKE '%dblink%';
```

## Validation

Confirm zero unprivileged accounts hold `rolsuper`, `pg_execute_server_program`, or `trust` rules in `pg_hba_file_rules`.

## Remediation and Rollback

CAUTION: Keep an emergency superuser console ready before you tighten `pg_hba.conf`. Strict authentication rules block misconfigured client applications.

1. Revoke server-file roles and update legacy passwords to `scram-sha-256`.

```sql
REVOKE pg_execute_server_program, pg_read_server_files, pg_write_server_files FROM audit_target;
ALTER ROLE audit_target WITH PASSWORD 'StrongRotatedPassword_2026';
```

2. If legitimate replication or maintenance scripts lose access, restore the previous role grant and reload `pg_hba.conf`.

```sql
SELECT pg_reload_conf();
```

## Related Documentation

- [Security Audit Checks, Catalogs & Remediation Reference](../03-reference/security-audit-checks-and-ports.md)
- [Privilege Boundaries and Defense-in-Depth Explanation](../04-explanation/threat-model-and-defense-in-depth.md)
