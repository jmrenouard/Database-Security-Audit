# Audit MySQL Security Configuration

WARNING: Obtain written authorization before you scan or query any database host. Unauthorized access causes legal and operational harm.

## Prerequisites

- Confirm target IP scope and maintenance window in your audit plan.
- Install the `mysql` client and `nmap` on your jump host.
- Provision a read-only audit account or lab `root` credential.

## Procedure

### Step 1: Check Network Exposure and TLS Settings

1. Scan only TCP port `3306` on the approved target host.

```bash
nmap -Pn -sV -p 3306 --script mysql-info 127.0.0.1
```

2. Connect with the `mysql` client and inspect TLS requirements and bind settings.

```sql
SELECT @@version, @@bind_address, @@require_secure_transport, @@local_infile, @@secure_file_priv;
```

NOTE: A blank `@@secure_file_priv` value allows unrestricted `SELECT ... INTO OUTFILE` writes if `FILE` privilege exists.

### Step 2: Audit Accounts, Anonymous Users, and Password Plugins

1. Query `mysql.user` for empty usernames, wildcard `%` hosts, and legacy `mysql_native_password` plugins.

```sql
SELECT user, host, plugin, account_locked
FROM mysql.user
WHERE user = '' OR host = '%' OR plugin = 'mysql_native_password'
ORDER BY user, host;
```

2. Check for accounts that hold dangerous global privileges (`SUPER`, `FILE`, `PROCESS`, `CREATE USER`).

```sql
SELECT grantee, privilege_type, is_grantable
FROM information_schema.user_privileges
WHERE privilege_type IN ('SUPER', 'FILE', 'PROCESS', 'CREATE USER')
ORDER BY grantee, privilege_type;
```

### Step 3: Inspect Stored Routines and Proxy Grants

1. List stored procedures that execute with `DEFINER` privileges.

```sql
SELECT routine_schema, routine_name, definer, security_type
FROM information_schema.ROUTINES
WHERE security_type = 'DEFINER';
```

2. Check for proxy impersonation entries in `mysql.proxies_priv`.

```sql
SELECT Host, User, Proxied_host, Proxied_user, With_grant
FROM mysql.proxies_priv;
```

## Validation

Confirm that non-admin application accounts hold zero `SUPER`, `FILE`, or `PROCESS` grants and use `caching_sha2_password` or TLS.

## Remediation and Rollback

CAUTION: Back up MySQL grants before you revoke user privileges. Incorrect privilege revocation blocks production applications.

1. Remove anonymous accounts and revoke unsafe privileges from non-admin accounts.

```sql
REVOKE FILE, PROCESS, SUPER ON *.* FROM 'app_user'@'%';
DROP USER IF EXISTS ''@'localhost', ''@'%';
```

2. If an application fails after revocation, restore the prior grant statement from your audit backup log.

## Related Documentation

- [Security Audit Checks, Catalogs & Remediation Reference](../03-reference/security-audit-checks-and-ports.md)
- [Privilege Boundaries and Defense-in-Depth Explanation](../04-explanation/threat-model-and-defense-in-depth.md)
