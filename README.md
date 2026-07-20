# wp2shell-scan

**Detect and clean up [wp2shell](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/) (CVE‑2026‑63030) compromise across one or many WordPress sites.**

wp2shell is the pre‑authentication remote‑code‑execution vulnerability fixed in **WordPress 7.0.2 / 6.9.5 / 6.8.6** (2026‑07‑17). A public PoC appeared within a day and mass‑exploitation followed within ~48 hours. Patching closes the hole — but a site exploited *before* it was patched is **already compromised**, and updating does **not** remove the attacker's persistence.

This tool finds and removes that persistence. It's a single, dependency‑light Bash script that runs **read‑only by default** and can scan **thousands of sites in one pass**.

> ⚠️ This is defensive tooling. It contains no exploit code. **Snapshot a site before running `--clean`.**

## What it detects

Post‑exploitation, wp2shell tooling typically leaves two persistence artifacts, both of which this tool finds:

1. **A rogue administrator** — several variants seen: `user_login` = `wpsvc_<hex>` / `wp2_<hex>` / `w2s_<hex>`, or an email on an attacker domain (`@wp2shell.*`, `@shellcode.*`, `@wordpress-svc.internal`, `@wordpress-noreply.net`, `@x.lol`), with the `administrator` role. (Note: `@system.local` is a *legit* placeholder admin email on some managed hosts — it is deliberately **not** treated as an IOC.)
2. **A webshell disguised as a plugin** — `wp-content/plugins/<plausible-name>-<6hex>/<same>.php`: a tiny (~1.3 KB) PHP file with a fake `Author: WordPress.org Community` header, gated behind a token, exposing a `?c=<command>` interface.

It also detects the generic case: any small PHP file under `wp-content/` that pipes `$_GET['c']` into a command/eval sink.

## Install

```bash
curl -fsSLO https://raw.githubusercontent.com/InstaWP/wp2shell-scan/main/wp2shell-scan.sh
chmod +x wp2shell-scan.sh
```

Requires `bash`, `find`, `grep`, and a `mysql`/`mariadb` client. [WP‑CLI](https://wp-cli.org) is used when present (cleaner user deletion) but is not required — webshell detection needs no database at all.

## Usage

```bash
# Scan ONE site (read-only)
./wp2shell-scan.sh --path /var/www/example.com

# Scan EVERY WordPress install under a base directory (bulk)
./wp2shell-scan.sh --base /var/www
./wp2shell-scan.sh --base /home            # shared hosting

# Auto-detect common layouts (/var/www/*, /home/*/public_html, ...)
./wp2shell-scan.sh

# Machine-readable
./wp2shell-scan.sh --base /var/www --json > report.json

# CLEAN — quarantine + remove backdoors, rotate wp-config salts (logs everyone out)
./wp2shell-scan.sh --base /var/www --clean --yes
```

Removed artifacts are moved to a **quarantine directory** (not deleted outright) so you keep evidence. Exit code is `1` when compromise is found (scan) or cleaned (clean), `0` when clean — handy for cron/CI.

### Sample output

```
[COMPROMISED] /var/www/example.com  — 2 backdoor admin(s), 2 webshell(s)
      admin: ID=41 wpsvc_2e1487df8abb <wpsvc_2e1487df8abb@wordpress-svc.internal> (2026-07-19 06:41:48)
      webshell: .../wp-content/plugins/security-headers-manager-8d1d21/security-headers-manager-8d1d21.php
[clean] /var/www/other-site.com
----------------------------------------------------------------
scanned=812  clean=811  compromised=1  cleaned=0
```

## After cleaning

`--clean` removes the admin + webshell and rotates salts. **You must still:**

1. **Update WordPress core** to 7.0.2 / 6.9.5 / 6.8.6 (the actual fix).
2. **Reset all admin passwords** and reinstall/verify core + plugins (`wp core verify-checksums`).
3. **Rotate any secrets the site could read** — DB password, API keys, SMTP creds — assume they leaked.
4. **Review what the shell ran** — your access logs record the `?c=` command values.
5. Block the batch route at your edge/origin until every site is patched (`/wp-json/batch/v1`, `?rest_route=/batch/v1`, incl. `%2f`‑encoded). Put it at the **origin** if a CDN might wave the REST path through.

## Check manually (no tool)

Rogue admins:
```sql
SELECT u.ID,u.user_login,u.user_email,u.user_registered
FROM wp_users u JOIN wp_usermeta m ON u.ID=m.user_id
WHERE m.meta_key='wp_capabilities' AND m.meta_value LIKE '%administrator%'
ORDER BY u.user_registered DESC;
```
Webshell plugins:
```bash
find wp-content/plugins -maxdepth 1 -type d -regextype posix-extended -regex '.*-[0-9a-f]{6}$'
grep -rl "\$_GET\['c'\]" wp-content/plugins/
```

## Prefer an AI agent?

See [`CLEANUP-WITH-CLAUDE.md`](./CLEANUP-WITH-CLAUDE.md) for a ready‑to‑paste prompt that drives [Claude Code](https://claude.com/claude-code) (or any capable coding agent) through the same detection and cleanup on a single site, with human confirmation before each destructive step.

## License

MIT — see [LICENSE](./LICENSE). Provided as‑is, no warranty. Built and battle‑tested during a live incident by the team at [InstaWP](https://instawp.com).
