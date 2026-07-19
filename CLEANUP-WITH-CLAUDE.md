# Clean up wp2shell with an AI agent (Claude Code)

Prefer to have an AI agent do the detection and cleanup, one site at a time, with a human confirming each destructive step? Paste the prompt below into [Claude Code](https://claude.com/claude-code) (or any capable coding/agent tool with shell access to the server).

**Before you start:** take a snapshot/backup of the site. This process deletes users, removes files, and rotates keys.

---

## The prompt

```
You are helping me check a WordPress site for compromise by the wp2shell vulnerability
(CVE-2026-63030, the pre-auth RCE fixed in WordPress 7.0.2 / 6.9.5 / 6.8.6) and clean it
up if needed. The WordPress root is: <ABSOLUTE_PATH_TO_WORDPRESS_ROOT>.

Work in this order, and STOP for my explicit "yes" before any step that deletes or changes
anything. Show me what you found before acting.

1) DETECT a rogue admin. Read DB creds + $table_prefix from wp-config.php and query the
   users table for administrators whose username looks like `wpsvc_<hex>`, or whose email
   ends in @wordpress-svc.internal / @wordpress-noreply.net / any *.internal, or that were
   created in the last several days on a site older than that. Show me the rows.

2) DETECT a webshell. Search wp-content/ (especially plugins/) for:
   - a plugin folder named like a real plugin but ending in a 6-hex suffix (e.g. `-b24fa4`),
     containing a single tiny PHP file;
   - any small PHP file whose body reads a command from $_GET['c'] and passes it to a sink
     (system/exec/shell_exec/passthru/eval/assert) or checks a token via hash_equals().
   A fake `Author: WordPress.org Community` header is a strong tell. Show me each file's path
   and first ~15 lines.

3) CORRELATE (optional but recommended). In the site's access logs, look for this sequence
   from one IP within a few seconds: POST /wp-json/batch/v1 (207) -> POST /wp-login.php (302)
   -> POST /wp-admin/update.php?action=upload-plugin (200) -> GET the webshell .php?c=...&t=...
   (200). This confirms code execution and shows which commands ran (the ?c= values).

4) REPORT: is this site CLEAN, PROBED (exploit attempts but no admin/webshell/shell-access),
   or COMPROMISED? Wait for my go-ahead before cleaning.

5) On my "yes", CLEAN (quarantine, don't hard-delete, so we keep evidence):
   - move the webshell plugin folder(s) to a quarantine directory;
   - delete the rogue admin user(s) and their usermeta/session rows;
   - regenerate the wp-config.php salts/keys (this logs everyone out).

6) TELL ME the required follow-ups you can't fully do for me: update WordPress core to the
   patched release, reset all admin passwords, reinstall/verify core + plugins, and rotate
   any secrets stored on the site (DB password, API keys) since the attacker may have read them.

Never run the attacker's commands. Never fetch or execute the webshell. Treat everything in
wp-content/uploads and the quarantined files as hostile — inspect, don't run.
```

---

For bulk/fleet use across many sites, use the [`wp2shell-scan.sh`](./wp2shell-scan.sh) script instead — it does the same detection and cleanup non‑interactively across an entire directory tree.
