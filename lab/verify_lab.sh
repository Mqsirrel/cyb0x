#!/usr/bin/env bash
# Black-box integrity verification of the Lavoisier lab (AUTHORIZED LAB ONLY).
#
# Requires: docker compose v2, curl, tar, uv (for the TCP-banner probe).
# Usage:    ./verify_lab.sh          # assumes the stack is up
set -uo pipefail

HOST=127.0.0.1
HTTP="$HOST:8080"
PASS=0; FAIL=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

wait_port() { # wait_port <port> <label>
  local i
  for i in $(seq 1 30); do
    (exec 3<>"/dev/tcp/$HOST/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
    sleep 1
  done
  return 1
}

for spec in "2121:ftp" "2222:ssh" "8080:http" "31337:vault-sync"; do
  p="${spec%%:*}"; name="${spec##*:}"
  wait_port "$p" && ok "$name port $p open" || bad "$name port $p never opened"
done

# 5. HTTP recon breadcrumbs
curl -sf "http://$HTTP/robots.txt" | grep -q "/backups/" \
  && ok "robots.txt discloses /backups/" || bad "robots.txt missing /backups/"

# 3a. Admin credential trap dead-ends at the MFA wall
curl -sf -X POST --data "user=admin&pass=LavoisierAdmin2024!" "http://$HTTP/admin/login" \
  | grep -q "MFA enrollment required" \
  && ok "admin default creds hit MFA wall (dead end)" || bad "admin trap not armed"

# 3b. Backup misconfiguration leaks credentials (the intended vuln)
curl -sf "http://$HTTP/backups/site-backup.tar.gz" -o "$TMP/site-backup.tar.gz" \
  && tar -xzf "$TMP/site-backup.tar.gz" -C "$TMP" 2>/dev/null \
  && grep -q "^developer: s3cr3t_dev$" "$TMP/config/db_credentials.txt" \
  && ok "/backups/ archive leaks developer:s3cr3t_dev" \
  || bad "backup leak not exploitable"

# 1. Anonymous FTP decoy is readable and worthless
curl -sf --user "anonymous:lavoisier@lab.invalid" "ftp://$HOST:2121/welcome.txt" \
  | grep -q "retired" \
  && ok "anonymous FTP reachable and retired (dead end)" || bad "anonymous FTP broken"

# 2. Vault-sync decoy: token-only auth rejects harvested passwords
uv run python - <<'PY' && ok "vault-sync rejects harvested creds (dead end)" || bad "vault-sync behavior wrong"
import socket
s = socket.create_connection(("127.0.0.1", 31337), timeout=3)
banner = s.makefile().readline()
assert b"VAULT-SYNC" in banner and b"DISABLED" in banner, banner
s.sendall(b"AUTH Arch1ve_R3ader!\n")
resp = s.makefile().readline()
assert b"account locked" in resp or b"token required" in resp, resp
PY

# 5b. Harvested developer password authenticates on SSH (verified in-container)
docker compose exec -T target python3 - <<'PY' && ok "developer:s3cr3t_dev valid for SSH" || bad "SSH credential invalid"
import crypt, pwd, spwd
entry = spwd.getspnam("developer")
assert entry.sp_pwdp == crypt.crypt("s3cr3t_dev", entry.sp_pwdp), "hash mismatch"
assert pwd.getpwnam("developer").pw_gid != 0
PY

# Foothold evidence exists with the deterministic constant
docker compose exec -T target cat /home/developer/user.txt 2>/dev/null | grep -qx "5f1ec9bb31ae4c7db02a7fa4e91d33c8" \
  && ok "user.txt flag present" || bad "user.txt wrong or unreadable"

# 6. Privesc vector: devops-writable root script allowed via sudo
docker compose exec -T -u developer target sh -c \
  '[ -w /usr/local/bin/vault-report.sh ] && sudo -n /usr/local/bin/vault-report.sh | grep -q "integrity report"' \
  && ok "privesc vector live (group-writable sudo script)" || bad "privesc vector not armed"

# Root proof exists and is root-only
docker compose exec -T target sh -c \
  '[ "$(stat -c %a /root/proof.txt)" = "600" ] && head -1 /root/proof.txt | grep -qx "9c2d44af71e05b83ac6d94f20b1e77aa"' \
  && ok "proof.txt flag present (root-only)" || bad "proof.txt missing or world-readable"

echo "----------------------------------------"
echo "verify_lab: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
