#!/bin/sh
# Lavoisier target entrypoint: deterministic lab bootstrap (AUTHORIZED LAB ONLY).
set -eu

FLAG_USER="5f1ec9bb31ae4c7db02a7fa4e91d33c8"
FLAG_ROOT="9c2d44af71e05b83ac6d94f20b1e77aa"
DEV_HASH='$6$lavoisier$mkgZ5Vb2q.OukqoLWiwkdLZ2RlzV/rZ7Wdlfh3w4A5is0eCiK1tu5CyHW1Ei8s/xNKaRiHFpBdG6j7c614UD70'

# --- Accounts ---------------------------------------------------------------
addgroup -S devops 2>/dev/null || true
adduser -D -s /bin/sh developer 2>/dev/null || true
addgroup developer devops 2>/dev/null || true
echo "developer:${DEV_HASH}" | chpasswd -e
echo "root:LavoisierRoot2024!" | chpasswd

# --- Flags ------------------------------------------------------------------
echo "$FLAG_USER" > /home/developer/user.txt
chown developer:developer /home/developer/user.txt
chmod 644 /home/developer/user.txt
echo "$FLAG_ROOT" > /root/proof.txt
chmod 600 /root/proof.txt

# --- Privilege escalation vector --------------------------------------------
# Root-owned maintenance script, writable by the 'devops' group, and allowed
# passwordless via sudo. developer is a devops member -> arbitrary root code.
cat > /usr/local/bin/vault-report.sh <<'EOF'
#!/bin/sh
echo "== Lavoisier vault integrity report =="
ls -la /var/vault
EOF
chown root:devops /usr/local/bin/vault-report.sh
chmod 0775 /usr/local/bin/vault-report.sh
# Append directly to /etc/sudoers: alpine's stock sudoers does not reliably
# @include sudoers.d, and this vector must exist after every rebuild.
cp /etc/sudoers /etc/sudoers.bak
echo "developer ALL=(root) NOPASSWD: /usr/local/bin/vault-report.sh" >> /etc/sudoers
mkdir -p /var/vault
echo "archive-index 2024-11-02: nominal" > /var/vault/index.txt

# --- Services ---------------------------------------------------------------
mkdir -p /run/sshd /var/log/vsftpd /usr/share/empty
ssh-keygen -A >/dev/null 2>&1
/usr/sbin/sshd -f /etc/ssh/sshd_config

/usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf &

python3 /opt/lavoisier/http_app.py &
python3 /opt/lavoisier/vault_sync.py &

echo "[lavoisier-target] all services up: ftp/21 ssh/22 http/8080 vault-sync/31337"
exec tail -f /dev/null
