FROM alpine:3.20

RUN apk add --no-cache \
        openssh-server \
        openssh-sftp-server \
        vsftpd \
        sudo \
        python3 \
        tar

COPY target/http_app.py /opt/lavoisier/http_app.py
COPY target/vault_sync.py /opt/lavoisier/vault_sync.py
COPY target/backup_source/ /opt/lavoisier/backup_source/
COPY target/ftp_root/ /srv/ftp/
COPY target/sshd_config /etc/ssh/sshd_config
COPY target/vsftpd.conf /etc/vsftpd/vsftpd.conf
COPY target/healthcheck.py /opt/lavoisier/healthcheck.py
COPY target/entrypoint.sh /entrypoint.sh

RUN chmod 0755 /entrypoint.sh /opt/lavoisier/http_app.py /opt/lavoisier/vault_sync.py

EXPOSE 21 22 8080 31337

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
    CMD ["python3", "/opt/lavoisier/healthcheck.py"]

ENTRYPOINT ["/entrypoint.sh"]
