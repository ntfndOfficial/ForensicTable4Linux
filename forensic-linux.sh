#!/usr/bin/env bash
# ForensicTable4Linux - read-only Linux incident-response triage collector
# Version: 1.0.0
set -Eeuo pipefail

VERSION="1.0.0"
OUTPUT=""
SINCE="30 days ago"
INCLUDE_SENSITIVE=0

usage() {
  cat <<'USAGE'
ForensicTable4Linux - Linux forensic triage collector

Usage:
  sudo ./forensic-linux.sh [options]

Options:
  -o, --output DIR          Evidence output directory
      --since TIME          journalctl time range (default: "30 days ago")
      --include-sensitive   Also collect sensitive credential/key stores
  -h, --help                Show this help

Examples:
  sudo ./forensic-linux.sh
  sudo ./forensic-linux.sh -o /mnt/evidence/host01
  sudo ./forensic-linux.sh --since "2026-11-01 00:00:00"
  sudo ./forensic-linux.sh --include-sensitive -o /mnt/secure-evidence/host01

Notes:
  * The collector does not install packages, stop services, or alter source files.
  * Run as root for the broadest collection. Without root, access will be partial.
  * Output may contain sensitive system and user information. Protect it accordingly.
  * RAM acquisition is intentionally not performed; use a dedicated tool such as AVML
    or LiME and write the dump to separate evidence storage.
USAGE
}

while (($#)); do
  case "$1" in
    -o|--output)
      [[ $# -ge 2 ]] || { echo "[!] Missing value for $1" >&2; exit 2; }
      OUTPUT="$2"; shift 2 ;;
    --since)
      [[ $# -ge 2 ]] || { echo "[!] Missing value for $1" >&2; exit 2; }
      SINCE="$2"; shift 2 ;;
    --include-sensitive)
      INCLUDE_SENSITIVE=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "[!] Unknown option: $1" >&2
      usage >&2
      exit 2 ;;
  esac
done

if [[ -z "$OUTPUT" ]]; then
  OUTPUT="./ForensicTable4Linux_$(date -u +%Y%m%dT%H%M%SZ)"
fi

mkdir -p -- "$OUTPUT"
OUTPUT="$(cd -- "$OUTPUT" && pwd -P)"
umask 077
chmod 700 -- "$OUTPUT" 2>/dev/null || true
mkdir -p "$OUTPUT"/{system,users,logs,network,persistence,volatile,filesystem,metadata}
chmod 700 "$OUTPUT"/{system,users,logs,network,persistence,volatile,filesystem,metadata} 2>/dev/null || true

ERROR_LOG="$OUTPUT/metadata/collection-errors.log"
: > "$ERROR_LOG"

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }

copy_path() {
  local src="$1"
  if [[ -e "$src" || -L "$src" ]]; then
    cp -a --parents -- "$src" "$OUTPUT" 2>>"$ERROR_LOG" || \
      printf 'COPY_FAILED %s\n' "$src" >> "$ERROR_LOG"
  fi
}

copy_globs() {
  local pattern item
  for pattern in "$@"; do
    while IFS= read -r -d '' item; do
      copy_path "$item"
    done < <(compgen -G "$pattern" | while IFS= read -r item; do printf '%s\0' "$item"; done || true)
  done
}

capture() {
  local name="$1"; shift
  local rc=0
  {
    printf '# UTC collection time: %s\n' "$(date -u +%FT%TZ)"
    printf '# Command:'
    printf ' %q' "$@"
    printf '\n\n'
    if command -v "$1" >/dev/null 2>&1; then
      "$@" || rc=$?
      printf '\n[exit_status=%s]\n' "$rc"
    else
      printf '[not_available]\n'
    fi
  } > "$OUTPUT/volatile/${name}.txt" 2>&1
}

log "Starting ForensicTable4Linux v${VERSION}"
cat > "$OUTPUT/metadata/collection-info.txt" <<INFO
Tool: ForensicTable4Linux
Version: ${VERSION}
Collection started (UTC): $(date -u +%FT%TZ)
Hostname: $(hostname 2>/dev/null || echo unknown)
Collector user: $(id -un 2>/dev/null || echo unknown)
Effective UID: ${EUID}
Kernel: $(uname -srmo 2>/dev/null || echo unknown)
Journal time range: ${SINCE}
Sensitive collection enabled: ${INCLUDE_SENSITIVE}
Output directory: ${OUTPUT}
INFO

# 1. Host and operating-system configuration
log "Collecting host and OS information"
for f in /etc/os-release /etc/issue /etc/hostname /etc/hosts /etc/fstab \
         /etc/passwd /etc/group /etc/login.defs /etc/shells /etc/machine-id \
         /etc/host.conf /etc/nsswitch.conf /etc/resolv.conf /etc/timezone \
         /etc/localtime /etc/sysctl.conf; do
  copy_path "$f"
done
copy_globs '/etc/sysctl.d/*.conf' '/etc/security/limits.conf' '/etc/security/limits.d/*.conf'

capture system-uname uname -a
capture system-date date --utc --iso-8601=ns
capture system-uptime uptime -a
capture system-hostname hostnamectl status
capture system-boot bootctl status
capture system-block-devices lsblk -a -o NAME,KNAME,TYPE,SIZE,FSTYPE,UUID,MOUNTPOINTS,MODEL,SERIAL
capture system-filesystems findmnt --real --output TARGET,SOURCE,FSTYPE,OPTIONS
capture system-disk-usage df -hT
capture system-users getent passwd
capture system-groups getent group
capture system-login-sessions loginctl list-sessions --no-legend
capture system-loaded-modules lsmod
capture system-kernel-messages dmesg --ctime

# 2. User profiles, shell activity and browser artefacts
log "Collecting user activity and browser artefacts"
while IFS=: read -r username _ uid _ _ home shell; do
  [[ "$home" == /* && -d "$home" ]] || continue
  [[ "$uid" == "0" || "$uid" -ge 1000 ]] || continue
  user_dest="$OUTPUT/users/${username}"
  mkdir -p "$user_dest"
  printf 'username=%s\nuid=%s\nhome=%s\nshell=%s\n' "$username" "$uid" "$home" "$shell" \
    > "$user_dest/account.txt"

  for f in \
    "$home/.bash_history" "$home/.zsh_history" "$home/.local/share/fish/fish_history" \
    "$home/.sh_history" "$home/.ksh_history" "$home/.python_history" \
    "$home/.lesshst" "$home/.viminfo" "$home/.wget-hsts" \
    "$home/.local/share/recently-used.xbel" "$home/.ssh/authorized_keys" \
    "$home/.ssh/known_hosts" "$home/.ssh/config" "$home/.profile" \
    "$home/.bashrc" "$home/.bash_profile" "$home/.zshrc"; do
    if [[ -e "$f" || -L "$f" ]]; then
      cp -a --parents -- "$f" "$user_dest" 2>>"$ERROR_LOG" || true
    fi
  done

  for d in "$home/.config/autostart" "$home/.config/systemd/user"; do
    if [[ -d "$d" ]]; then
      cp -a --parents -- "$d" "$user_dest" 2>>"$ERROR_LOG" || true
    fi
  done

  # Browser history/bookmark databases only; cookies and saved-password stores are excluded.
  for browser_root in \
    "$home/.mozilla/firefox" "$home/.config/google-chrome" "$home/.config/chromium" \
    "$home/.var/app/org.mozilla.firefox/.mozilla/firefox" \
    "$home/.var/app/com.google.Chrome/config/google-chrome" \
    "$home/.var/app/org.chromium.Chromium/config/chromium"; do
    if [[ -d "$browser_root" ]]; then
      while IFS= read -r -d '' f; do
        cp -a --parents -- "$f" "$user_dest" 2>>"$ERROR_LOG" || true
      done < <(find "$browser_root" -type f \( -name places.sqlite -o -name History -o -name Bookmarks \) -print0 2>/dev/null)
    fi
  done

  if (( INCLUDE_SENSITIVE )); then
    for f in "$home"/.ssh/id_* "$home"/.gnupg "$home"/.local/share/keyrings \
             "$home"/.config/gh/hosts.yml "$home"/.aws "$home"/.kube/config; do
      [[ -e "$f" || -L "$f" ]] && cp -a --parents -- "$f" "$user_dest" 2>>"$ERROR_LOG" || true
    done
  fi
done < /etc/passwd

# 3. Logs and event records
log "Collecting system and application logs"
for f in \
  /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages \
  /var/log/kern.log /var/log/boot.log /var/log/daemon.log \
  /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/faillog \
  /var/log/audit/audit.log /var/log/apt/history.log /var/log/apt/term.log \
  /var/log/dpkg.log /var/log/yum.log /var/log/dnf.log /var/log/pacman.log \
  /var/log/ufw.log /var/log/fail2ban.log /var/log/clamav/clamav.log; do
  copy_path "$f"
done
copy_globs '/var/log/auth.log.*' '/var/log/secure-*' '/var/log/syslog.*' \
  '/var/log/messages-*' '/var/log/kern.log.*' '/var/log/audit/audit.log.*' \
  '/var/log/apt/history.log.*' '/var/log/dpkg.log.*' '/var/log/nginx/*.log*' \
  '/var/log/apache2/*.log*' '/var/log/httpd/*.log*'

capture journal-system journalctl --utc --no-pager --since "$SINCE" --output=short-iso
capture journal-export journalctl --utc --no-pager --since "$SINCE" --output=export
capture log-last-logins last -Faiwx
capture log-failed-logins lastb -Faiwx
capture log-audit-status auditctl -s
capture log-audit-recent ausearch -ts recent
capture log-kernel-ring dmesg --time-format iso

# 4. Persistence and execution traces
log "Collecting persistence mechanisms and execution traces"
for f in /etc/crontab /etc/anacrontab /etc/rc.local /etc/ld.so.preload \
         /etc/sudoers /etc/ssh/sshd_config /etc/pam.conf; do
  copy_path "$f"
done
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly \
         /etc/cron.monthly /etc/cron.yearly /etc/cron.hourly /etc/cron.daily \
         /etc/cron.monthly /etc/cron.weekly /etc/cron.yearly \
         /etc/systemd/system /etc/systemd/user /etc/init.d /etc/rc.d \
         /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d \
         /etc/rc6.d /etc/udev/rules.d /etc/modules-load.d /etc/modprobe.d \
         /etc/profile.d /etc/sudoers.d /etc/pam.d /var/spool/cron /var/spool/cron/crontabs; do
  [[ -d "$d" ]] && cp -a --parents -- "$d" "$OUTPUT/persistence" 2>>"$ERROR_LOG" || true
done
copy_globs '/etc/at.allow' '/etc/at.deny' '/var/spool/at/*' '/etc/systemd/system/*.wants/*'

capture persistence-systemd-units systemctl list-unit-files --no-pager
capture persistence-systemd-services systemctl list-units --type=service --all --no-pager
capture persistence-systemd-timers systemctl list-timers --all --no-pager
capture persistence-systemd-failed systemctl --failed --no-pager
capture persistence-crontab-current crontab -l
capture persistence-crontab-root crontab -u root -l
capture persistence-atq atq
capture persistence-suid find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt -xdev -type f -perm /6000 -printf '%m %u:%g %TY-%Tm-%TdT%TH:%TM:%TS %p\n'
capture persistence-capabilities getcap -r /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt
capture persistence-kernel-modules find "/lib/modules/$(uname -r)" -type f \( -name '*.ko' -o -name '*.ko.xz' -o -name '*.ko.zst' \) -printf '%p\n'

# Package manager databases/logs help establish installed and recently changed software.
capture packages-dpkg dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n'
capture packages-rpm rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME:date}\n'
capture packages-pacman pacman -Q
capture packages-flatpak flatpak list --app
capture packages-snap snap list

# 5. Network state and remote-access traces
log "Collecting network state"
for f in /etc/hosts /etc/resolv.conf /etc/hostname /etc/NetworkManager/NetworkManager.conf \
         /etc/ssh/sshd_config /etc/ssh/ssh_config; do
  copy_path "$f"
done
copy_globs '/etc/NetworkManager/conf.d/*.conf' '/etc/netplan/*.yaml' '/etc/netplan/*.yml' \
  '/etc/wireguard/*.conf' '/etc/iptables/*' '/etc/nftables.conf' '/etc/ufw/*.rules'

capture network-ip-address ip -details address show
capture network-routes ip route show table all
capture network-neighbors ip neigh show
capture network-sockets ss -tulpna
capture network-sockets-process ss -tpna
capture network-listeners lsof -nP -i
capture network-arp arp -an
capture network-mounts mount
capture network-smb-sessions smbstatus -b
capture network-nmcli nmcli -f NAME,UUID,TYPE,DEVICE connection show
capture network-resolved resolvectl status
capture network-firewall-nft nft list ruleset
capture network-firewall-iptables iptables-save
capture network-firewall-ip6tables ip6tables-save
capture network-firewall-ufw ufw status verbose
capture network-conntrack conntrack -L

# 6. USB and externally attached devices
log "Collecting USB and device information"
capture devices-lsusb lsusb
capture devices-usb-tree lsusb -t
capture devices-usb-devices usb-devices
capture devices-udevadm udevadm info --export-db
capture devices-blkid blkid
capture devices-mounts findmnt --real
capture devices-journal journalctl --utc --no-pager --since "$SINCE" --grep='usb|udisks|mount|block' --output=short-iso

# 7. Filesystem, deleted-file and malware/exploitation traces
log "Collecting filesystem metadata and volatile locations"
capture filesystem-tmp-metadata find /tmp /var/tmp /dev/shm -xdev -type f -printf '%M\t%u:%g\t%s\t%TY-%Tm-%TdT%TH:%TM:%TS\t%p\n'
capture filesystem-tmp-hashes find /tmp /var/tmp /dev/shm -xdev -type f -exec sha256sum -- {} +
capture filesystem-core-dumps coredumpctl list --no-pager
capture filesystem-extended-attributes getfattr -R -d -m- /etc /usr/local /opt
capture filesystem-acls getfacl -R -p /etc /usr/local /opt
capture filesystem-open-files lsof -nP

# Linux has no Recycle Bin/ADS equivalent. Desktop Trash metadata is collected per-user above.
# Collect core-dump and crash-report metadata without copying potentially huge dump contents.
for d in /var/lib/systemd/coredump /var/crash; do
  if [[ -d "$d" ]]; then
    find "$d" -xdev -type f -printf '%M\t%u:%g\t%s\t%TY-%Tm-%TdT%TH:%TM:%TS\t%p\n' \
      >> "$OUTPUT/filesystem/core-dump-metadata.txt" 2>>"$ERROR_LOG" || true
  fi
done

# 8. Authentication and encryption configuration (secret stores are opt-in)
log "Collecting authentication and encryption artefacts"
for f in /etc/pam.d /etc/security /etc/krb5.conf \
         /etc/sudoers /etc/sudoers.d /etc/ssh/ssh_config /etc/ssh/sshd_config \
         /etc/ssl/openssl.cnf; do
  [[ -e "$f" || -L "$f" ]] && cp -a --parents -- "$f" "$OUTPUT/system" 2>>"$ERROR_LOG" || true
done
capture auth-current-user id
capture auth-who who -a
capture auth-w last -Faiwx
capture auth-sudoers visudo -c
capture auth-sshd-effective sshd -T

if (( INCLUDE_SENSITIVE )); then
  log "Sensitive collection explicitly enabled"
  mkdir -p "$OUTPUT/sensitive"
  for f in /etc/shadow /etc/gshadow /etc/krb5.keytab; do
    if [[ -e "$f" || -L "$f" ]]; then
      cp -a --parents -- "$f" "$OUTPUT/sensitive" 2>>"$ERROR_LOG" || true
    fi
  done
  for d in /etc/ssh /etc/ssl/private /etc/NetworkManager/system-connections \
           /etc/wireguard /root/.gnupg /root/.local/share/keyrings; do
    [[ -e "$d" ]] && cp -a --parents -- "$d" "$OUTPUT/sensitive" 2>>"$ERROR_LOG" || true
  done
  # Keep the sensitive subtree inaccessible to other local users.
  chmod -R go-rwx "$OUTPUT/sensitive" 2>/dev/null || true
fi

# 9. Runtime process and container state
log "Collecting runtime process and container state"
capture runtime-processes ps auxwwf
capture runtime-process-tree pstree -ap
capture runtime-open-files lsof -nP
capture runtime-proc-mounts cat /proc/mounts
capture runtime-proc-modules cat /proc/modules
capture runtime-docker docker ps -a --no-trunc
capture runtime-podman podman ps -a --no-trunc
capture runtime-crictl crictl ps -a

# 10. File inventory and integrity hashes
log "Building file inventory and SHA-256 manifest"
{
  printf 'path\ttype\tmode\towner\tgroup\tsize\tmtime\n'
  find "$OUTPUT" -xdev -type f ! -path "$OUTPUT/metadata/file-inventory.tsv" \
    -printf '%p\tfile\t%m\t%u\t%g\t%s\t%TY-%Tm-%TdT%TH:%TM:%TS\n' 2>/dev/null
} > "$OUTPUT/metadata/file-inventory.tsv"

cat > "$OUTPUT/README-EVIDENCE.txt" <<INFO
ForensicTable4Linux evidence collection
=======================================
Tool version: ${VERSION}
Collection completed (UTC): $(date -u +%FT%TZ)
Hostname: $(hostname 2>/dev/null || echo unknown)
Journal range: ${SINCE}
Sensitive collection: ${INCLUDE_SENSITIVE}

Directory map:
  system/       OS and authentication configuration files
  users/        selected per-user shell, browser history and activity artefacts
  logs/         copied conventional log files
  persistence/  cron, systemd, init, udev and related persistence artefacts
  network/      reserved for network artefacts; command output is under volatile/
  volatile/     command output and point-in-time runtime state
  filesystem/   temporary-file metadata, hashes and crash-dump metadata
  metadata/     collector details, errors, inventory and integrity information
  sensitive/    created only when --include-sensitive is selected

Important:
- Collection is best-effort and depends on privileges, distribution and installed tools.
- A missing file or command output does not prove that the artefact never existed.
- Browser cookies, browser saved-password databases and private user SSH keys are excluded
  unless --include-sensitive is selected (private keys are not copied for every possible
  application-specific location).
- This is a triage collector, not a forensic disk imager or RAM acquisition utility.
- Preserve the original host state and document chain of custody separately.
INFO

# Hash all collected files except the manifest itself. Paths are relative to the evidence root.
(
  cd "$OUTPUT"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 -r sha256sum
) > "$OUTPUT/SHA256SUMS" 2>>"$ERROR_LOG"

cat >> "$OUTPUT/metadata/collection-info.txt" <<INFO
Collection completed (UTC): $(date -u +%FT%TZ)
Collected regular files: $(find "$OUTPUT" -type f | wc -l | tr -d ' ')
SHA256 manifest: ${OUTPUT}/SHA256SUMS
INFO

log "Collection completed: $OUTPUT"
printf '\n[+] Evidence directory: %s\n' "$OUTPUT"
printf '[+] SHA-256 manifest: %s/SHA256SUMS\n' "$OUTPUT"
printf '[!] Review metadata/collection-errors.log for files that could not be accessed or copied.\n'
