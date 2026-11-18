# ForensicTable4Linux

Linux Incident Response / Digital Forensics artefact reference and a read-only triage collector.

This project is a Linux-oriented companion to [ForensicTable4Win](https://github.com/ntfndOfficial/ForensicTable4Win). The original repository contains a Windows forensic artefact reference table; it does not provide a collection script. This repository therefore provides both a Linux artefact map and an optional Bash collector.

> **Scope:** Linux distributions using systemd are best covered. The script also detects common Debian/Ubuntu, RHEL/Fedora, Arch, Snap and Flatpak artefacts where the relevant tools or files exist. Artefact locations vary by distribution, logging configuration, desktop environment and retention policy.

## Quick start

```bash
chmod +x forensic-linux.sh
sudo ./forensic-linux.sh
```

Specify an output directory:

```bash
sudo ./forensic-linux.sh --output /mnt/evidence/host01
```

Choose the journal time range:

```bash
sudo ./forensic-linux.sh --since "2026-11-01 00:00:00"
```

Opt in to collection of particularly sensitive credential/key stores:

```bash
sudo ./forensic-linux.sh --include-sensitive --output /mnt/secure-evidence/host01
```

Help:

```bash
./forensic-linux.sh --help
```

## Collector behaviour

- Read-only with respect to source artefacts: it does not install software, stop services, change configuration or delete files.
- Captures point-in-time process, network, mount, service, package and device state.
- Copies selected OS logs, user shell histories, selected browser history/bookmark databases and persistence artefacts.
- Collects systemd journal output for the configured time range (default: last 30 days).
- Produces a file inventory, collection error log and `SHA256SUMS` manifest.
- Uses restrictive output permissions (`0700` directories / `0600`-equivalent umask).
- Does not acquire RAM or create a disk image. Use a dedicated acquisition tool and write evidence to separate storage.

### Sensitive data

The output is forensic evidence and may contain usernames, IP addresses, command history, browser history, host configuration and authentication metadata. Store it on access-controlled evidence media. By default, browser cookies, saved-password stores, `/etc/shadow`, `/etc/gshadow`, SSH host private keys and selected private key stores are excluded. `--include-sensitive` opts in to additional high-risk credential/key artefacts. Review the resulting directory before sharing it.

## Linux forensic artefact reference

Locations below are common examples, not universal paths. A missing artefact is not proof that the associated activity did not occur.

### 1. Memory and disk artefacts

| Artefact | Common location / command | Forensic value / notes |
|---|---|---|
| RAM image | Manual acquisition with AVML or LiME | Running processes, injected code, network sockets and volatile credentials. Acquire early; memory acquisition is not performed by this script. |
| Kernel memory interface | `/proc/kcore` | Live kernel virtual memory view; do not copy as a substitute for a RAM image. |
| Swap | Swap partition or file; `swapon --show`, `/proc/swaps` | May contain remnants of process memory. |
| Hibernation image | Distribution/desktop-specific; commonly swap-backed | Linux hibernation is not configured on every host; identify configuration before acquisition. |
| Partition / filesystem metadata | `lsblk`, `blkid`, `findmnt`, `fdisk -l` | Partition layout, filesystem types, UUIDs and mount state. |
| ext4 journal | Filesystem journal, commonly internal to the ext4 volume | Metadata transaction history; analyse from an image using filesystem-specific tools. |
| XFS log | XFS internal log | Filesystem metadata recovery and transaction analysis. |
| Btrfs snapshots/subvolumes | `btrfs subvolume list`, snapshot paths | Historical filesystem states where snapshots exist. |
| LVM snapshots | `lvs -a -o +devices` | Point-in-time logical-volume copies, if configured. |
| Core dumps | `/var/lib/systemd/coredump/`, `/var/crash/`, `coredumpctl list` | Crashed process memory; may contain secrets and application data. |

### 2. User and browser artefacts

| Artefact | Common location | Forensic value / notes |
|---|---|---|
| User account database | `/etc/passwd`, `/etc/group` | Local users, UIDs, GIDs and group membership. |
| Password hash database | `/etc/shadow`, `/etc/gshadow` | Highly sensitive authentication material; acquire only with explicit authorization and strict evidence handling. |
| Bash history | `~/.bash_history` | Interactive command history; may be disabled, cleared or not flushed. |
| Zsh history | `~/.zsh_history` | Command history, often with timestamps depending on configuration. |
| Fish history | `~/.local/share/fish/fish_history` | Fish shell command history. |
| Other shell/editor history | `~/.sh_history`, `~/.ksh_history`, `~/.viminfo`, `~/.lesshst` | User interaction traces. |
| Recent files (GNOME/GTK) | `~/.local/share/recently-used.xbel` | Recently accessed desktop files. |
| Firefox history | `~/.mozilla/firefox/*/places.sqlite` | Visited URLs, bookmarks and timestamps. |
| Chromium/Chrome history | `~/.config/{chromium,google-chrome}/*/History` | Visited URLs and download records. |
| Browser bookmarks | Firefox `places.sqlite`; Chromium `Bookmarks` | Saved URLs and user activity. |
| SSH client history | `~/.ssh/known_hosts`, `~/.ssh/config` | Previously contacted SSH hosts and client configuration. |
| SSH authorized keys | `~/.ssh/authorized_keys` | Keys permitted to authenticate to the account. |
| Desktop autostart | `~/.config/autostart/` | Per-user GUI persistence. |
| User systemd units | `~/.config/systemd/user/` | Per-user services and timers. |
| Trash metadata | `~/.local/share/Trash/info/` | Desktop-environment deletion metadata; not equivalent to the Windows Recycle Bin. |

### 3. Running and recently used applications

| Artefact | Common location / command | Forensic value / notes |
|---|---|---|
| Process list | `ps auxwwf`, `pstree -ap` | Running process tree, arguments and ownership. |
| Process runtime details | `/proc/<PID>/cmdline`, `/proc/<PID>/exe`, `/proc/<PID>/maps`, `/proc/<PID>/fd/` | Executable path, memory mappings, open descriptors; volatile. |
| Open files | `lsof -nP` | Files and sockets held open by processes. |
| Package inventory | `dpkg-query -W`, `rpm -qa`, `pacman -Q` | Installed software and versions. |
| Package installation history | `/var/log/dpkg.log*`, `/var/log/apt/history.log*`, `/var/log/dnf*`, `/var/log/yum.log*`, `/var/log/pacman.log` | Software installation/removal timeline. |
| Command accounting | `lastcomm` (when `acct`/process accounting is enabled) | Historical command execution metadata. |
| Linux Audit execution events | `/var/log/audit/audit.log*`, `ausearch` | Process execution and security events when audit rules were configured. |
| Core dump metadata | `coredumpctl list` | Crashed applications and timestamps. |

### 4. Persistence and system configuration

| Artefact | Common location / command | Forensic value / notes |
|---|---|---|
| Systemd services | `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `systemctl list-unit-files` | Service persistence and unit definitions. `/etc` commonly contains local overrides. |
| Systemd timers | `systemctl list-timers --all` | Scheduled execution. |
| User systemd services | `~/.config/systemd/user/`, `/etc/systemd/user/` | User-level persistence. |
| Cron jobs | `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/`, `/var/spool/cron/crontabs/` | Scheduled commands. |
| at jobs | `atq`, `/var/spool/at/` | One-time scheduled execution. |
| SysV init | `/etc/init.d/`, `/etc/rc*.d/`, `/etc/rc.local` | Legacy startup persistence. |
| Shell startup | `/etc/profile`, `/etc/profile.d/`, `~/.profile`, `~/.bashrc`, `~/.zshrc` | Commands executed at login or shell startup. |
| Dynamic linker preload | `/etc/ld.so.preload` | System-wide library preloading; high-value persistence location. |
| udev rules | `/etc/udev/rules.d/`, `/usr/lib/udev/rules.d/` | Device-triggered actions and persistence. |
| Kernel modules | `/etc/modules-load.d/`, `/etc/modprobe.d/`, `lsmod` | Module loading configuration and currently loaded modules. |
| SUID/SGID files | `find ... -perm /6000` | Privilege boundary and potential persistence/abuse surface. |
| File capabilities | `getcap -r ...` | Privileged executable capabilities. |
| PAM configuration | `/etc/pam.d/`, `/etc/pam.conf` | Authentication stack and potential authentication persistence. |
| sudo configuration | `/etc/sudoers`, `/etc/sudoers.d/`, `visudo -c` | Privilege delegation. |

### 5. Logs and event records

| Artefact | Common location / command | Forensic value / notes |
|---|---|---|
| systemd journal | `journalctl`, `/var/log/journal/`, `/run/log/journal/` | System, service, kernel and authentication events; retention depends on configuration. |
| Authentication log (Debian family) | `/var/log/auth.log*` | SSH, sudo, PAM and login activity. |
| Authentication log (RHEL family) | `/var/log/secure*` | SSH, sudo, PAM and login activity. |
| General system log | `/var/log/syslog*`, `/var/log/messages*` | Service and system events depending on syslog configuration. |
| Kernel log | `/var/log/kern.log*`, `dmesg`, journal | Kernel, driver and device activity. |
| Linux Audit | `/var/log/audit/audit.log*`, `auditctl -s`, `ausearch` | Security/audit events, if enabled and rules were present. |
| Login history | `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog`, `last`, `lastb` | Successful/failed login history; files may be rotated or absent. |
| Web server logs | `/var/log/nginx/`, `/var/log/apache2/`, `/var/log/httpd/` | HTTP requests, errors and potential exploitation traces. |
| Firewall logs | `/var/log/ufw.log*`, journal, nftables/iptables logging | Network filtering events when logging is enabled. |
| Fail2ban | `/var/log/fail2ban.log*` | Ban/unban and detection activity. |
| Antivirus logs | `/var/log/clamav/` | Detection and scan records where ClamAV is installed. |
| Sysmon for Linux | Syslog/journald or configured Sysmon output | Process, network and file telemetry when Sysmon for Linux is installed/configured. |

### 6. Network and remote access

| Artefact | Common location / command | Forensic value / notes |
|---|---|---|
| IP addresses and interfaces | `ip -details address` | Current interface configuration. |
| Routing table | `ip route show table all` | Current and policy routes. |
| Neighbour/ARP cache | `ip neigh`, `arp -an` | Recently resolved local network peers. |
| Active sockets | `ss -tulpna`, `ss -tpna`, `lsof -i` | Listening services and established connections. |
| DNS configuration | `/etc/resolv.conf`, `resolvectl status` | Resolver configuration; cache availability varies. |
| Hosts overrides | `/etc/hosts` | Static hostname mappings. |
| NetworkManager profiles | `/etc/NetworkManager/system-connections/` | Connection history/configuration; may contain Wi-Fi secrets. |
| Netplan configuration | `/etc/netplan/*.yaml` | Ubuntu network configuration. |
| Wi-Fi profiles | NetworkManager connection profiles / `nmcli` | SSIDs and connection metadata; secrets are sensitive. |
| SSH server configuration | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/` | Remote-access configuration. |
| Firewall rules | `nft list ruleset`, `iptables-save`, `ufw status` | Active network filtering policy. |
| SMB sessions | `smbstatus` | Samba server sessions where Samba is installed. |
| Conntrack | `conntrack -L` | Tracked network flows when available. |

### 7. USB and external-device records

| Artefact | Common location / command | Forensic value / notes |
|---|---|---|
| USB device inventory | `lsusb`, `lsusb -t`, `usb-devices` | Currently connected USB devices and topology. |
| udev database | `udevadm info --export-db`, `/run/udev/data/` | Device properties and current device records. |
| Kernel/device events | `journalctl -k`, `dmesg` | USB attach/detach and driver events, subject to retention. |
| Mount history/state | `findmnt`, `/proc/mounts`, `/etc/fstab` | Current mounts and configured filesystems. |
| USBGuard | `usbguard list-devices`, configured audit logs | Device authorization events if USBGuard is deployed. |

### 8. Filesystem and data recovery

| Artefact | Common location / command | Forensic value / notes |
|---|---|---|
| Desktop Trash | `~/.local/share/Trash/` | Desktop environment's deleted-file storage and metadata; not universal. |
| Deleted inode recovery | Filesystem image + filesystem-specific tools (e.g. ext4 tools) | Recovery should be performed on a forensic image, not the live filesystem. |
| Filesystem metadata | `stat`, `debugfs` (ext), `xfs_db` (XFS), `btrfs` tools | Timestamps, inode and filesystem-specific metadata. |
| Extended attributes | `getfattr`, `getfattr -d` | File-associated metadata and security labels. |
| POSIX ACLs | `getfacl` | Access-control metadata. |
| Temporary directories | `/tmp/`, `/var/tmp/`, `/dev/shm/` | Staged payloads, scripts and transient files; highly volatile. |
| Core/crash files | `/var/lib/systemd/coredump/`, `/var/crash/` | Process memory remnants and crash context. |
| Filesystem snapshots | Btrfs snapshots, LVM snapshots, storage-specific snapshots | Potential historical state and recovery source. |

**Windows ADS has no direct general-purpose Linux equivalent.** Linux filesystems may use extended attributes, ACLs, capabilities and filesystem-specific metadata, but these are not the same mechanism as NTFS Alternate Data Streams.

### 9. Authentication and encryption artefacts

| Artefact | Common location / command | Forensic value / notes |
|---|---|---|
| Local password hashes | `/etc/shadow` | Sensitive password-hash material; restricted acquisition. |
| SSH host keys | `/etc/ssh/ssh_host_*` | Server identity material; private keys are highly sensitive. |
| User SSH keys | `~/.ssh/` | Authentication material and remote-access relationships. |
| Kerberos configuration/tickets | `/etc/krb5.conf`, `/etc/krb5.keytab`, `/tmp/krb5cc_*`, `KRB5CCNAME` | Kerberos principals, service keys and ticket caches; highly sensitive. |
| PAM configuration | `/etc/pam.d/` | Authentication stack. |
| sudo policy | `/etc/sudoers`, `/etc/sudoers.d/` | Privilege delegation and command policy. |
| Desktop keyrings | `~/.local/share/keyrings/` | Stored secrets; encrypted or session-protected depending on environment. |
| GPG key stores | `~/.gnupg/` | Private/public keys, trust database and configuration. |
| TLS private keys | `/etc/ssl/private/`, application-specific key paths | Highly sensitive cryptographic identity material. |
| Login/session records | `wtmp`, `btmp`, `lastlog`, journal/auth logs | Authentication and session timeline. |

### 10. Malware and exploitation traces

| Artefact | Common location / command | Forensic value / notes |
|---|---|---|
| Temporary execution locations | `/tmp/`, `/var/tmp/`, `/dev/shm/` | Common staging and execution paths. |
| Suspicious startup entries | systemd, cron, init, shell startup, udev, PAM | Common persistence mechanisms. |
| Dynamic linker manipulation | `/etc/ld.so.preload`, suspicious shared libraries | Library injection and persistence indicators. |
| Kernel modules | `/lib/modules/$(uname -r)/`, `lsmod`, `modinfo` | Unexpected or unsigned modules may warrant investigation. |
| SUID/SGID binaries | `find` with `-perm /6000` | Unexpected privileged executables. |
| File capabilities | `getcap` | Unexpected privilege-bearing binaries. |
| Core dumps | `coredumpctl`, `/var/lib/systemd/coredump/`, `/var/crash/` | Exploitation/crash context and memory remnants. |
| Container runtime state | `docker ps -a`, `podman ps -a`, `crictl ps -a` | Container workloads and runtime presence. |
| Web/application logs | Web server and application-specific log paths | Exploit requests, web shells and post-exploitation traces. |
| Audit/Sysmon telemetry | auditd, Sysmon for Linux, EDR logs | Process, file, network and security telemetry when deployed. |

## Output structure

```text
ForensicTable4Linux_YYYYMMDDTHHMMSSZ/
├── README-EVIDENCE.txt
├── SHA256SUMS
├── system/
├── users/
├── logs/
├── network/
├── persistence/
├── volatile/
├── filesystem/
├── metadata/
└── sensitive/                 # only when --include-sensitive is used
```

## Operational limitations

1. **Live response changes the system.** Even read-only commands can affect caches, process scheduling and access times in some environments. For strict forensic acquisition, image the storage and acquire RAM using a documented procedure.
2. **No universal Linux artefact layout exists.** Distribution, init system, desktop environment, browser packaging (deb/rpm/Flatpak/Snap), logging daemon and retention settings change paths.
3. **The collector is best-effort.** Missing tools and permission errors are recorded in `metadata/collection-errors.log`.
4. **The journal is time-bounded.** The default collection window is the last 30 days; use `--since` to change it.
5. **Do not analyse recovered evidence on the original host.** Work from verified copies and maintain chain-of-custody records.

## Validation

Test syntax before use:

```bash
bash -n forensic-linux.sh
```

The collector does not install optional tools. For additional coverage, tools such as `auditd`, `acct`, `lsof`, `usbutils`, `acl`, `attr`, `iproute2`, `nftables`, `iptables`, `NetworkManager` utilities and filesystem-specific forensic tools may be required.
