# Scan summary

Last full scan: 2026-11-22, Fedora Silverblue 44, openscap 1.4.6 (`openscap-scanner`
1.4.6-1.fc44), scap-security-guide 0.1.82 (0.1.82-1.fc44), `ssg-fedora-ds.xml`, profile
`cis_workstation_l2` (DRAFT). Both scans the same hour, hardening tree `1a632dd3`.
Reports stay on the host; this file has rule ids and counts only.

## Counts

| Result         | plain | tailored |
|----------------|------:|---------:|
| fail           |    83 |        8 |
| pass           |   316 |      324 |
| not applicable |    34 |       34 |
| rules scanned  |   433 |      366 |

Tailored = [tailoring.xml](tailoring.xml): 67 rules unselected, 11 variables set to my
values. The tailored scan of 2026-11-22 had one rule less (365 / 323 pass):
`sshd_limit_user_access` was unselected then, it passed in the plain scan, so it is scanned
again since. Every tailored fail is a backlog rule (below); 9 plain fails pass with my values
(`set-value`), 66 are unselected with a reason, `dconf_db_up_to_date` is unselected but
passed this time (false positive that depends on image timestamps).

## Since the last full scan (2026-11-18: fail 97, pass 302, not applicable 34)

- 16 fail -> pass: the audit rules written in the scanner's text (13: `audit_rules_execution_`
  chacl / chcon / setfacl, `audit_rules_mac_modification_` etc_selinux / usr_share /
  var_lib_selinux, `..._etc_sysconfig_network`, `audit_rules_privileged_commands`, `_kmod`,
  `_usermod`, `audit_rules_suid_auid_privilege_function`, `audit_rules_sysadmin_actions`,
  `audit_rules_usergroup_modification_pamd`), password min age (2:
  `accounts_minimum_age_login_defs`, `accounts_password_set_min_life_existing`),
  `dconf_db_up_to_date`.
- 2 pass -> fail: `dconf_gnome_disable_user_list`, `journald_disable_forward_to_syslog`: the
  copies written only for the scanner are gone (one place per setting); false positives with
  a check command in [docs/deviations.md](../docs/deviations.md).

## The 83 plain fails by kind

Reasons and check commands: [docs/deviations.md](../docs/deviations.md), same section names.

| Count | Kind | Tailored |
|------:|------|----------|
| 11 | Would break this machine | 9 unselected, 2 my value (`rp_filter` 2) |
| 10 | Not useful on a personal device | unselected |
| 1  | Two accounts | unselected |
| 34 | Changed on purpose | 27 unselected, 7 my value |
| 15 | Scanner false positives on Silverblue | unselected |
| 4  | Rootless container storage | unselected |
| 8  | Backlog | scanned: the 8 tailored fails |

- Would break this machine: `kernel_module_overlayfs_disabled`,
  `kernel_module_usb-storage_disabled`, `package_dnsmasq_removed`, `package_httpd_removed`,
  `package_rsync_removed`, `sysctl_net_ipv4_ip_forward`, `sysctl_net_ipv4_conf_all_forwarding`,
  `sysctl_net_ipv4_conf_default_forwarding`, `xwayland_disabled`; my value:
  `sysctl_net_ipv4_conf_all_rp_filter`, `sysctl_net_ipv4_conf_default_rp_filter`.
- Not useful on a personal device: `accounts_tmout`, `banner_etc_issue_cis`,
  `banner_etc_issue_net_cis`, `dconf_gnome_banner_enabled`, `dconf_gnome_login_banner_text`,
  `sshd_enable_warning_banner_net`, `package_systemd-journal-remote_installed`,
  `accounts_passwords_pam_faillock_even_deny_root_or_root_unlock_time`,
  `ensure_root_password_configured`, `service_bluetooth_disabled`.
- Two accounts: `account_disable_post_pw_expiration`.
- Changed on purpose: `audit_rules_dac_modification_*` (14),
  `audit_rules_file_deletion_events_*` (5), `audit_rules_unsuccessful_file_modification_*` (5),
  `audit_rules_time_clock_settime`, `sysctl_kernel_yama_ptrace_scope`,
  `accounts_password_pam_modules_in_authselect_profile`; my value:
  `sysctl_kernel_kptr_restrict`, `auditd_data_disk_full_action`,
  `auditd_data_retention_admin_space_left_action`, `auditd_data_retention_space_left_action`,
  `auditd_data_retention_max_log_file_action`, `sshd_set_keepalive`, `sshd_set_idle_timeout`.
- Scanner false positives on Silverblue: `grub2_audit_argument`,
  `grub2_audit_backlog_limit_argument`, `audit_rules_kernel_module_loading_create`,
  `audit_rules_kernel_module_loading_query`, `ensure_fedora_gpgkey_installed`,
  `package_cron_installed`, `sysctl_fs_suid_dumpable`, `file_groupownership_sshd_private_key`,
  `sshd_disable_gssapi_auth`, `accounts_password_pam_unix_authtok`,
  `audit_rules_networkconfig_modification_sethostname`,
  `audit_rules_networkconfig_modification_setdomainname`,
  `audit_rules_networkconfig_modification_etc_networkmanager_system_connections`,
  `journald_disable_forward_to_syslog`, `dconf_gnome_disable_user_list`.
- Rootless container storage: `no_files_or_dirs_unowned_by_user`,
  `no_files_or_dirs_ungroupowned`, `file_permissions_unauthorized_world_writable`,
  `dir_perms_world_writable_sticky_bits`.
- Backlog (not decided yet, no row): AIDE (`package_aide_installed`, `aide_build_database`,
  `aide_check_audit_tools`, `aide_periodic_cron_checking`; since 2026-11-22 the integrity
  section: the first three pass at the next scan, the fourth is a scanner false positive
  row), CIS crypto-policy module
  (`configure_custom_crypto_policy_cis`), umask (`accounts_umask_etc_bashrc`,
  `accounts_umask_etc_login_defs`, `accounts_umask_etc_profile`).

## Next scan

At the Fedora 45 upgrade (the review of every row in docs/deviations.md):
`python3 -I tools/check-tailoring.py`, then both scans ([README.md](README.md)), then this
file.
