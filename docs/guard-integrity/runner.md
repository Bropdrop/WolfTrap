# Protected Linux runtime qualification handoff

The protected jobs on the exact #35 and #36 candidates stopped before the driver could create a result. The hosted runner reported `HOSTED_UID_MAP_PERMISSION_DENIED`. The portable job passed on both heads. The replacement runner requires separate operator custody and owner authorization before use. No replacement runner was provisioned in this qualification.

Use an ephemeral Linux VM with an unprivileged runner account, util-linux unshare and setpriv, distribution Python 3, Git, user and network namespaces, permitted per-user UID/GID mappings, and the seccomp support required by the pinned driver. Use a fresh full checkout of Bropdrop/WolfTrap at the selected commit. Retain Git history for the package driver's pinned inputs. Stage dependencies before disabling network access. Give the runner no signing keys, production credentials, deployment permissions or host control sockets.

| Original | Candidate | Tree |
|---|---|---|
| #35 | `99f148be239309315f4eca16860ad5eb45d8826b` | `680578ca7cc0d1bed571db5e95b1c29230b710e5` |
| #36 | `ff1b7e1ccabcf4abe138d235ecd49674454dd9ea` | `38c469b33016b859f4a498c8f5c30ae97cbacd08` |

Compare HEAD, its tree and the clean checkout against the row under review. Run the preflight as the runner service account inside its actual service sandbox. A UID-map error on this command reproduces the infrastructure blocker. Retain stderr, exit code, kernel version, namespace mappings and runner image identity.

```sh
unshare --user --map-current-user --net -- setpriv --no-new-privs sh -ec '
  cat /proc/self/uid_map /proc/self/gid_map
  cat /proc/self/status | grep -E "^(NoNewPrivs|Seccomp):"
  ls /sys/class/net
'
```

Run both jobs from the selected commit's wt-pkg-005-qualification workflow in the authorized runner environment. The protected job uses the following command. Select a fresh output directory outside the checkout.

```sh
out=$(mktemp -d)
unshare --user --map-current-user --net -- setpriv --no-new-privs \
  /usr/bin/python3 -EBS qualification/wt_pkg_005/wt_pkg_005.py qualify \
  --source "$PWD" --output "$out/result" --hosted
```

Record the actual exit status and retain the driver log, result.json and its SHA-256. The preflight alone cannot qualify enforcement. A passing protected result requires the driver's mandatory namespace and seccomp checks. Preserve any blocked or unsupported result and keep the runtime gate closed. Changing branch protections, running the driver as host root or relaxing the isolation settings would invalidate comparability.
