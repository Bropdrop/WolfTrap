# Offline execution

The cloud host denied creation of a separate network namespace. The fallback uses Linux seccomp through the installed libseccomp2 2.6.0-2 on x86_64. Before exec, it closes inherited file descriptors above standard I/O and rejects socket-backed standard I/O. It denies socket creation, connection, listening, send/receive and related syscalls as well as io_uring. The kernel applies the filter to child threads and processes. Library offline flags, pip no-index mode and disabled Hugging Face telemetry are also set.

Run an experiment under the filter from the evidence root using `python -B offline/offline_exec.py -- /path/to/venv/bin/python ...`. Use a fresh output directory for each attempt. The isolation applies to this process tree. The separate acquisition phase used network access.

The verification command was `python -B offline_exec.py -- /usr/bin/python3.13 -B check_offline.py` from this directory. Both processes observed EPERM for IPv4, IPv6, UNIX and netlink socket creation as well as connect, socketpair and io_uring entry points. Linux reported two stacked filters and NoNewPrivs=1. [Filter results](filter-check.json) · [Namespace attempt](netns-probe.log)
