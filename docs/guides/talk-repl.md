# Talk REPL

Interactive **observe** sessions (cookies / duplex TCP) — not a general shell.

```bash
ares talk http://127.0.0.1:8080/ --proto http --repl
ares talk 127.0.0.1:6379 --proto redis --repl
ares talk 127.0.0.1:22 --proto ssh --repl
```

| Proto | What you get |
|-------|----------------|
| `http` / `https` | Cookie jar, `GET` / path shortcuts |
| `redis` | Read-only RESP (`PING`, `INFO`, `GET`, …); reconnects if down |
| `ssh` | **Observe-only**: `banner`, `algs`, `probe` — **no** login/shell/SCP |

## Honesty bar

- SSH REPL will never become `ssh user@host` — use OpenSSH for interactive access.
- Redis blocks write/admin commands.
- Prefer `--ephemeral` in labs if you do not want workspace pollution.

Type `help` inside a REPL for commands; `quit` to exit.
