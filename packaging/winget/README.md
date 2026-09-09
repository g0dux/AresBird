# AresBird winget manifest (draft)

After a GitHub Release publishes Windows assets, install locally with:

```powershell
# once published to winget-pkgs (or sideload):
winget install --manifest packaging/winget
```

## Files

| File | Role |
|------|------|
| `G0dux.AresBird.yaml` | Version catalog |
| `G0dux.AresBird.installer.yaml` | Installer URLs / SHA256 (fill after release) |
| `G0dux.AresBird.locale.en-US.yaml` | Package metadata |

## Refresh after each release

1. Download `ares-x86_64-pc-windows-msvc.zip` from the Release.
2. `Get-FileHash … -Algorithm SHA256`
3. Update `InstallerUrl` + `InstallerSha256` in `G0dux.AresBird.installer.yaml`
4. Bump `PackageVersion` in all three YAML files
5. Open a PR to [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)

Until then, prefer:

```powershell
# from Release assets
# or: cargo install --git https://github.com/g0dux/AresBird --locked
```
