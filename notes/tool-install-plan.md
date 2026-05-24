# Tool Install Plan

This Kali machine already has:

- `git`
- `curl`
- `jq`
- `nmap`
- `httpx`
- `ffuf`
- `feroxbuster`
- `amass`
- `python3`
- `pipx`
- `go`
- ProjectDiscovery `httpx` in `$HOME/go/bin`
- `ripgrep` / `rg`
- `nuclei`
- `subfinder`
- `katana`
- `waybackurls`

Missing or not found:

- None currently known from the planned core set.

Special note:

- `gau` is currently a shell alias for `git add --update`, so do not assume `gau` means GetAllUrls in this shell.

Recommended install order:

```bash
sudo apt update
sudo apt install -y ripgrep

go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
```

Go tools are installed under `$HOME/go/bin`. Ensure this stays in your shell profile:

```bash
export PATH="$HOME/go/bin:$PATH"
```

Kali also ships a different `/usr/bin/httpx`. Keep `$HOME/go/bin` first in PATH so ProjectDiscovery `httpx` is used by recon scripts.
