# multitool

One Python CLI, three toolboxes. Standard library only (Pillow is optional, for image conversion).

```bash
python3 main.py              # list every tool
python3 main.py <tool> -h    # help for one tool
python3 -m unittest discover -s tests
```

Python 3.9+. Optional: `pip install -r requirements.txt` for `imgconv`.

## 1. Utility toolkit

| Tool | What it does |
|------|--------------|
| `hash <file\|dir> [--algo sha256]` / `hash --text "abc"` | checksums for files, whole trees, or a string |
| `enc` / `dec` `<b64\|b64url\|b32\|hex\|url\|rot13> <text\|->` | encode/decode, `-` reads stdin |
| `passgen [--length 20] [--count 5] [--no-symbols]` | cryptographically random passwords (`secrets`) |
| `dedupe <dir> [--delete]` | finds byte-identical duplicates (size, then SHA-256); dry run by default |
| `rename <dir> --find RE --replace STR` or `--seq 'photo_{n:03d}'` | bulk rename; dry run unless `--apply`; refuses collisions |
| `imgconv <file\|dir> --to webp [--max-size 1600]` | convert/resize images (needs Pillow) |
| `dns <host\|ip>` | forward + reverse lookup |
| `whois <domain\|ip>` | follows the IANA referral to the right registry |
| `myip` | your public IP |
| `portscan <host> --ports 1-1024` | TCP connect scan. Private/loopback targets only unless you pass `--allow-public` (only for hosts you're authorized to test) |
| `json <file\|-> [--get a.0.b] [--min]` | pretty-print, minify, query |

## 2. Instagram (your own account)

Works on Instagram's official data export. No login, no password, no scraping, nothing sent anywhere.

1. Instagram -> Accounts Center -> Your information and permissions -> **Download your information**
2. Pick *Followers and following*, format **JSON**, and unzip the result.

```bash
python3 main.py ig nonfollowers ~/Downloads/instagram-export     # you follow, they don't follow back
python3 main.py ig fans ~/Downloads/instagram-export             # follow you, you don't follow back
python3 main.py ig mutuals ~/Downloads/instagram-export --out mutuals.txt
python3 main.py ig stats ~/Downloads/instagram-export
python3 main.py ig snapshot ~/Downloads/instagram-export         # save for later
python3 main.py ig diff                                          # new/lost followers between your last two snapshots
```

Snapshots live in `~/.multitool/instagram/snapshots` (override with `$MULTITOOL_HOME`).

## 3. Memory scanner (single-player games)

Interactive Cheat-Engine-style scanner and editor.

```bash
python3 main.py mem ps game          # find the PID
sudo python3 main.py mem attach 1234 # or a unique name substring
mem> scan i32 100        # first scan for health = 100
mem> next 87             # took damage, narrow down
mem> next changed        # also: unchanged | inc | dec
mem> list
mem> write #0 999        # write by candidate index or by 0x address
mem> freeze #0 999       # keep rewriting it every 50 ms (unfreeze to stop)
```

Types: `i8 u8 i16 u16 i32 u32 i64 u64 f32 f64`.

**macOS notes (Apple Silicon and Intel):** uses `task_for_pid` plus `mach_vm_read/write`, so it needs `sudo`.
Apple-signed apps, SIP-protected processes and hardened-runtime apps without `get-task-allow` refuse
to be attached; that's a macOS restriction, not a bug. Windows-only games need to run under
CrossOver/Whisky/a VM first, and then you attach to the wine process. The Darwin backend is written
against the Mach API but I could only exercise the scan/edit logic through the Linux (`/proc`) backend,
which is what the test suite runs against a live process.

Only use this on single-player games. Editing memory in online games can get your account banned.
