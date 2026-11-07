"""General utility toolkit. Standard library only (Pillow is optional, for imgconv)."""
import base64
import codecs
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import string
import sys
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .common import ToolError

HASH_ALGOS = sorted(a for a in hashlib.algorithms_guaranteed if not a.startswith("shake"))


# --------------------------------------------------------------------------- hash
def hash_file(path, algo="sha256", chunk=1 << 20):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def cmd_hash(args):
    if args.text:
        print(hashlib.new(args.algo, args.target.encode()).hexdigest())
        return
    p = Path(args.target)
    if p.is_file():
        print(f"{hash_file(p, args.algo)}  {p}")
    elif p.is_dir():
        for f in sorted(p.rglob("*")):
            if f.is_file() and not f.is_symlink():
                print(f"{hash_file(f, args.algo)}  {f}")
    else:
        raise ToolError(f"{args.target!r} is not a file or directory (use --text to hash a string)")


# ------------------------------------------------------------------- encode/decode
def _b64d(text, urlsafe=False):
    text = "".join(text.split())
    text += "=" * (-len(text) % 4)
    return (base64.urlsafe_b64decode if urlsafe else base64.b64decode)(text)


ENCODERS = {
    "b64": lambda b: base64.b64encode(b).decode(),
    "b64url": lambda b: base64.urlsafe_b64encode(b).decode(),
    "b32": lambda b: base64.b32encode(b).decode(),
    "hex": lambda b: b.hex(),
    "url": lambda b: urllib.parse.quote(b, safe=""),
    "rot13": lambda b: codecs.encode(b.decode(), "rot13"),
}
DECODERS = {
    "b64": _b64d,
    "b64url": lambda t: _b64d(t, urlsafe=True),
    "b32": lambda t: base64.b32decode(t.strip().upper() + "=" * (-len(t.strip()) % 8)),
    "hex": lambda t: bytes.fromhex("".join(t.split())),
    "url": lambda t: urllib.parse.unquote_to_bytes(t),
    "rot13": lambda t: codecs.decode(t, "rot13").encode(),
}


def _input_text(value):
    return sys.stdin.read().rstrip("\n") if value == "-" else value


def cmd_enc(args):
    print(ENCODERS[args.kind](_input_text(args.text).encode()))


def cmd_dec(args):
    try:
        raw = DECODERS[args.kind](_input_text(args.text))
    except Exception as e:  # binascii.Error, ValueError, ...
        raise ToolError(f"cannot decode as {args.kind}: {e}")
    sys.stdout.write(raw.decode("utf-8", errors="replace") + "\n")


# ---------------------------------------------------------------------- passgen
def make_password(length=20, symbols=True):
    if length < 8:
        raise ToolError("password length must be at least 8")
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append("!@#$%^&*()-_=+[]{};:,.?")
    alphabet = "".join(classes)
    while True:  # rejection-sample until every class is represented
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in classes):
            return pw


def cmd_passgen(args):
    for _ in range(args.count):
        print(make_password(args.length, not args.no_symbols))


# ----------------------------------------------------------------------- dedupe
def find_duplicates(root, min_size=1):
    by_size = defaultdict(list)
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size >= min_size:
                by_size[size].append(p)
    groups = []
    for size, paths in by_size.items():
        if len(paths) < 2:
            continue
        by_hash = defaultdict(list)
        for p in paths:
            try:
                by_hash[hash_file(p)].append(p)
            except OSError:
                pass
        groups += [(size, sorted(v)) for v in by_hash.values() if len(v) > 1]
    return sorted(groups, key=lambda g: -g[0])


def cmd_dedupe(args):
    root = Path(args.directory)
    if not root.is_dir():
        raise ToolError(f"{root} is not a directory")
    groups = find_duplicates(root, args.min_size)
    reclaim = 0
    for size, paths in groups:
        print(f"{size} bytes x{len(paths)}")
        print(f"  keep   {paths[0]}")
        for dup in paths[1:]:
            reclaim += size
            if args.delete:
                dup.unlink()
                print(f"  delete {dup}")
            else:
                print(f"  dup    {dup}")
    verb = "freed" if args.delete else "reclaimable (re-run with --delete)"
    print(f"{len(groups)} duplicate group(s), {reclaim} bytes {verb}")


# ----------------------------------------------------------------------- rename
def plan_renames(files, find=None, replace="", seq=None):
    """Return [(src, dst)] for files that would actually change name."""
    import re

    plan = []
    for n, src in enumerate(sorted(files), start=1):
        if seq:
            new = seq.format(n=n, stem=src.stem, ext=src.suffix.lstrip("."))
            if "{ext}" not in seq and "." not in new and src.suffix:
                new += src.suffix
        else:
            new = re.sub(find, replace, src.name)
        if new != src.name:
            plan.append((src, src.with_name(new)))
    return plan


def cmd_rename(args):
    root = Path(args.directory)
    if not root.is_dir():
        raise ToolError(f"{root} is not a directory")
    if bool(args.find) == bool(args.seq):
        raise ToolError("give exactly one of --find/--replace or --seq")
    it = root.rglob("*") if args.recursive else root.iterdir()
    files = [p for p in it if p.is_file() and not p.is_symlink()]
    plan = plan_renames(files, args.find, args.replace, args.seq)
    if not plan:
        print("nothing to rename")
        return
    dsts = [d for _, d in plan]
    srcs = {s for s, _ in plan}
    if len(set(dsts)) != len(dsts):
        raise ToolError("two files would end up with the same name; aborting")
    for d in dsts:
        if d.exists() and d not in srcs:
            raise ToolError(f"{d} already exists; aborting")
    for s, d in plan:
        print(f"{s.name} -> {d.name}")
    if not args.apply:
        print(f"{len(plan)} rename(s) planned, nothing changed (re-run with --apply)")
        return
    staged = []  # two-phase so swaps and chains can't clobber each other
    for s, d in plan:
        tmp = s.with_name(f".{uuid.uuid4().hex}.tmp")
        s.rename(tmp)
        staged.append((tmp, d))
    for tmp, d in staged:
        tmp.rename(d)
    print(f"renamed {len(plan)} file(s)")


# ---------------------------------------------------------------------- imgconv
def cmd_imgconv(args):
    try:
        from PIL import Image
    except ImportError:
        raise ToolError("Pillow is required: pip install pillow")
    src = Path(args.source)
    files = [src] if src.is_file() else sorted(p for p in src.iterdir() if p.is_file())
    if not files:
        raise ToolError(f"no files at {src}")
    fmt = args.to.lower().lstrip(".")
    pil_fmt = {"jpg": "JPEG", "jpeg": "JPEG"}.get(fmt, fmt.upper())
    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    done = 0
    for f in files:
        try:
            with Image.open(f) as im:
                if args.max_size:
                    im.thumbnail((args.max_size, args.max_size))
                if pil_fmt == "JPEG" and im.mode not in ("RGB", "L"):
                    im = im.convert("RGB")
                dst = (out_dir or f.parent) / f"{f.stem}.{fmt}"
                if dst == f:
                    continue
                im.save(dst, pil_fmt, quality=args.quality)
                print(f"{f.name} -> {dst}")
                done += 1
        except OSError as e:
            print(f"skip {f.name}: {e}", file=sys.stderr)
    print(f"converted {done} image(s)")


# ------------------------------------------------------------------ dns/whois/ip
def cmd_dns(args):
    host = args.host
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    try:
        if not is_ip:
            seen = []
            for fam, _t, _p, _c, sockaddr in socket.getaddrinfo(host, None):
                ip = sockaddr[0]
                if ip not in seen:
                    seen.append(ip)
                    print(f"{'AAAA' if fam == socket.AF_INET6 else 'A':5} {ip}")
        else:
            seen = [host]
        for ip in seen[:4]:
            try:
                print(f"PTR   {ip} -> {socket.gethostbyaddr(ip)[0]}")
            except OSError:
                print(f"PTR   {ip} -> (no reverse record)")
    except socket.gaierror as e:
        raise ToolError(f"lookup failed: {e}")


def _whois_query(server, query, timeout=10):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall(query.encode() + b"\r\n")
        chunks = []
        while data := s.recv(4096):
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def cmd_whois(args):
    try:
        text = _whois_query("whois.iana.org", args.query)
        for line in text.splitlines():
            if line.lower().startswith(("refer:", "whois:")):
                server = line.split(":", 1)[1].strip()
                if server:
                    text = _whois_query(server, args.query)
                    break
    except OSError as e:
        raise ToolError(f"whois failed: {e}")
    print(text.strip())


def cmd_myip(_args):
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                print(r.read().decode().strip())
                return
        except OSError:
            continue
    raise ToolError("could not reach an IP echo service")


# -------------------------------------------------------------------- port scan
def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ToolError("ports must be within 1-65535")
    return sorted(ports)


def cmd_portscan(args):
    try:
        ports = parse_ports(args.ports)
        ip = socket.gethostbyname(args.host)
    except (ValueError, socket.gaierror) as e:
        raise ToolError(f"bad target/ports: {e}")
    addr = ipaddress.ip_address(ip)
    if not (addr.is_private or addr.is_loopback or addr.is_link_local) and not args.allow_public:
        raise ToolError(
            f"{ip} is a public address. Only scan hosts you own or have written permission to test; "
            "pass --allow-public to confirm that."
        )

    def probe(port):
        try:
            with socket.create_connection((ip, port), timeout=args.timeout):
                return port
        except OSError:
            return None

    print(f"scanning {args.host} ({ip}), {len(ports)} port(s)...")
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        open_ports = [p for p in pool.map(probe, ports) if p]
    for p in open_ports:
        try:
            name = socket.getservbyport(p)
        except OSError:
            name = "?"
        print(f"{p}/tcp open  {name}")
    print(f"{len(open_ports)} open")


# --------------------------------------------------------------------------- json
def _dig(obj, path):
    for key in path.split("."):
        if isinstance(obj, list):
            try:
                obj = obj[int(key)]
            except (ValueError, IndexError):
                raise ToolError(f"bad list index {key!r}")
        elif isinstance(obj, dict) and key in obj:
            obj = obj[key]
        else:
            raise ToolError(f"key {key!r} not found")
    return obj


def cmd_json(args):
    raw = sys.stdin.read() if args.file == "-" else Path(args.file).read_text()
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ToolError(f"invalid JSON: {e}")
    if args.get:
        obj = _dig(obj, args.get)
    if args.min:
        print(json.dumps(obj, separators=(",", ":"), sort_keys=args.sort_keys, ensure_ascii=False))
    else:
        print(json.dumps(obj, indent=2, sort_keys=args.sort_keys, ensure_ascii=False))


# ------------------------------------------------------------------------ wiring
def register(sub):
    p = sub.add_parser("hash", help="hash a file, a directory tree, or text")
    p.add_argument("target")
    p.add_argument("--algo", choices=HASH_ALGOS, default="sha256")
    p.add_argument("--text", action="store_true", help="treat TARGET as a string")
    p.set_defaults(func=cmd_hash)

    for name, fn in (("enc", cmd_enc), ("dec", cmd_dec)):
        p = sub.add_parser(name, help=f"{'encode' if name == 'enc' else 'decode'} text (use - for stdin)")
        p.add_argument("kind", choices=sorted(ENCODERS))
        p.add_argument("text")
        p.set_defaults(func=fn)

    p = sub.add_parser("passgen", help="generate strong random passwords")
    p.add_argument("--length", type=int, default=20)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--no-symbols", action="store_true")
    p.set_defaults(func=cmd_passgen)

    p = sub.add_parser("dedupe", help="find (and optionally delete) duplicate files")
    p.add_argument("directory")
    p.add_argument("--min-size", type=int, default=1, help="ignore files smaller than N bytes")
    p.add_argument("--delete", action="store_true", help="delete duplicates, keeping the first path")
    p.set_defaults(func=cmd_dedupe)

    p = sub.add_parser("rename", help="bulk rename files (dry run unless --apply)")
    p.add_argument("directory")
    p.add_argument("--find", help="regex to search for in file names")
    p.add_argument("--replace", default="", help="replacement for --find (supports \\1 groups)")
    p.add_argument("--seq", help="name template, e.g. 'photo_{n:03d}' ({n} {stem} {ext})")
    p.add_argument("-r", "--recursive", action="store_true")
    p.add_argument("--apply", action="store_true")
    p.set_defaults(func=cmd_rename)

    p = sub.add_parser("imgconv", help="convert/resize images (needs Pillow)")
    p.add_argument("source", help="image file or directory")
    p.add_argument("--to", required=True, help="target format: png, jpg, webp, ...")
    p.add_argument("--quality", type=int, default=90)
    p.add_argument("--max-size", type=int, help="fit inside N x N pixels")
    p.add_argument("--out-dir")
    p.set_defaults(func=cmd_imgconv)

    p = sub.add_parser("dns", help="forward/reverse DNS lookup")
    p.add_argument("host")
    p.set_defaults(func=cmd_dns)

    p = sub.add_parser("whois", help="whois lookup for a domain or IP")
    p.add_argument("query")
    p.set_defaults(func=cmd_whois)

    p = sub.add_parser("myip", help="show your public IP")
    p.set_defaults(func=cmd_myip)

    p = sub.add_parser("portscan", help="TCP connect scan (private/loopback targets by default)")
    p.add_argument("host")
    p.add_argument("--ports", default="1-1024", help="e.g. 22,80,443 or 1-1024")
    p.add_argument("--timeout", type=float, default=0.5)
    p.add_argument("--threads", type=int, default=200)
    p.add_argument("--allow-public", action="store_true", help="confirm you have permission to scan a public host")
    p.set_defaults(func=cmd_portscan)

    p = sub.add_parser("json", help="pretty-print / minify / query JSON (use - for stdin)")
    p.add_argument("file")
    p.add_argument("--get", help="dotted path, e.g. users.0.name")
    p.add_argument("--min", action="store_true")
    p.add_argument("--sort-keys", action="store_true")
    p.set_defaults(func=cmd_json)
