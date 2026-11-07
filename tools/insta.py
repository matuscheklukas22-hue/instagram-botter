"""Instagram tools for YOUR OWN account, built on the official data export.

Get the export from Instagram: Accounts Center -> Your information and permissions ->
Download your information -> choose "Followers and following", format JSON.
No login, no passwords, no API calls: everything runs locally on the files.
"""
import json
import time
from pathlib import Path

from .common import ToolError, data_dir


def _names_from_json(path):
    """Pull usernames out of followers_N.json / following.json (both layouts)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):  # following.json: {"relationships_following": [...]}
        entries = [e for v in data.values() if isinstance(v, list) for e in v]
    else:  # followers_1.json: [...]
        entries = data
    names = set()
    for entry in entries:
        for item in entry.get("string_list_data", []):
            name = item.get("value") or entry.get("title")
            if not name and item.get("href"):
                name = item["href"].rstrip("/").rsplit("/", 1)[-1]
            if name:
                names.add(name.strip().lower())
    return names


def load_export(export_dir):
    root = Path(export_dir)
    if not root.is_dir():
        raise ToolError(f"{root} is not a directory")
    follower_files = sorted(root.rglob("followers_*.json"))
    following_files = sorted(root.rglob("following.json"))
    if not follower_files or not following_files:
        raise ToolError(
            "could not find followers_*.json and following.json under that folder. "
            "Request the export in JSON format (not HTML)."
        )
    followers, following = set(), set()
    for f in follower_files:
        followers |= _names_from_json(f)
    for f in following_files:
        following |= _names_from_json(f)
    return followers, following


def _emit(title, names, out=None):
    names = sorted(names)
    print(f"{title}: {len(names)}")
    for n in names:
        print(f"  https://instagram.com/{n}")
    if out:
        Path(out).write_text("\n".join(names) + "\n", encoding="utf-8")
        print(f"saved to {out}")


def cmd_nonfollowers(args):
    followers, following = load_export(args.export)
    _emit("you follow, they don't follow back", following - followers, args.out)


def cmd_fans(args):
    followers, following = load_export(args.export)
    _emit("follow you, you don't follow back", followers - following, args.out)


def cmd_mutuals(args):
    followers, following = load_export(args.export)
    _emit("mutuals", followers & following, args.out)


def cmd_stats(args):
    followers, following = load_export(args.export)
    print(f"followers : {len(followers)}")
    print(f"following : {len(following)}")
    print(f"mutuals   : {len(followers & following)}")
    print(f"not following back : {len(following - followers)}")
    print(f"fans you don't follow: {len(followers - following)}")
    if following:
        print(f"follow-back rate: {len(followers & following) / len(following):.1%}")


def _snap_dir():
    return data_dir("instagram", "snapshots")


def cmd_snapshot(args):
    followers, following = load_export(args.export)
    path = _snap_dir() / f"{time.strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps({"followers": sorted(followers), "following": sorted(following)}))
    print(f"saved snapshot: {path} ({len(followers)} followers, {len(following)} following)")


def cmd_diff(_args):
    snaps = sorted(_snap_dir().glob("*.json"))
    if len(snaps) < 2:
        raise ToolError("need at least two snapshots; run `ig snapshot <export>` after each new export")
    old, new = (json.loads(p.read_text()) for p in snaps[-2:])
    print(f"comparing {snaps[-2].stem} -> {snaps[-1].stem}")
    for label, a, b in (
        ("new followers", old["followers"], new["followers"]),
        ("lost followers", new["followers"], old["followers"]),
        ("newly followed by you", old["following"], new["following"]),
        ("unfollowed by you", new["following"], old["following"]),
    ):
        _emit(label, set(b) - set(a))


def register(sub):
    ig = sub.add_parser("ig", help="Instagram export analysis for your own account")
    igsub = ig.add_subparsers(dest="ig_cmd", metavar="<action>", required=True)
    for name, fn, helptext in (
        ("nonfollowers", cmd_nonfollowers, "people you follow who don't follow back"),
        ("fans", cmd_fans, "people who follow you that you don't follow"),
        ("mutuals", cmd_mutuals, "people you follow who follow you"),
    ):
        p = igsub.add_parser(name, help=helptext)
        p.add_argument("export", help="folder of your unzipped Instagram export")
        p.add_argument("--out", help="also write usernames to this file")
        p.set_defaults(func=fn)
    p = igsub.add_parser("stats", help="follower/following summary")
    p.add_argument("export")
    p.set_defaults(func=cmd_stats)
    p = igsub.add_parser("snapshot", help="save this export so later exports can be diffed")
    p.add_argument("export")
    p.set_defaults(func=cmd_snapshot)
    p = igsub.add_parser("diff", help="who followed/unfollowed between your last two snapshots")
    p.set_defaults(func=cmd_diff)
