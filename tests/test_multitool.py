import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import main as cli  # noqa: E402
from tools import insta, memscan, util  # noqa: E402
from tools.common import ToolError  # noqa: E402


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class UtilTests(unittest.TestCase):
    def test_hash_text_known_vector(self):
        code, out, _ = run("hash", "--text", "abc")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_encode_decode_roundtrip(self):
        for kind in util.ENCODERS:
            enc = util.ENCODERS[kind]("héllo wörld/+=".encode())
            self.assertEqual(util.DECODERS[kind](enc).decode(), "héllo wörld/+=", kind)

    def test_b64_decode_without_padding(self):
        self.assertEqual(util.DECODERS["b64"]("aGk"), b"hi")

    def test_passgen_has_all_classes(self):
        for _ in range(50):
            pw = util.make_password(12)
            self.assertEqual(len(pw), 12)
            self.assertTrue(any(c.islower() for c in pw) and any(c.isupper() for c in pw))
            self.assertTrue(any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw))
        with self.assertRaises(ToolError):
            util.make_password(4)

    def test_dedupe_finds_and_deletes(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "a.txt").write_text("same")
            (d / "b.txt").write_text("same")
            (d / "c.txt").write_text("different")
            groups = util.find_duplicates(d)
            self.assertEqual(len(groups), 1)
            run("dedupe", str(d), "--delete")
            self.assertTrue((d / "a.txt").exists())
            self.assertFalse((d / "b.txt").exists())
            self.assertTrue((d / "c.txt").exists())

    def test_rename_dry_run_then_apply_and_swap_safety(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            for n in ("x.txt", "y.txt"):
                (d / n).write_text(n)
            run("rename", str(d), "--seq", "photo_{n:03d}")
            self.assertTrue((d / "x.txt").exists())  # dry run changes nothing
            code, _, _ = run("rename", str(d), "--seq", "photo_{n:03d}", "--apply")
            self.assertEqual(code, 0)
            self.assertEqual(sorted(p.name for p in d.iterdir()), ["photo_001.txt", "photo_002.txt"])
            self.assertEqual((d / "photo_001.txt").read_text(), "x.txt")

    def test_rename_refuses_collision(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "a1.txt").write_text("1")
            (d / "a2.txt").write_text("2")
            code, _, err = run("rename", str(d), "--find", r"\d", "--replace", "", "--apply")
            self.assertEqual(code, 1)
            self.assertIn("same name", err)
            self.assertTrue((d / "a1.txt").exists())

    def test_json_get_and_min(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.json"
            f.write_text('{"users":[{"name":"ada"}]}')
            _, out, _ = run("json", str(f), "--get", "users.0.name")
            self.assertEqual(json.loads(out), "ada")
            _, out, _ = run("json", str(f), "--min")
            self.assertEqual(out.strip(), '{"users":[{"name":"ada"}]}')

    def test_portscan_finds_local_listener_and_blocks_public(self):
        import socket

        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        try:
            code, out, _ = run("portscan", "127.0.0.1", "--ports", str(port))
            self.assertEqual(code, 0)
            self.assertIn(f"{port}/tcp open", out)
        finally:
            srv.close()
        code, _, err = run("portscan", "8.8.8.8", "--ports", "53")
        self.assertEqual(code, 1)
        self.assertIn("--allow-public", err)


class InstaTests(unittest.TestCase):
    def make_export(self, d, followers, following):
        base = Path(d) / "connections" / "followers_and_following"
        base.mkdir(parents=True)
        (base / "followers_1.json").write_text(json.dumps([
            {"title": "", "media_list_data": [], "string_list_data": [
                {"href": f"https://www.instagram.com/{n}", "value": n, "timestamp": 1}]}
            for n in followers]))
        (base / "following.json").write_text(json.dumps({"relationships_following": [
            {"title": n, "string_list_data": [{"href": f"https://www.instagram.com/_u/{n}", "timestamp": 1}]}
            for n in following]}))

    def test_nonfollowers_fans_mutuals(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_export(d, ["Ann", "bob", "cy"], ["bob", "cy", "dee", "eve"])
            followers, following = insta.load_export(d)
            self.assertEqual(following - followers, {"dee", "eve"})
            self.assertEqual(followers - following, {"ann"})
            _, out, _ = run("ig", "nonfollowers", d)
            self.assertIn("dee", out)
            self.assertNotIn("bob", out)

    def test_missing_files_gives_clean_error(self):
        with tempfile.TemporaryDirectory() as d:
            code, _, err = run("ig", "stats", d)
            self.assertEqual(code, 1)
            self.assertIn("JSON", err)

    def test_snapshot_and_diff(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as e1, tempfile.TemporaryDirectory() as e2:
            os.environ["MULTITOOL_HOME"] = home
            try:
                self.make_export(e1, ["a", "b"], ["a"])
                self.make_export(e2, ["b", "c"], ["a"])
                run("ig", "snapshot", e1)
                time.sleep(1.1)  # snapshot names are per-second
                run("ig", "snapshot", e2)
                _, out, _ = run("ig", "diff")
                self.assertIn("new followers: 1", out)
                self.assertIn("lost followers: 1", out)
            finally:
                del os.environ["MULTITOOL_HOME"]


CHILD = r"""
import ctypes, sys, time
secret = ctypes.c_int32(1337133)
other = ctypes.c_double(2.5)
print(ctypes.addressof(secret), ctypes.addressof(other), flush=True)
while True:
    print(secret.value, other.value, flush=True)
    time.sleep(0.1)
"""


@unittest.skipUnless(sys.platform.startswith("linux"), "linux backend is the testable one")
class MemscanTests(unittest.TestCase):
    def setUp(self):
        self.child = subprocess.Popen([sys.executable, "-c", CHILD], stdout=subprocess.PIPE, text=True)
        self.addr_secret, self.addr_other = map(int, self.child.stdout.readline().split())
        try:
            self.session = memscan.Session(memscan.make_backend(self.child.pid, "linux"))
        except ToolError as e:
            self.child.kill()
            self.skipTest(str(e))

    def tearDown(self):
        self.session.unfreeze()
        self.child.kill()
        self.child.wait()
        self.child.stdout.close()

    def child_values(self):
        line = ""
        for _ in range(5):  # skip lines buffered before the write landed
            line = self.child.stdout.readline()
        return line.split()

    def test_scan_finds_value_then_write_changes_child(self):
        n = self.session.first_scan("i32", 1337133)
        self.assertGreaterEqual(n, 1)
        self.assertIn(self.addr_secret, self.session.candidates)
        self.session.write_value(self.addr_secret, 4242)
        self.assertEqual(self.session.read_value(self.addr_secret), 4242)
        self.assertEqual(self.child_values()[0], "4242")

    def test_next_scan_narrows(self):
        self.session.first_scan("i32", 1337133)
        self.session.write_value(self.addr_secret, 99)
        self.assertEqual(self.session.next_scan("eq", 99), 1)
        self.assertEqual(self.session.next_scan("unchanged"), 1)
        self.assertEqual(self.session.next_scan("eq", 7), 0)

    def test_float64_scan_and_freeze(self):
        self.session.first_scan("f64", 2.5)
        self.assertIn(self.addr_other, self.session.candidates)
        self.session.freeze(self.addr_other, 9.75, interval=0.01)
        time.sleep(0.3)
        self.assertEqual(self.child_values()[1], "9.75")

    def test_repl_dispatch(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            memscan.run_command(self.session, "scan i32 1337133")
            memscan.run_command(self.session, f"write {self.addr_secret:#x} 5")
            memscan.run_command(self.session, f"read {self.addr_secret:#x}")
        self.assertIn("candidate(s)", buf.getvalue())
        self.assertIn("5", buf.getvalue().splitlines()[-1])
        with self.assertRaises(ToolError):
            memscan.run_command(self.session, "scan i32 notanumber")


class CliTests(unittest.TestCase):
    def test_no_args_prints_help(self):
        code, out, _ = run()
        self.assertEqual(code, 0)
        for tool in ("hash", "portscan", "ig", "mem"):
            self.assertIn(tool, out)


if __name__ == "__main__":
    unittest.main()
