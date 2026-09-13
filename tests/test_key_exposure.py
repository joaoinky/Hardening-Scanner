from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from nvg_scanner.checks.key_exposure_checks import run
from nvg_scanner.collectors import Collector, Context, Unavailable
from nvg_scanner.diff import compare
from nvg_scanner.engine import scan
from nvg_scanner.key_patterns import detect, valid_nsec, valid_wif, valid_mnemonic, wordlist
from nvg_scanner.reports import to_json, to_markdown
from tests.fixtures import config, FakeCollector

VECTORS = json.loads(Path(__file__).with_name("public_key_vectors.json").read_text())


class Keys(FakeCollector):
    def select_files(self, pattern, max_entries):
        return [pattern], False

    def read_regular_bytes(self, path, limit):
        value = self.files.get(path, Unavailable("Arquivo ausente"))
        if isinstance(value, Exception): raise value
        return value[:limit], len(value) > limit


def context(content=b"no credentials here"):
    cfg = config()
    cfg["key_exposure"] = {"enabled": True, "home_dir": "/home/nvg", "paths": [{"id": "history", "path": "~/.bash_history"}],
                           "max_file_bytes": 262144, "max_total_bytes": 1048576, "max_files": 8, "max_seconds": 5, "max_directory_entries": 128}
    return Context(cfg, Keys({"/home/nvg/.bash_history": content}))


class KeyTests(unittest.TestCase):
    def test_public_format_vectors_and_corruption(self):
        self.assertTrue(valid_nsec(VECTORS["nsec"]), "Vetor público nsec inválido")
        self.assertTrue(valid_wif(VECTORS["wif"]), "Vetor público WIF inválido")
        self.assertTrue(valid_mnemonic(VECTORS["bip39"].split(), wordlist()))
        self.assertFalse(valid_nsec(VECTORS["nsec"][:-1] + ("q" if VECTORS["nsec"][-1] != "q" else "p")))
        self.assertFalse(valid_wif(VECTORS["wif"][:-1] + "1"))
        self.assertFalse(valid_mnemonic(["abandon"] * 12, wordlist()))

    def test_all_types_critical_and_no_content_in_output_or_diff(self):
        text = "\nNONWORDSEPARATOR\n".join(VECTORS.values())
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            before = scan(context(text.encode()), ["key_exposure_checks"])
            after = scan(context(b"cleared test file"), ["key_exposure_checks"])
            diff = compare(before, after)
            rendered = to_json(before) + to_markdown(before) + to_json(diff) + to_markdown(diff)
        result = before["results"][0]
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["severity"], "critical")
        self.assertEqual(result["evidence"]["occurrences"], {"nsec": 1, "wif": 1, "bip39": 1})
        self.assertEqual(diff["summary"]["resolved_fail"], 1)
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        import hashlib
        for value in VECTORS.values():
            for forbidden in (value, value[:10], hashlib.sha256(value.encode()).hexdigest()):
                self.assertNotIn(forbidden, rendered)

    def test_diff_does_not_track_secret_identity(self):
        before = scan(context(VECTORS["nsec"].encode()), ["key_exposure_checks"])
        after = scan(context(VECTORS["wif"].encode()), ["key_exposure_checks"])
        change = compare(before, after)["changes"][0]
        self.assertEqual(change["transition"], "changed")
        self.assertEqual(change["changed_fields"], ["evidence"])
        self.assertNotIn("occurrences", to_json(compare(before, after)))

    def test_partial_file_without_findings_is_not_pass(self):
        ctx = context(b"x" * 1000)
        ctx.config["key_exposure"]["max_file_bytes"] = 10
        self.assertTrue(all(r.status == "warning" for r in run(ctx)))

    def test_invalid_candidate_is_warning_not_pass(self):
        self.assertTrue(all(r.status == "warning" for r in run(context(b"nsec1qqqqqqqqqqqqqqqqqqqq"))))

    def test_total_budget_and_file_limit(self):
        ctx = context(b"abcdefghij")
        ctx.config["key_exposure"]["max_total_bytes"] = 5
        ctx.config["key_exposure"]["paths"].append({"id": "second", "path": "/second"})
        results = list(run(ctx))
        self.assertTrue(any(r.id == "key_exposure.budget" for r in results))
        self.assertFalse(any(r.status == "pass" for r in results))

    def test_missing_file_is_inconclusive(self):
        self.assertEqual(next(run(context(Unavailable("not found")))).status, "warning")

    def test_real_fifo_symlink_and_large_file(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo, link, target = [Path(directory, name) for name in ("fifo", "link", "target")]
            os.mkfifo(fifo)
            target.write_bytes(b"x" * 20)
            link.symlink_to(target)
            collector = Collector()
            for path in (fifo, link):
                with self.assertRaises(Unavailable): collector.read_regular_bytes(path, 10)
            self.assertEqual(collector.read_regular_bytes(target, 10), (b"x" * 10, True))

    def test_filename_and_id_containing_secret_are_fully_omitted(self):
        ctx = context()
        path = "/tmp/" + VECTORS["nsec"]
        ctx.config["key_exposure"]["paths"] = [{"id": "test", "path": path}]
        ctx.collector.files[path] = VECTORS["nsec"].encode()
        report = scan(ctx, ["key_exposure_checks"])
        self.assertNotIn(VECTORS["nsec"][:10], to_json(report))
        legacy = deepcopy(report)
        legacy["results"][0]["id"] = path
        self.assertNotIn(VECTORS["nsec"][:10], to_json(compare(legacy, legacy)))

    def test_words_separated_by_other_text_are_not_reconstructed(self):
        phrase = VECTORS["bip39"].replace(" ", " NONWORDSEPARATOR ")
        self.assertEqual(detect(phrase, wordlist())[0]["bip39"], 0)

    def test_deadline_and_file_count_are_enforced(self):
        self.assertTrue(detect(VECTORS["nsec"], wordlist(), deadline=0)[2])
        ctx = context()
        ctx.config["key_exposure"]["max_files"] = 1
        ctx.config["key_exposure"]["paths"].append({"id": "other", "path": "/other"})
        self.assertTrue(any(r.id == "key_exposure.budget" for r in run(ctx)))

    def test_directory_enumeration_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("a.log", "b.log", "c.log"):
                Path(directory, name).touch()
            selected, partial = Collector().select_files(str(Path(directory, "*.log")), 2)
            self.assertEqual(len(selected), 2)
            self.assertTrue(partial)
