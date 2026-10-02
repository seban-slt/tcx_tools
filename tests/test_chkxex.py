"""Synthetic XEX fixtures: no copyrighted program files are required."""

import contextlib
import io
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from struct import pack
from unittest.mock import patch

from chkxex import XexFormatError, describe_vectors, iter_segments, main


SCRIPT = Path(__file__).resolve().parents[1] / "chkxex.py"


def block(start, payload):
    return pack("<HH", start, start + len(payload) - 1) + payload


class ParserTests(unittest.TestCase):
    def assert_format_error(self, data, offset, number, message):
        with self.assertRaises(XexFormatError) as caught:
            list(iter_segments(data))
        self.assertEqual(caught.exception.offset, offset)
        self.assertEqual(caught.exception.segment_number, number)
        self.assertIn(message, str(caught.exception))

    def test_short_or_wrong_signature(self):
        for data in (b"", b"\xff", b"\x00"):
            with self.subTest(data=data):
                self.assert_format_error(data, 0, None, "incomplete file signature")
        for data in (b"\x00\x00", b"\xff\x00", b"\x00\xff"):
            with self.subTest(data=data):
                self.assert_format_error(data, 0, None, "$FFFF file signature")

    def test_markers_without_segment(self):
        for data in (b"\xff\xff", b"\xff\xff" * 3):
            with self.subTest(data=data):
                self.assert_format_error(data, len(data), 1, "found 0")

    def test_partial_first_header(self):
        for size in range(1, 4):
            with self.subTest(size=size):
                self.assert_format_error(
                    b"\xff\xff" + b"\x00\x20\x01"[:size],
                    2, 1, f"expected 4 bytes, found {size}",
                )

    def test_one_byte_segment(self):
        segments = list(iter_segments(bytes.fromhex("ff ff 00 20 00 20 aa")))
        self.assertEqual(len(segments), 1)
        segment = segments[0]
        self.assertEqual((segment.number, segment.offset), (1, 2))
        self.assertEqual((segment.start, segment.end, segment.data), (0x2000, 0x2000, b"\xaa"))

    def test_markers_segments_and_overlapping_ranges(self):
        data = b"\xff\xff" * 3 + block(0x3000, b"\xff\xff")
        data += block(0x2000, b"\x11\x22")
        data += b"\xff\xff" * 2 + block(0x2001, b"\x33")
        segments = list(iter_segments(data))
        self.assertEqual([s.number for s in segments], [1, 2, 3])
        self.assertEqual([s.offset for s in segments], [6, 12, 22])
        self.assertEqual([s.start for s in segments], [0x3000, 0x2000, 0x2001])
        self.assertEqual([s.data for s in segments], [b"\xff\xff", b"\x11\x22", b"\x33"])

    def test_address_space_boundaries(self):
        for start, payload in ((0, b"\x11"), (0xfffe, b"\x22\x33"), (0, bytes(65536))):
            with self.subTest(start=start, length=len(payload)):
                segment, = iter_segments(b"\xff\xff" + block(start, payload))
                self.assertEqual(segment.start, start)
                self.assertEqual(segment.end, start + len(payload) - 1)
                self.assertEqual(segment.data, payload)

    def test_reversed_ranges(self):
        for start, end in ((0x2001, 0x2000), (5, 0), (0x2000, 0x1000)):
            with self.subTest(start=start, end=end):
                self.assert_format_error(
                    b"\xff\xff" + pack("<HH", start, end),
                    2, 1, "end address is below start address",
                )

    def test_truncated_data_including_vectors(self):
        for start, length in ((0x2000, 3), (0x02e0, 2), (0x02e2, 2), (0x02e0, 4)):
            for available in range(length):
                with self.subTest(start=start, available=available):
                    self.assert_format_error(
                        b"\xff\xff" + pack("<HH", start, start + length - 1)
                        + bytes(available),
                        6, 1,
                        f"expected {length} bytes, found {available} (missing {length - available})",
                    )

    def test_preserves_complete_segments_before_error(self):
        segments = iter_segments(bytes.fromhex("ff ff 00 20 00 20 aa 00 30 02 30 bb"))
        self.assertEqual(next(segments).data, b"\xaa")
        with self.assertRaises(XexFormatError) as caught:
            next(segments)
        self.assertEqual(caught.exception.offset, 11)
        self.assertEqual(caught.exception.segment_number, 2)
        self.assertIn("$3000-$3002", str(caught.exception))

    def test_partial_next_header_with_or_without_marker(self):
        complete = b"\xff\xff" + block(0x2000, b"\xaa")
        for marker in (b"", b"\xff\xff", b"\xff\xff" * 2):
            for size in range(1, 4):
                with self.subTest(marker=marker, size=size):
                    self.assert_format_error(
                        complete + marker + b"\x00\x30\x01"[:size],
                        len(complete) + len(marker), 2, f"found {size}",
                    )

    def test_trailing_markers_are_rejected(self):
        complete = b"\xff\xff" + block(0x2000, b"\xaa")
        for tail in (b"\xff\xff", b"\xff\xff" * 3):
            with self.subTest(tail=tail):
                self.assert_format_error(complete + tail, len(complete + tail), 2, "found 0")

    def test_every_cut_accepts_only_complete_segment_boundaries(self):
        data = b"\xff\xff"
        boundaries = {}
        for start, payload in (
            (0x2000, b"\xaa\xbb\xcc"),
            (0x3000, b"\x01\x02"),
            (0x02e0, b"\x00\x20"),
        ):
            data += block(start, payload)
            boundaries[len(data)] = len(boundaries) + 1
        for cut in range(len(data) + 1):
            with self.subTest(cut=cut):
                if cut in boundaries:
                    self.assertEqual(len(list(iter_segments(data[:cut]))), boundaries[cut])
                else:
                    with self.assertRaises(XexFormatError):
                        list(iter_segments(data[:cut]))

    def test_vector_writes(self):
        cases = (
            (0x2000, b"\x00", []),
            (0x02e0, b"\x34\x12", ["RUN=$1234"]),
            (0x02e2, b"\x78\x56", ["INIT=$5678"]),
            (0x02e0, b"\x34\x12\x78\x56", ["RUN=$1234", "INIT=$5678"]),
            (0x02df, b"\xaa\x34\x12\x78\x56\xbb", ["RUN=$1234", "INIT=$5678"]),
            (0x02e0, b"\x34", ["RUN low byte ($02e0)=$34"]),
            (0x02e1, b"\x12", ["RUN high byte ($02e1)=$12"]),
            (0x02e2, b"\x78", ["INIT low byte ($02e2)=$78"]),
            (0x02e3, b"\x56", ["INIT high byte ($02e3)=$56"]),
            (0x02e1, b"\x12\x78", ["RUN high byte ($02e1)=$12", "INIT low byte ($02e2)=$78"]),
        )
        for start, payload, expected in cases:
            with self.subTest(start=start, payload=payload):
                segment, = iter_segments(b"\xff\xff" + block(start, payload))
                self.assertEqual(describe_vectors(segment), expected)

    def test_split_vectors_are_not_combined_across_segments(self):
        data = b"\xff\xff" + block(0x02e0, b"\x00") + block(0x02e1, b"\x20")
        self.assertEqual(
            [describe_vectors(s) for s in iter_segments(data)],
            [["RUN low byte ($02e0)=$00"], ["RUN high byte ($02e1)=$20"]],
        )


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "sample with spaces.xex"

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            capture_output=True, text=True, timeout=5,
        )

    def test_valid_file(self):
        self.path.write_bytes(bytes.fromhex("ff ff 00 20 00 20 aa e0 02 e1 02 00 20"))
        result = self.run_cli(self.path)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertIn("block 001 @ file $000002: $2000-$2000 ($0001 bytes)", result.stdout)
        self.assertIn("RUN=$2000", result.stdout)
        self.assertIn("structure is valid (2 segment(s))", result.stdout)

    def test_errors_never_report_success_or_traceback(self):
        for hex_data in (
            "", "ff", "00 00", "ff ff", "ff ff 00 20 02 20 aa",
            "ff ff 05 00 00 00", "ff ff 01 20 00 20", "ff ff e0 02 e1 02 00",
            "ff ff 00 20 00 20 aa 00", "ff ff 00 20 00 20 aa 00 30",
            "ff ff 00 20 00 20 aa ff ff",
        ):
            with self.subTest(hex_data=hex_data):
                self.path.write_bytes(bytes.fromhex(hex_data))
                result = self.run_cli(self.path)
                self.assertEqual(result.returncode, 1)
                self.assertIn("file offset $", result.stderr)
                self.assertNotIn("structure is valid", result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_partial_report_and_diagnostic(self):
        self.path.write_bytes(bytes.fromhex("ff ff 00 20 00 20 aa 00 30 02 30 bb"))
        result = self.run_cli(self.path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("block 001", result.stdout)
        self.assertIn("segment 002, file offset $00000b", result.stderr)
        self.assertIn("$3000-$3002", result.stderr)
        self.assertIn("expected 3 bytes, found 1 (missing 2)", result.stderr)

    def test_missing_file_and_directory(self):
        for path in (self.path, Path(self.directory.name)):
            with self.subTest(path=path):
                result = self.run_cli(path)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Cannot read", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_permission_error(self):
        stderr = io.StringIO()
        with patch("chkxex.Path.read_bytes", side_effect=PermissionError("Permission denied")):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main([str(self.path)]), 2)
        self.assertIn("Permission denied", stderr.getvalue())

    def test_help_and_usage_errors(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Exit codes:", result.stdout)
        for args in ((), (self.path, "unexpected")):
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("usage:", result.stderr)

    def test_import_has_no_side_effects(self):
        result = subprocess.run(
            [sys.executable, "-c", "import chkxex"], cwd=SCRIPT.parent,
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout + result.stderr, "")

    def test_bounded_random_and_mutated_inputs(self):
        # A separate process gives a timeout even if the parser starts looping.
        result = subprocess.run(
            [sys.executable, "-m", "tests.test_chkxex", "--fuzz"],
            cwd=SCRIPT.parent, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fuzz cases: 3000", result.stdout)


def fuzz_inputs():
    rng = random.Random(20261002)
    seed = bytes.fromhex("ff ff 00 20 02 20 aa bb cc e0 02 e3 02 00 20 00 30")
    for index in range(3000):
        if index % 3 == 0:
            data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(128)))
        elif index % 3 == 1:
            data = b"\xff\xff" + block(0x2000, b"\xaa")
            data += bytes(rng.getrandbits(8) for _ in range(rng.randrange(128)))
        else:
            mutated = bytearray(seed)
            for _ in range(rng.randrange(1, 5)):
                mutated[rng.randrange(len(mutated))] = rng.getrandbits(8)
            data = bytes(mutated[:rng.randrange(len(mutated) + 1)])
        segments = iter_segments(data)
        while True:
            try:
                segment = next(segments)
            except (StopIteration, XexFormatError):
                break
            assert 0 <= segment.start <= segment.end <= 0xffff
            assert len(segment.data) == segment.end - segment.start + 1
            assert 2 <= segment.offset < len(data)
            describe_vectors(segment)
    print("fuzz cases: 3000")


if __name__ == "__main__":
    if sys.argv[1:] == ["--fuzz"]:
        fuzz_inputs()
    else:
        unittest.main()
