# simple Atari binary DOS file analyzer
#
# done by Seban/Slight
#
# file is released as addon to Turbo Copy 3/4 stream analyzer & decompressor
#
# Python 3.8 or newer; standard library only.
#
# .O. released at 2020.05.17
# ..O
# OOO >>> Public Domain <<<

"""Inspect the segment structure of Atari DOS binary (XEX) files."""

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from struct import unpack_from
from typing import Iterator, List, Optional, Sequence


@dataclass(frozen=True)
class Segment:
    """A complete segment; offset points to its start/end address header."""

    number: int
    offset: int
    start: int
    end: int
    data: bytes


class XexFormatError(ValueError):
    """An incomplete or invalid field at a zero-based file offset."""

    def __init__(
        self, offset: int, message: str, segment_number: Optional[int] = None
    ) -> None:
        self.offset = offset
        self.segment_number = segment_number
        location = f"file offset ${offset:06x}"
        if segment_number is not None:
            location = f"segment {segment_number:03d}, {location}"
        super().__init__(f"{location}: {message}")


def iter_segments(data: bytes) -> Iterator[Segment]:
    """Yield complete segments, then raise XexFormatError at the first error.

    Require an initial $FFFF signature and at least one segment. Repeated
    $FFFF markers are accepted before segments, but not on their own at EOF.
    Every segment must have start <= end and exactly end - start + 1 bytes.
    This checks the file's structure, not whether its program will run.
    """
    if len(data) < 2:
        raise XexFormatError(
            0, f"incomplete file signature: expected 2 bytes, found {len(data)}"
        )
    if data[:2] != b"\xff\xff":
        raise XexFormatError(0, "expected the Atari DOS $FFFF file signature")

    offset = 2
    number = 1
    while True:
        # $FFFF is a marker only at a segment boundary, never inside its data.
        while data[offset:offset + 2] == b"\xff\xff":
            offset += 2

        available = len(data) - offset
        if available < 4:
            raise XexFormatError(
                offset,
                f"incomplete segment header: expected 4 bytes, found {available} "
                f"(missing {4 - available})",
                number,
            )

        start, end = unpack_from("<HH", data, offset)
        if end < start:
            raise XexFormatError(
                offset,
                f"invalid address range ${start:04x}-${end:04x}: "
                "end address is below start address",
                number,
            )

        length = end - start + 1
        data_offset = offset + 4
        available = len(data) - data_offset
        if available < length:
            raise XexFormatError(
                data_offset,
                f"incomplete data for ${start:04x}-${end:04x}: "
                f"expected {length} bytes, found {available} "
                f"(missing {length - available})",
                number,
            )

        next_offset = data_offset + length
        yield Segment(number, offset, start, end, data[data_offset:next_offset])
        offset = next_offset
        number += 1
        if offset == len(data):
            return


def describe_vectors(segment: Segment) -> List[str]:
    """Describe RUN/INIT bytes written by this segment, without simulating DOS."""
    descriptions = []
    for name, address in (("RUN", 0x02E0), ("INIT", 0x02E2)):
        low_present = segment.start <= address <= segment.end
        high_present = segment.start <= address + 1 <= segment.end
        if low_present and high_present:
            index = address - segment.start
            value = int.from_bytes(segment.data[index:index + 2], "little")
            descriptions.append(f"{name}=${value:04x}")
        elif low_present:
            value = segment.data[address - segment.start]
            descriptions.append(f"{name} low byte (${address:04x})=${value:02x}")
        elif high_present:
            value = segment.data[address + 1 - segment.start]
            descriptions.append(
                f"{name} high byte (${address + 1:04x})=${value:02x}"
            )
    return descriptions


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect the segment structure of an Atari DOS binary (XEX) file.",
        epilog="Exit codes: 0 = valid structure, 1 = format error, 2 = usage or file error.",
    )
    parser.add_argument("filename", type=Path, help="XEX file to inspect")
    args = parser.parse_args(argv)

    try:
        data = args.filename.read_bytes()
    except OSError as error:
        print(f"Cannot read '{args.filename}': {error}", file=sys.stderr)
        return 2

    print(f"\nInput file is {args.filename} and the file size is {len(data)} bytes.\n")
    count = 0
    try:
        for segment in iter_segments(data):
            description = (
                f"block {segment.number:03d} @ file ${segment.offset:06x}: "
                f"${segment.start:04x}-${segment.end:04x} "
                f"(${len(segment.data):04x} bytes)"
            )
            vectors = describe_vectors(segment)
            if vectors:
                description += " ---> " + ", ".join(vectors)
            print(description)
            count += 1
    except XexFormatError as error:
        sys.stdout.flush()
        print(f"Error: {error}", file=sys.stderr)
        print(
            "File does not conform to the checked XEX segment structure.",
            file=sys.stderr,
        )
        return 1

    print(f"\nXEX segment structure is valid ({count} segment(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
