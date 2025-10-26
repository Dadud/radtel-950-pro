#!/usr/bin/env python3
"""Flash Radtel RT-950 firmware over the USB CDC update protocol.

This script implements the protocol observed in the captured USB traces:

- Packets are framed as: 0xAA | CMD | u16:param1 (big-endian) | u16:param2 |
  payload[param2] | u16:CRC16-XMODEM | 0x55
- All acks mirror the command with param1=0x0006 on success.
- Data blocks (CMD=0x03) use param1 as the chunk index and param2 as the
  payload length (usually 1024 bytes).

The tool can accept a raw binary image (already ready to send) or a RT*.BTF
file. For BTF files we implement the FwCrypt decode (same logic as
fwcrypt_io.py) to obtain the plaintext firmware before chunking.

Example usage:
    python radtel_flash.py --port /dev/ttyACM0 firmware.bin
    python radtel_flash.py --port COM5 firmware.btf

You need pyserial installed (pip install pyserial) and the radio connected in
USB update mode. The script reproduces the captured handshake:
    1. ASCII "PROGRAMBT9000U" (expects ACK 0x06)
    2. ASCII "UPDATE" (expects ACK 0x06)
    3. CMD 0x42 (enter binary mode)
    4. CMD 0x0A with payload "BOOTLOADER_V3"
    5. CMD 0x02 with static 32-byte metadata (model + signature)
    6. CMD 0x04 with payload 0x01 0x78
    7. CMD 0x03 for each 1024-byte chunk of the firmware
    8. CMD 0x45 to finalise and trigger reboot

The metadata payloads (commands 0x02 and 0x04) are hard-coded from the trace:
- 0x02 payload: b" RT-950      \x00\x00\x00\x00" + signature (16 bytes)
- 0x04 payload: b"\x01\x78"

If future discoveries show these depend on the firmware image, adapt the
builder functions accordingly.
"""

from __future__ import annotations

import argparse
import math
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple

try:
    import serial  # type: ignore
except ImportError:  # pragma: no cover - runtime dependency only
    serial = None  # Allow import so argparse help works.

# --- FwCrypt decode (mirrors firmware/scripts/fwcrypt_io.py) -----------------

BLOCK_SKIP_SIZE = 0x800
BASE_KEY_OFFSET = 0x400
BASE_KEY_LEN = 16
FULL_KEY_LEN = 128


def _rol8(value: int, shift: int) -> int:
    return ((value << shift) & 0xFF) | (value >> (8 - shift))


def _ror8(value: int, shift: int) -> int:
    return ((value >> shift) | ((value << (8 - shift)) & 0xFF)) & 0xFF


def build_fwcrypt_key(fw: bytes) -> bytes:
    if len(fw) < BASE_KEY_OFFSET + BASE_KEY_LEN:
        raise ValueError("Firmware too short to contain base key")
    key = bytearray(FULL_KEY_LEN)
    key[:BASE_KEY_LEN] = fw[BASE_KEY_OFFSET:BASE_KEY_OFFSET + BASE_KEY_LEN]
    for j in range(16, FULL_KEY_LEN, 16):
        for i in range(j, j + 8):
            key[i] = _rol8(key[i - 16], 1)
        for i in range(j + 8, j + 16):
            key[i] = _ror8(key[i - 16], 1)
    return bytes(key)


def fwcrypt_transform(fw_bytes: bytearray, key: bytes) -> bytearray:
    for i in range(BLOCK_SKIP_SIZE, len(fw_bytes)):
        current = fw_bytes[i]
        if current in (0x00, 0xFF):
            continue
        mask = key[i % FULL_KEY_LEN]
        transformed = current ^ mask
        if transformed in (0x00, 0xFF):
            continue
        fw_bytes[i] = transformed
    return fw_bytes


def load_firmware(image_path: Path, *, treat_as_raw: bool = False) -> bytes:
    data = image_path.read_bytes()
    if treat_as_raw:
        return data
    key = build_fwcrypt_key(data)
    decoded = fwcrypt_transform(bytearray(data), key)
    return bytes(decoded)

# --- CRC16-XMODEM -----------------------------------------------------------

CRC16_POLY = 0x1021


def crc16_xmodem(data: bytes) -> int:
    reg = 0x0000
    for byte in data:
        reg ^= byte << 8
        for _ in range(8):
            if reg & 0x8000:
                reg = ((reg << 1) ^ CRC16_POLY) & 0xFFFF
            else:
                reg = (reg << 1) & 0xFFFF
    return reg & 0xFFFF

# --- Protocol helpers -------------------------------------------------------

PACKET_START = 0xAA
PACKET_END = 0x55
SUCCESS_CODE = 0x0006
DEFAULT_CHUNK_SIZE = 1024

# Command identifiers (from capture)
CMD_ENTER_BINARY = 0x42
CMD_BOOT_VERSION = 0x0A
CMD_METADATA = 0x02
CMD_CONFIG = 0x04
CMD_DATA = 0x03
CMD_FINALISE = 0x45

# Static payloads derived from capture / updater
BOOT_VERSION_PAYLOAD = b"BOOTLOADER_V3"
ASCII_PROGRAM = b"PROGRAMBT9000U"
ASCII_UPDATE = b"UPDATE"


@dataclass
class Packet:
    cmd: int
    param1: int
    param2: int
    payload: bytes


class ProtocolError(RuntimeError):
    pass


class CDCFlasher:
    def __init__(self, port: str, baudrate: int, timeout: float) -> None:
        if serial is None:
            raise RuntimeError("pyserial is required. Install with 'pip install pyserial'.")
        self._ser = serial.Serial(port=port, baudrate=baudrate, timeout=timeout, write_timeout=timeout)
        self._timeout = timeout

    def close(self) -> None:
        if self._ser:
            self._ser.close()

    # Context manager support
    def __enter__(self) -> "CDCFlasher":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # pragma: no cover - context cleanup
        self.close()

    def _read_exact(self, size: int) -> bytes:
        data = self._ser.read(size)
        if len(data) != size:
            raise ProtocolError(f"Timeout waiting for {size} bytes (got {len(data)})")
        return data

    def read_response(self) -> Tuple[str, Optional[Packet]]:
        deadline = time.time() + self._timeout
        while True:
            if time.time() > deadline:
                raise ProtocolError("Timed out waiting for response")
            byte = self._ser.read(1)
            if not byte:
                continue
            if byte == b"\x06":
                return ("ack-byte", None)
            if byte[0] != PACKET_START:
                # Skip unexpected byte and keep searching for frame start
                continue
            header = self._read_exact(1 + 2 + 2)
            cmd = header[0]
            param1 = int.from_bytes(header[1:3], "big")
            param2 = int.from_bytes(header[3:5], "big")
            payload = self._read_exact(param2) if param2 else b""
            crc_bytes = self._read_exact(2)
            end_byte = self._read_exact(1)
            if end_byte[0] != PACKET_END:
                raise ProtocolError(f"Invalid frame terminator: 0x{end_byte[0]:02x}")
            crc_calc = crc16_xmodem(bytes([cmd]) + header[1:] + payload)
            crc_recv = int.from_bytes(crc_bytes, "big")
            if crc_calc != crc_recv:
                raise ProtocolError(
                    f"CRC mismatch for cmd 0x{cmd:02x}: expected 0x{crc_calc:04x}, got 0x{crc_recv:04x}"
                )
            return ("packet", Packet(cmd=cmd, param1=param1, param2=param2, payload=payload))

    def send_ascii(self, payload: bytes, desc: str) -> None:
        self._ser.write(payload)
        kind, pkt = self.read_response()
        if kind != "ack-byte" or pkt is not None:
            raise ProtocolError(f"Expected single-byte ACK after {desc}, received {kind}")

    def send_packet(self, cmd: int, param1: int, payload: bytes, *, param2: Optional[int] = None) -> Packet:
        if param2 is None:
            param2 = len(payload)
        frame = bytearray()
        frame.append(PACKET_START)
        frame.append(cmd)
        frame.extend(param1.to_bytes(2, "big"))
        frame.extend(param2.to_bytes(2, "big"))
        frame.extend(payload)
        crc = crc16_xmodem(bytes([cmd]) + frame[2:6] + payload)
        frame.extend(crc.to_bytes(2, "big"))
        frame.append(PACKET_END)
        self._ser.write(frame)
        kind, pkt = self.read_response()
        if kind != "packet" or pkt is None:
            raise ProtocolError(f"Unexpected response type {kind} for command 0x{cmd:02x}")
        if pkt.cmd != cmd:
            raise ProtocolError(f"Mismatched ACK cmd (got 0x{pkt.cmd:02x}, expected 0x{cmd:02x})")
        if pkt.param1 != SUCCESS_CODE:
            raise ProtocolError(f"Device reported error 0x{pkt.param1:04x} for cmd 0x{cmd:02x}")
        return pkt


def chunk_firmware(data: bytes, chunk_size: int) -> Iterable[bytes]:
    for offset in range(0, len(data), chunk_size):
        yield data[offset:offset + chunk_size]


def extract_model_metadata(firmware: bytes) -> bytes:
    """Replicates the OEM updater behaviour of reading 32 bytes at offset 0x3E0."""
    start = 0x3E0
    end = start + 32
    if len(firmware) >= end:
        return firmware[start:end]
    if len(firmware) <= start:
        return b"\x00" * 32
    segment = bytearray(firmware[start:])
    segment.extend(b"\x00" * (32 - len(segment)))
    return bytes(segment)


def encode_total_package_field(total_chunks: int) -> bytes:
    if total_chunks <= 0:
        value = 0
    elif total_chunks == 1:
        value = 1
    else:
        value = total_chunks - 1
    return value.to_bytes(2, "big")


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Flash RT-950 firmware over USB CDC")
    parser.add_argument("image", type=Path, help="Path to .btf or raw firmware image")
    parser.add_argument("--port", required=True, help="Serial port (e.g. COM5, /dev/ttyACM0)")
    parser.add_argument("--baud", type=int, default=115200, help="UART baud rate (default: 115200)")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="Payload bytes per CMD=0x03 packet")
    parser.add_argument("--skip-handshake", action="store_true", help="Skip the PROGRAM/UPDATE ASCII handshake")
    parser.add_argument("--raw", action="store_true", help="Treat the input file as a ready-to-send binary (skip fwcrypt decode)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Serial read/write timeout in seconds")
    parser.add_argument("--resume", type=int, default=0, help="Start chunk index (for manual resume)")

    args = parser.parse_args(list(argv) if argv is not None else None)

    firmware = load_firmware(args.image, treat_as_raw=args.raw)
    if args.chunk_size <= 0:
        parser.error("chunk size must be positive")
    original_length = len(firmware)
    total_chunks = math.ceil(original_length / args.chunk_size) if original_length else 0
    padding = (-original_length) % args.chunk_size
    if padding:
        firmware = firmware + (b"\x00" * padding)
    metadata_payload = extract_model_metadata(firmware[:original_length])
    package_field = encode_total_package_field(total_chunks)

    print(f"Loaded firmware: {len(firmware)} bytes ({total_chunks} chunks of {args.chunk_size} bytes)")
    if args.resume:
        if not (0 <= args.resume < total_chunks):
            parser.error("--resume chunk index out of range")
        print(f"Resuming from chunk {args.resume}")

    with CDCFlasher(args.port, args.baud, args.timeout) as flasher:
        if not args.skip_handshake:
            print("[1/6] Sending PROGRAMBT9000U handshake…")
            flasher.send_ascii(ASCII_PROGRAM, "PROGRAM handshake")
            print("      Device ACKed")
            print("[2/6] Sending UPDATE handshake…")
            flasher.send_ascii(ASCII_UPDATE, "UPDATE handshake")
            print("      Device ACKed")
        else:
            print("Skipping ASCII handshake as requested")

        print("[3/6] Entering binary mode (CMD=0x42)…")
        flasher.send_packet(CMD_ENTER_BINARY, 0x0000, b"")

        print("[4/6] Sending bootloader info (CMD=0x0A)…")
        flasher.send_packet(CMD_BOOT_VERSION, 0x0000, BOOT_VERSION_PAYLOAD)

        print("[5/6] Sending metadata (CMD=0x02)…")
        flasher.send_packet(CMD_METADATA, 0x0000, metadata_payload)

        print("[6/6] Sending package count (CMD=0x04)…")
        flasher.send_packet(CMD_CONFIG, 0x0000, package_field)

        print("Transmitting firmware chunks…")
        start_chunk = args.resume
        for chunk_index in range(start_chunk, total_chunks):
            chunk = firmware[chunk_index * args.chunk_size : (chunk_index + 1) * args.chunk_size]
            flasher.send_packet(CMD_DATA, chunk_index, chunk)
            if chunk_index % 10 == 0 or chunk_index == total_chunks - 1:
                pct = (chunk_index + 1) * 100 / total_chunks
                print(f"  Chunk {chunk_index + 1}/{total_chunks} ({pct:.1f}%)")

        print("Finalising (CMD=0x45)…")
        flasher.send_packet(CMD_FINALISE, 0x0000, b"")

    print("Flash transfer complete. The radio should reboot shortly.")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    try:
        raise SystemExit(main())
    except ProtocolError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
