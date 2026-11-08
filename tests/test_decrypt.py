"""Offline regressions using synthetic licenses, Mach-O slices, and IPA files."""

from __future__ import annotations

import contextlib
import hashlib
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import core
import decrypt

CREDENTIAL = bytes(range(16))
WORK = bytes(range(16, 32))


def atom(tag: bytes, payload: bytes) -> bytes:
    return struct.pack(">I4s", 8 + len(payload), tag) + payload


def license_sinf(priv_size: int = 448) -> bytes:
    # A tag inside a different atom must not shadow the real priv field.
    name = b"synthetic priv marker"
    iviv = bytes(range(32, 48))
    clear = bytearray(448 if priv_size == 448 else 432)
    clear[:4], clear[20:24], clear[44:48] = b"itun", b"key ", b"iviv"
    clear[24:40] = WORK
    key = bytes(value ^ 0x30 for value in CREDENTIAL)
    cipher = Cipher(algorithms.AES(key), modes.CBC(hashlib.md5(name + iviv).digest()))
    op = cipher.encryptor()
    private = op.update(clear) + op.finalize()
    if priv_size == 440:
        private += bytes(8)
    return atom(
        b"sinf",
        atom(
            b"schi",
            atom(b"name", name + b"\0") + atom(b"iviv", iviv) + atom(b"priv", private),
        ),
    )


def thin_slice(
    subtype: int, cryptid: int = 1, encryption_command: bool = True
) -> bytes:
    command = (
        struct.pack("<6I", 0x2C, 24, core.PAGE_SIZE, core.PAGE_SIZE, cryptid, 0)
        if encryption_command
        else b""
    )
    header = struct.pack(
        "<8I", 0xFEEDFACF, core.ARM64, subtype, 2, bool(command), len(command), 0, 0
    )
    return (header + command).ljust(core.PAGE_SIZE * 2, b"\0")


def fat_binary(slices: list[tuple[int, bytes]], fat64: bool) -> tuple[bytes, list[int]]:
    result = bytearray(core.PAGE_SIZE)
    struct.pack_into(">II", result, 0, 0xCAFEBABF if fat64 else 0xCAFEBABE, len(slices))
    bases = []
    for index, (subtype, data) in enumerate(slices):
        base = len(result)
        bases.append(base)
        if fat64:
            struct.pack_into(
                ">IIQQII",
                result,
                8 + index * 32,
                core.ARM64,
                subtype,
                base,
                len(data),
                12,
                0,
            )
        else:
            struct.pack_into(
                ">IIIII",
                result,
                8 + index * 20,
                core.ARM64,
                subtype,
                base,
                len(data),
                12,
            )
        result.extend(data)
    return bytes(result), bases


def encrypted_fixture(
    fat64: bool = False, supf_version: int = 5
) -> tuple[bytes, bytes, bytes]:
    source_bytes, bases = fat_binary([(0, thin_slice(0)), (2, thin_slice(2))], fat64)
    source = bytearray(source_bytes)
    expected = bytearray(source)
    records = {}
    for subtype, base in zip((0, 2), bases):
        wrapped = bytes(value + subtype for value in range(16))
        iv = bytes(value + subtype for value in range(16, 32))
        start = base + core.PAGE_SIZE
        clear = bytes((value + subtype) % 256 for value in range(core.PAGE_SIZE))
        key = core.derive_page_key(wrapped, start // core.PAGE_SIZE, WORK)
        op = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        source[start : start + core.PAGE_SIZE] = op.update(clear) + op.finalize()
        expected[start : start + core.PAGE_SIZE] = clear
        struct.pack_into("<I", expected, base + 48, 0)
        records[subtype] = wrapped + iv
    supf = bytes([supf_version]) + b"612" + bytes(4) + struct.pack(">I", len(records))
    header_size = 32 if supf_version == 3 else 12
    # Reverse SUPF order to detect selecting the first ARM64 entry for both slices.
    for subtype in (2, 0):
        supf += (
            struct.pack(">III", header_size + 32, core.ARM64, subtype)
            + bytes(header_size - 12)
            + struct.pack(">I", 1)
            + records[subtype]
        )
    return bytes(source), bytes(expected), supf


class MachoTests(unittest.TestCase):
    def test_page_keys_match_original_c_transform(self):
        # Derived independently with the original C transform at 0c952e1.
        vectors = (
            ("00" * 16, 0, "00" * 16, "474cf2dec25b2bb27309fd095d03f94d"),
            (
                "000102030405060708090a0b0c0d0e0f",
                1,
                "101112131415161718191a1b1c1d1e1f",
                "bb6190517f163774d138de16d08b702c",
            ),
            (
                "ff" * 16,
                2**32 - 1,
                "ff" * 16,
                "4bf0322d2bf8ddc3c209df1d39663c16",
            ),
            (
                "00112233445566778899aabbccddeeff",
                0x12345678,
                "000102030405060708090a0b0c0d0e0f",
                "11be9e22ff375a7415b62da726a5da21",
            ),
        )
        for wrapped, page, work, expected in vectors:
            with self.subTest(page=page):
                self.assertEqual(
                    core.derive_page_key(
                        bytes.fromhex(wrapped), page, bytes.fromhex(work)
                    ),
                    bytes.fromhex(expected),
                )

    def test_decrypts_each_arm64_subtype_in_fat32_and_fat64(self):
        for fat64 in (False, True):
            for supf_version in (3, 5):
                with self.subTest(fat64=fat64, supf_version=supf_version):
                    source, expected, supf = encrypted_fixture(fat64, supf_version)
                    result, pages = core.decrypt_binary(
                        source, license_sinf(), supf, CREDENTIAL
                    )
                    self.assertEqual(result, expected)
                    self.assertEqual(pages, 2)
                    self.assertEqual(core.arm64_encryption_infos(result), [])

    def test_skips_clear_slices_with_or_without_encryption_command(self):
        for fat64 in (False, True):
            with self.subTest(fat64=fat64):
                source, bases = fat_binary(
                    [
                        (0, thin_slice(0)),
                        (2, thin_slice(2, cryptid=0)),
                        (1, thin_slice(1, encryption_command=False)),
                    ],
                    fat64,
                )
                infos = core.arm64_encryption_infos(source)
                self.assertEqual(
                    [(info.base, info.subtype) for info in infos], [(bases[0], 0)]
                )

    def test_rejects_mismatched_load_command_totals(self):
        source = bytearray(thin_slice(0))
        struct.pack_into("<I", source, 20, 32)
        with self.assertRaisesRegex(ValueError, "load command sizes do not match"):
            core.arm64_encryption_infos(source)

    def test_requires_matching_supf_subtype(self):
        _, _, supf = encrypted_fixture()
        with self.assertRaisesRegex(ValueError, "arm64 SUPF record missing"):
            core.arm64_supf_record_offset(supf, 1, 1)

    def test_sinf_priv_is_found_at_atom_boundary(self):
        for priv_size in (440, 448):
            with self.subTest(priv_size=priv_size):
                self.assertEqual(
                    core.derive_work16(CREDENTIAL, license_sinf(priv_size)), WORK
                )


class IpaTests(unittest.TestCase):
    def test_decrypts_ipa_streams_assets_and_preserves_member_metadata(self):
        source, expected, supf = encrypted_fixture()
        binary_name = "Payload/Demo.app/Demo"
        asset_name = "Payload/Demo.app/large.dat"
        asset = bytes(range(256)) * 1024
        info = ZipInfo(asset_name, date_time=(2024, 3, 4, 5, 6, 8))
        info.compress_type = ZIP_DEFLATED
        info.create_system = 3
        info.external_attr = 0o100640 << 16
        info.comment = b"synthetic asset"
        info.extra = struct.pack("<HH", 0xCAFE, 4) + b"test"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original, output, credential = (
                root / "input.ipa",
                root / "output.ipa",
                root / "credential.bin",
            )
            credential.write_bytes(CREDENTIAL)
            with ZipFile(original, "w") as archive:
                archive.writestr(binary_name, source)
                archive.writestr("Payload/Demo.app/SC_Info/Demo.sinf", license_sinf())
                archive.writestr("Payload/Demo.app/SC_Info/Demo.supf", supf)
                archive.writestr(info, asset)
            original_bytes = original.read_bytes()
            original_read = ZipFile.read

            def guarded_read(archive, member, *args, **kwargs):
                name = member.filename if isinstance(member, ZipInfo) else member
                self.assertNotEqual(
                    name, asset_name, "unchanged assets must be streamed"
                )
                return original_read(archive, member, *args, **kwargs)

            arguments = [
                "decrypt.py",
                str(original),
                str(output),
                "--credential",
                str(credential),
            ]
            with mock.patch.object(sys, "argv", arguments), mock.patch.object(
                ZipFile, "read", guarded_read
            ), contextlib.redirect_stdout(io.StringIO()):
                decrypt.main()
            self.assertEqual(original.read_bytes(), original_bytes)
            with ZipFile(original) as before, ZipFile(output) as after:
                self.assertEqual(after.namelist(), before.namelist())
                self.assertEqual(after.read(binary_name), expected)
                for name in before.namelist():
                    if name != binary_name:
                        self.assertEqual(after.read(name), before.read(name))
                    for field in (
                        "date_time",
                        "compress_type",
                        "create_system",
                        "external_attr",
                        "comment",
                        "extra",
                        "file_size",
                    ):
                        self.assertEqual(
                            getattr(after.getinfo(name), field),
                            getattr(before.getinfo(name), field),
                        )
            output_bytes = output.read_bytes()
            with mock.patch.object(sys, "argv", arguments), contextlib.redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit) as raised:
                decrypt.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(output.read_bytes(), output_bytes)


if __name__ == "__main__":
    unittest.main()
