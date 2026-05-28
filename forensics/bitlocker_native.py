"""Pure-Python BitLocker metadata parser and decrypter.

Used as a fallback when ``libbde`` refuses to parse a volume (typically
when a single new metadata-entry version trips the strict version check
in libbde's parser). The parser here is lenient — it skips unknown
entry versions and unknown entry/value types instead of aborting, then
tries to apply credentials to whatever VMK protectors it finds.

The crypto primitives come from pycryptodome (already a dependency).
Supported encryption methods:

* 0x8000 / 0x8001  AES-128/256-CBC with Elephant Diffuser  (Vista)
* 0x8002 / 0x8003  AES-128/256-CBC                          (Win7+)
* 0x8004 / 0x8005  AES-128/256-XTS                          (Win10+)

Recovery-password protector only — TPM / startup-key / smart-card
protectors require hardware secrets we can't access from a forensic
image.

This module deliberately does not chase the Win11 22H2+ format changes
(protection_type values libbde doesn't know, larger VMK headers,
entry version 5 records). If the parser cannot resolve a VMK or the
authenticated decryption fails, we surface a clear error message and
let the existing libbde + mount-and-folder workflow take over.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Encryption methods reported in the metadata header.
ENC_AES_128_CBC_DIFFUSER = 0x8000
ENC_AES_256_CBC_DIFFUSER = 0x8001
ENC_AES_128_CBC          = 0x8002
ENC_AES_256_CBC          = 0x8003
ENC_AES_128_XTS          = 0x8004
ENC_AES_256_XTS          = 0x8005

ENC_LABELS = {
    ENC_AES_128_CBC_DIFFUSER: "AES-128-CBC + Elephant diffuser (Vista)",
    ENC_AES_256_CBC_DIFFUSER: "AES-256-CBC + Elephant diffuser (Vista)",
    ENC_AES_128_CBC:          "AES-128-CBC (Win7+)",
    ENC_AES_256_CBC:          "AES-256-CBC (Win7+)",
    ENC_AES_128_XTS:          "AES-128-XTS (Win10+)",
    ENC_AES_256_XTS:          "AES-256-XTS (Win10+)",
}

ENC_KEY_SIZES = {
    ENC_AES_128_CBC_DIFFUSER: 16,
    ENC_AES_256_CBC_DIFFUSER: 32,
    ENC_AES_128_CBC:          16,
    ENC_AES_256_CBC:          32,
    ENC_AES_128_XTS:          16,
    ENC_AES_256_XTS:          32,
}

# Entry types.
ENTRY_PROPERTY    = 0x0000
ENTRY_VOLUME_HDR  = 0x0002
ENTRY_VMK         = 0x0003
ENTRY_FVEK        = 0x0004
ENTRY_VALIDATION  = 0x0006
ENTRY_DESCRIPTION = 0x0007
ENTRY_USE_KEY     = 0x000a  # libbde calls this "VOLUME_HEADER_BLOCK" sometimes
ENTRY_AES_CCM_KEY = 0x000b
ENTRY_OFFSET_SIZE = 0x000f
ENTRY_PROTECTION  = 0x0011

# Value types.
VAL_ERASED   = 0x0000
VAL_KEY      = 0x0001
VAL_UNICODE  = 0x0002
VAL_STRETCH  = 0x0003
VAL_USE_KEY  = 0x0004
VAL_VMK      = 0x0005
VAL_EXTERNAL = 0x0006
VAL_UPDATE   = 0x0007
VAL_ERROR    = 0x0008
VAL_OFFSET_SZ = 0x000f

# Protection types (libbde-known values).
PROT_CLEAR            = 0x0000
PROT_TPM              = 0x0100
PROT_STARTUP_KEY      = 0x0200
PROT_TPM_AND_PIN      = 0x0500
PROT_RECOVERY         = 0x0800
PROT_PASSWORD         = 0x0900
PROT_FVEK             = 0x2000
PROT_TPM_AND_PIN_KEY  = 0x4000


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class BitLockerNativeError(RuntimeError):
    """Raised when our pure-Python parser can't make sense of a volume."""


try:  # pragma: no cover — optional dep, declared in requirements.txt
    from Crypto.Cipher import AES
    _HAS_CRYPTO = True
except Exception:  # noqa: BLE001
    _HAS_CRYPTO = False


# ---------------------------------------------------------------------------
# Recovery key derivation
# ---------------------------------------------------------------------------


def _recovery_key_to_intermediate(recovery: str) -> bytes:
    """Decode the printable 48-digit recovery key to a 16-byte intermediate key.

    The key is 8 groups of 6 digits, each group being a 16-bit number
    divided by 11. The 8 resulting 16-bit values concatenated form the
    128-bit intermediate key. See `MS-BDE` §3.5.2.
    """
    digits = recovery.replace("-", "").replace(" ", "").strip()
    if len(digits) != 48 or not digits.isdigit():
        raise BitLockerNativeError(
            "Recovery key must be 48 digits (8 groups of 6, optionally dashed)."
        )
    groups = [int(digits[i:i + 6]) for i in range(0, 48, 6)]
    values: list[int] = []
    for idx, group in enumerate(groups):
        if group % 11 != 0:
            raise BitLockerNativeError(
                f"Recovery-key group {idx + 1} ({group:06d}) is not divisible by 11 — "
                f"check the key for typos."
            )
        v = group // 11
        if v >= 2 ** 16:
            raise BitLockerNativeError(
                f"Recovery-key group {idx + 1} produced an out-of-range value: {v}"
            )
        values.append(v)
    return b"".join(struct.pack("<H", v) for v in values)


def _stretch_key(intermediate: bytes, salt: bytes, iterations: int = 0x100000) -> bytes:
    """Stretch the 128-bit recovery intermediate key into a 256-bit AES key.

    BitLocker uses SHA-256 chained ``iterations`` times with a fixed
    structure (last_sha256_hash || initial_sha256_hash || salt || counter).
    Reference: ``libbde_recovery.c::libbde_recovery_calculate_key``.
    """
    if len(salt) != 16:
        raise BitLockerNativeError(f"Stretch salt must be 16 bytes (got {len(salt)})")
    initial = hashlib.sha256(hashlib.sha256(intermediate).digest()).digest()
    last = b"\x00" * 32
    counter = 0
    for _ in range(iterations):
        # block = last (32) || initial (32) || salt (16) || counter (8 LE)  = 88 bytes
        block = last + initial + salt + struct.pack("<Q", counter)
        last = hashlib.sha256(block).digest()
        counter += 1
    return last  # 32 bytes


# ---------------------------------------------------------------------------
# Metadata parsing
# ---------------------------------------------------------------------------


@dataclass
class _Entry:
    size: int
    entry_type: int
    value_type: int
    version: int
    data: bytes
    offset: int  # offset within the metadata entries blob (for debugging)

    @property
    def is_unknown_version(self) -> bool:
        return self.version != 1


@dataclass
class VMKProtector:
    """A VMK candidate found in the metadata block."""

    identifier: bytes              # 16-byte GUID
    protection_type: int
    raw_body: bytes                # The full VMK body bytes after the header
    nested: List[_Entry] = field(default_factory=list)

    @property
    def is_recovery(self) -> bool:
        # Strict libbde-known recovery protector.
        return self.protection_type == PROT_RECOVERY

    @property
    def label(self) -> str:
        names = {
            PROT_CLEAR: "Clear",
            PROT_TPM: "TPM",
            PROT_STARTUP_KEY: "Startup-key",
            PROT_TPM_AND_PIN: "TPM+PIN",
            PROT_RECOVERY: "Recovery",
            PROT_PASSWORD: "Password",
            PROT_FVEK: "FVEK",
            PROT_TPM_AND_PIN_KEY: "TPM+PIN key",
        }
        return names.get(self.protection_type, f"Unknown(0x{self.protection_type:04x})")


@dataclass
class _Metadata:
    encryption_method: int
    volume_identifier: bytes
    nonce_counter: int
    entries: List[_Entry] = field(default_factory=list)
    vmks: List[VMKProtector] = field(default_factory=list)
    fvek_entries: List[_Entry] = field(default_factory=list)
    volume_header_offset: int = 0
    volume_header_size: int = 0


def _parse_entries(blob: bytes, base_offset: int = 0) -> List[_Entry]:
    """Parse a sequence of entries, skipping silently past malformed blocks."""
    out: List[_Entry] = []
    pos = 0
    while pos + 8 <= len(blob):
        size, etype, vtype, ver = struct.unpack("<HHHH", blob[pos:pos + 8])
        if size < 8 or pos + size > len(blob):
            # Pad or malformed — stop here. Real metadata is densely packed
            # so an inconsistent size means we walked past the end.
            break
        out.append(_Entry(
            size=size, entry_type=etype, value_type=vtype, version=ver,
            data=blob[pos + 8:pos + size],
            offset=base_offset + pos,
        ))
        pos += size
    return out


def parse_metadata(metadata_block: bytes) -> _Metadata:
    """Parse a single BitLocker metadata block (no decryption yet).

    *metadata_block* must start at the ``-FVE-FS-`` signature. The
    layout is:
        0x00  8   signature -FVE-FS-
        0x08  56  bde_metadata_block_header (size, version, refs to copies)
        0x40  4   metadata_size
        0x44  4   version
        0x48  4   header_size (always 0x30 in practice)
        0x4C  4   metadata_size_copy
        0x50  16  volume_identifier
        0x60  4   nonce_counter
        0x64  4   encryption_method
        0x68  8   creation_time
        0x70  ... entries
    """
    if metadata_block[:8] != b"-FVE-FS-":
        raise BitLockerNativeError(
            f"Metadata block does not start with -FVE-FS- (got {metadata_block[:8]!r})"
        )

    metadata_size = struct.unpack("<I", metadata_block[0x40:0x44])[0]
    header_size = struct.unpack("<I", metadata_block[0x48:0x4c])[0]
    if header_size < 0x30 or header_size > 0x200:
        raise BitLockerNativeError(f"Unexpected metadata_header_size: {header_size}")
    vol_id = metadata_block[0x50:0x60]
    nonce_ctr = struct.unpack("<I", metadata_block[0x60:0x64])[0]
    enc_method = struct.unpack("<I", metadata_block[0x64:0x68])[0]

    entries_start = 0x40 + header_size
    entries_end = 0x40 + metadata_size
    entries = _parse_entries(
        metadata_block[entries_start:entries_end],
        base_offset=entries_start,
    )

    md = _Metadata(
        encryption_method=enc_method,
        volume_identifier=vol_id,
        nonce_counter=nonce_ctr,
        entries=entries,
    )

    # Sort the entries into VMK / FVEK / volume-header categories.
    for entry in entries:
        if entry.entry_type == ENTRY_VMK and entry.value_type == VAL_VMK and entry.version == 1:
            md.vmks.append(_parse_vmk(entry))
        elif entry.entry_type == ENTRY_FVEK and entry.version == 1:
            md.fvek_entries.append(entry)
        elif entry.entry_type == ENTRY_VOLUME_HDR and entry.value_type == VAL_OFFSET_SZ and entry.version == 1:
            md.volume_header_offset, md.volume_header_size = struct.unpack(
                "<QQ", entry.data[:16],
            )
        elif entry.entry_type == ENTRY_OFFSET_SIZE and entry.version == 1:
            # Some images put the volume header block under this type code.
            try:
                md.volume_header_offset, md.volume_header_size = struct.unpack(
                    "<QQ", entry.data[:16],
                )
            except struct.error:
                pass
    return md


def _parse_vmk(entry: _Entry) -> VMKProtector:
    if len(entry.data) < 26:
        raise BitLockerNativeError("VMK entry too short to hold its header")
    identifier = entry.data[:16]
    # libbde docs: 16 id, 8 last_change_time, 2 protection_type, then nested entries.
    prot = struct.unpack("<H", entry.data[24:26])[0]
    nested = _parse_entries(entry.data[26:], base_offset=entry.offset + 8 + 26)
    return VMKProtector(
        identifier=identifier,
        protection_type=prot,
        raw_body=entry.data,
        nested=nested,
    )


# ---------------------------------------------------------------------------
# AES-CCM helpers
# ---------------------------------------------------------------------------


def _aes_ccm_unwrap(key: bytes, nonce: bytes, mac: bytes, ciphertext: bytes) -> bytes:
    """Authenticated decrypt with AES-CCM (libbde's parameters).

    BitLocker uses CCM with:
      * 12-byte nonce
      * 16-byte MAC
      * 4-byte length field (so L = 4)
    pycryptodome accepts these as ``nonce``, ``mac_len``.
    """
    if not _HAS_CRYPTO:
        raise BitLockerNativeError(
            "pycryptodome is not installed — required for native BitLocker support."
        )
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=len(mac))
    return cipher.decrypt_and_verify(ciphertext, mac)


def _try_unwrap_aes_ccm_entry(entry: _Entry, key: bytes) -> Optional[bytes]:
    """Try the libbde-style AES-CCM unwrap of an ``AES_CCM_ENCRYPTED_KEY`` entry.

    Layout (libbde_aes_ccm_encrypted_key.c):
        12 bytes: nonce
        16 bytes: MAC
        remaining: ciphertext (variable, often 32 or 48 bytes plaintext)
    """
    if entry.entry_type != ENTRY_AES_CCM_KEY:
        return None
    data = entry.data
    if len(data) < 12 + 16 + 1:
        return None
    nonce = data[:12]
    mac = data[12:28]
    ct = data[28:]
    try:
        return _aes_ccm_unwrap(key, nonce, mac, ct)
    except (ValueError, KeyError) as exc:
        logger.debug("AES-CCM unwrap failed (likely wrong key): %s", exc)
        return None


# ---------------------------------------------------------------------------
# Sector decryption
# ---------------------------------------------------------------------------


def _decrypt_sector_xts(
    fvek: bytes,
    tweak_key: bytes,
    sector_offset: int,
    ciphertext: bytes,
    sector_size: int = 512,
) -> bytes:
    """Decrypt sectors using AES-XTS where the tweak is the sector index.

    BitLocker derives the tweak from the byte offset divided by the
    sector size. pycryptodome's XTS expects the data unit number as
    bytes_le128.
    """
    out = bytearray()
    sector = sector_offset // sector_size
    for s_idx in range(0, len(ciphertext), sector_size):
        block = ciphertext[s_idx:s_idx + sector_size]
        tweak = struct.pack("<Q", sector) + b"\x00" * 8
        cipher = AES.new(fvek + tweak_key, AES.MODE_XTS, sector_size=sector_size, initial_value=tweak)
        out.extend(cipher.decrypt(block))
        sector += 1
    return bytes(out)


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------


@dataclass
class NativeUnlockResult:
    """Outcome of a native-unlock attempt."""

    success: bool
    fvek: Optional[bytes] = None
    tweak_key: Optional[bytes] = None
    encryption_method: int = 0
    volume_header_offset: int = 0
    volume_header_size: int = 0
    reason: str = ""

    @property
    def description(self) -> str:
        if self.success:
            label = ENC_LABELS.get(self.encryption_method, f"0x{self.encryption_method:04x}")
            return f"Unlocked ({label})"
        return f"Native unlock failed: {self.reason}"


def try_native_unlock_with_recovery_key(
    metadata_block: bytes,
    recovery_key: str,
) -> NativeUnlockResult:
    """Try to derive FVEK + tweak key from *metadata_block* + *recovery_key*.

    Returns a ``NativeUnlockResult`` describing the outcome. This is
    best-effort: parsing or AES-CCM verification can fail for Win11
    22H2+ images where Microsoft changed the VMK structure.
    """
    if not _HAS_CRYPTO:
        return NativeUnlockResult(
            success=False,
            reason="pycryptodome is not installed",
        )

    try:
        md = parse_metadata(metadata_block)
    except BitLockerNativeError as exc:
        return NativeUnlockResult(success=False, reason=f"metadata parse failed: {exc}")

    try:
        intermediate = _recovery_key_to_intermediate(recovery_key)
    except BitLockerNativeError as exc:
        return NativeUnlockResult(success=False, reason=str(exc))

    if not md.vmks:
        return NativeUnlockResult(
            success=False,
            reason="no VMK entries found in metadata",
        )

    vmk_value: Optional[bytes] = None
    for vmk in md.vmks:
        # Look for a STRETCH_KEY nested entry that gives us the salt
        # for PBKDF2-style stretching, then an AES_CCM_ENCRYPTED_KEY for
        # the wrapped VMK.
        stretch_entry: Optional[_Entry] = None
        ccm_entry: Optional[_Entry] = None
        for nested in vmk.nested:
            if nested.value_type == VAL_STRETCH and stretch_entry is None:
                stretch_entry = nested
            elif nested.entry_type == ENTRY_AES_CCM_KEY and ccm_entry is None:
                ccm_entry = nested
        if not stretch_entry or not ccm_entry:
            logger.debug(
                "VMK %s: missing stretch or AES-CCM entry (got %s)",
                vmk.label, [(e.entry_type, e.value_type) for e in vmk.nested],
            )
            continue
        # Stretch entry layout (libbde_stretch_key.c):
        #   4 bytes: encryption method
        #   16 bytes: salt
        #   rest:    nested key entry (we ignore)
        if len(stretch_entry.data) < 20:
            continue
        salt = stretch_entry.data[4:20]
        try:
            stretched = _stretch_key(intermediate, salt)
        except BitLockerNativeError as exc:
            logger.debug("stretch failed: %s", exc)
            continue
        try:
            candidate = _try_unwrap_aes_ccm_entry(ccm_entry, stretched)
        except BitLockerNativeError:
            candidate = None
        if candidate is not None:
            vmk_value = candidate
            break

    if vmk_value is None:
        labels = [v.label for v in md.vmks]
        return NativeUnlockResult(
            success=False,
            reason=(
                "no VMK protector responded to the recovery key derivation. "
                f"VMK protectors found: {', '.join(labels) or '(none)'}. "
                "This image's metadata may use the Win11 22H2+ format that "
                "added new protector layouts (entry version 5 records) — those "
                "are not yet supported by this native parser."
            ),
        )

    # The unwrapped VMK is itself an entry blob: a single AES_CCM_ENCRYPTED_KEY
    # entry wrapping the FVEK. Parse it and unwrap.
    inner = _parse_entries(vmk_value)
    fvek_blob: Optional[bytes] = None
    for entry in inner:
        if entry.entry_type == ENTRY_AES_CCM_KEY and entry.value_type == VAL_KEY:
            # We need the actual VMK bytes, which are the value of the
            # KEY entry inside the unwrapped CCM-decrypted blob.
            # libbde returns the inner key directly.
            fvek_blob = entry.data
            break

    if fvek_blob is None:
        # Sometimes the inner blob IS just key bytes (entry-less). Try that.
        if len(vmk_value) in (32, 48, 64):
            fvek_blob = vmk_value

    if fvek_blob is None:
        return NativeUnlockResult(
            success=False,
            reason="VMK was unwrapped but the FVEK inside it has an unexpected layout",
        )

    # Now find the FVEK entry at the top level — it's an AES_CCM_ENCRYPTED_KEY
    # encrypted with the VMK we just derived.
    fvek_ct_entry: Optional[_Entry] = None
    for entry in md.entries:
        if entry.entry_type == ENTRY_FVEK and entry.version == 1:
            # FVEK entry's data is again an AES_CCM_ENCRYPTED_KEY blob.
            inner_fvek = _parse_entries(entry.data)
            for nested in inner_fvek:
                if nested.entry_type == ENTRY_AES_CCM_KEY:
                    fvek_ct_entry = nested
                    break
            if fvek_ct_entry is not None:
                break

    if fvek_ct_entry is None:
        # As fallback, use the unwrapped VMK directly as the FVEK (older
        # images sometimes store the FVEK directly inside the VMK).
        fvek_bytes = fvek_blob
    else:
        # The first 16 bytes of fvek_blob are the actual VMK key.
        actual_vmk = fvek_blob[:32] if len(fvek_blob) >= 32 else fvek_blob[:16]
        # Unwrap the FVEK using the VMK as the AES-CCM key.
        unwrapped = _try_unwrap_aes_ccm_entry(fvek_ct_entry, actual_vmk)
        if unwrapped is None:
            return NativeUnlockResult(
                success=False,
                reason="VMK unwrapped but FVEK AES-CCM verification failed (key/structure mismatch)",
            )
        fvek_bytes = unwrapped

    # The decrypted FVEK blob carries the key + (for XTS) the tweak key.
    key_size = ENC_KEY_SIZES.get(md.encryption_method, 0)
    if key_size == 0:
        return NativeUnlockResult(
            success=False,
            reason=f"unsupported encryption method: 0x{md.encryption_method:04x}",
        )

    if md.encryption_method in (ENC_AES_128_XTS, ENC_AES_256_XTS):
        if len(fvek_bytes) < 2 * key_size:
            return NativeUnlockResult(
                success=False,
                reason=f"FVEK blob too short for XTS (need {2 * key_size}, got {len(fvek_bytes)})",
            )
        fvek = fvek_bytes[:key_size]
        tweak = fvek_bytes[key_size:2 * key_size]
    else:
        if len(fvek_bytes) < key_size:
            return NativeUnlockResult(
                success=False,
                reason=f"FVEK blob too short ({key_size} required)",
            )
        fvek = fvek_bytes[:key_size]
        tweak = b""

    return NativeUnlockResult(
        success=True,
        fvek=fvek,
        tweak_key=tweak,
        encryption_method=md.encryption_method,
        volume_header_offset=md.volume_header_offset,
        volume_header_size=md.volume_header_size,
    )


# ---------------------------------------------------------------------------
# Convenience: full file-object decryptor for pytsk3 consumption
# ---------------------------------------------------------------------------


class NativeBitLockerVolume:
    """Decrypt-on-read view over a BitLocker partition.

    Constructed with the partition's file-like object (raw encrypted
    bytes), an :class:`NativeUnlockResult` that already supplied the
    FVEK + tweak key, and the sector size (always 512 in BitLocker).

    ``read(offset, size)`` decrypts the requested range on the fly and
    returns plaintext. The original NTFS boot sector that BitLocker
    moved out of the way is restored over the relocated header range
    when ``volume_header_offset`` is non-zero — same trick libbde does.
    """

    SECTOR_SIZE = 512

    def __init__(self, file_object, unlock: NativeUnlockResult) -> None:
        if not unlock.success:
            raise BitLockerNativeError(f"Cannot wrap an unsuccessful unlock: {unlock.reason}")
        self._fo = file_object
        self._fvek = unlock.fvek
        self._tweak = unlock.tweak_key
        self._method = unlock.encryption_method
        self._vol_hdr_offset = unlock.volume_header_offset
        self._vol_hdr_size = unlock.volume_header_size
        self._size = file_object.get_size() if hasattr(file_object, "get_size") else 0

    def get_size(self) -> int:
        return self._size

    def read(self, offset: int, size: int) -> bytes:
        # Align to sector boundaries: read whole sectors then trim.
        aligned_start = (offset // self.SECTOR_SIZE) * self.SECTOR_SIZE
        aligned_end = ((offset + size + self.SECTOR_SIZE - 1) // self.SECTOR_SIZE) * self.SECTOR_SIZE
        if hasattr(self._fo, "seek"):
            self._fo.seek(aligned_start)
            cipher_blob = self._fo.read(aligned_end - aligned_start)
        else:
            cipher_blob = self._fo.read(aligned_start, aligned_end - aligned_start)
        if self._method in (ENC_AES_128_XTS, ENC_AES_256_XTS):
            plain = _decrypt_sector_xts(self._fvek, self._tweak, aligned_start, cipher_blob, self.SECTOR_SIZE)
        else:
            # CBC path not yet implemented — keep a clear failure rather
            # than returning corrupted data.
            raise BitLockerNativeError(
                f"Native decryption for encryption method 0x{self._method:04x} not yet implemented"
            )
        offset_into = offset - aligned_start
        return plain[offset_into:offset_into + size]
