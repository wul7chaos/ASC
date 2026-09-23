"""MUTF-8 string decoding regressions.

`DEX.get_string` used to slice `utf16_size` BYTES out of a string_data_item,
but that field counts UTF-16 CODE UNITS. Every non-ASCII name was therefore
truncated mid-character: on a hardened sample whose classes are named with
Thai/Yi/Syriac code points, `Ll/᩻ܶ;` (6 units, 9 bytes) decoded as `Ll/᩻`, the
type_ids binary search never matched, and `getclass` answered "not found in
DEX" for the app's own package.
"""
import struct
import unittest

from droidasc.asc_core.utils.tinydex import DEX, decode_mutf8, mutf8_end


def mutf8_encode(text):
    """Dalvik MUTF-8: U+0000 as C0 80, supplementary chars as CESU-8."""
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if cp == 0:
            out += b'\xc0\x80'
        else:
            out += ch.encode('utf-8', 'surrogatepass')
    return bytes(out)


def make_dex_with_strings(strings):
    """Minimal DEX whose string table holds `strings` (class descriptors)."""
    header_size = 0x70
    encoded = [mutf8_encode(s) for s in strings]
    units = [len(s.encode('utf-16-le')) // 2 for s in strings]

    buf = bytearray(header_size)
    string_ids = len(buf)
    buf.extend(bytes(4 * len(encoded)))
    type_ids = len(buf)
    buf.extend(bytes(4 * len(encoded)))
    # type_ids must be sorted by string index; the caller passes sorted input.
    for index in range(len(encoded)):
        struct.pack_into('<I', buf, type_ids + index * 4, index)
    class_defs = len(buf)
    buf.extend(bytes(32 * len(encoded)))
    data_off = len(buf)

    def uleb(value):
        out = bytearray()
        while value > 0x7F:
            out.append((value & 0x7F) | 0x80)
            value >>= 7
        out.append(value)
        return bytes(out)

    for index, (value, unit) in enumerate(zip(encoded, units)):
        string_off = len(buf)
        struct.pack_into('<I', buf, string_ids + index * 4, string_off)
        buf += uleb(unit) + value + b'\x00'
        struct.pack_into('<IIIIIIII', buf, class_defs + index * 32,
                         index, 1, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0, 0, 0)

    buf[:8] = b'dex\n035\0'
    struct.pack_into('<IIIIII', buf, 0x20, len(buf), header_size, 0x12345678, 0, 0, 0)
    struct.pack_into(
        '<IIIIIIIIIIIIII', buf, 0x38,
        len(encoded), string_ids,
        len(encoded), type_ids,
        0, 0,
        0, 0,
        0, 0,
        len(encoded), class_defs,
        len(buf) - data_off, data_off,
    )
    return bytes(buf)


class Mutf8DecoderTests(unittest.TestCase):
    def test_units_are_not_bytes(self):
        raw = mutf8_encode('Ll/᩻ܶ;')
        self.assertEqual(len(raw), 9)          # bytes
        self.assertEqual(len('Ll/᩻ܶ;'), 6)     # UTF-16 units
        self.assertEqual(mutf8_end(raw, 0, 6), 9)

    def test_bmp_multibyte_roundtrip(self):
        text = 'Ll/᩻ܶ;'
        raw = mutf8_encode(text)
        self.assertEqual(decode_mutf8(raw[:mutf8_end(raw, 0, len(text))]), text)

    def test_embedded_nul_via_overlong_form(self):
        raw = mutf8_encode('a\x00b')
        # `a` = 1 byte/1 unit, `C0 80` = 2 bytes/1 unit, `b` = 1 byte/1 unit.
        self.assertEqual(raw, b'a\xc0\x80b')
        self.assertEqual(mutf8_end(raw, 0, 3), 4)
        self.assertEqual(decode_mutf8(raw[:4]), 'a\x00b')

    def test_supplementary_plane_cesu8_pair(self):
        # U+1F600 as a CESU-8 surrogate pair: 2 units, 6 bytes.
        raw = b'\xed\xa0\xbd\xed\xb8\x80'
        self.assertEqual(mutf8_end(raw, 0, 2), 6)
        self.assertEqual(decode_mutf8(raw), '\U0001F600')

    def test_four_byte_form_counts_two_units(self):
        raw = b'\xf0\x9f\x98\x80'
        self.assertEqual(mutf8_end(raw, 0, 2), 4)

    def test_ascii_is_unchanged(self):
        raw = b'Landroid/media/MediaDrmThrowable;'
        self.assertEqual(mutf8_end(raw, 0, len(raw)), len(raw))
        self.assertEqual(decode_mutf8(raw), raw.decode('ascii'))


class DexGetClassTests(unittest.TestCase):
    # Sorted by UTF-16 code-unit order, as the DEX spec requires, so the
    # binary search in get_class has a valid premise.
    NAMES = [
        'Landroid/media/MediaDrmThrowable;',
        'Ll/\u1a7b\u0736;',
        'Ll/\u1a7b\u06e1;',
        'Ll/\u0736\u0736;',
    ]

    def test_get_class_finds_every_non_ascii_name(self):
        dex = DEX.parse(make_dex_with_strings(self.NAMES), 'fixture.dex')
        for index, name in enumerate(self.NAMES):
            with self.subTest(name=name):
                self.assertEqual(dex.get_string(index), name)
                self.assertIsNotNone(dex.get_class(name),
                                     f'{name} resolved to None')

    def test_get_string_is_not_truncated(self):
        dex = DEX.parse(make_dex_with_strings(self.NAMES), 'fixture.dex')
        # The regression: 6 UTF-16 units but 9 bytes.
        self.assertEqual(dex.get_string(1), 'Ll/\u1a7b\u0736;')

    def test_missing_class_still_reports_none(self):
        dex = DEX.parse(make_dex_with_strings(self.NAMES), 'fixture.dex')
        self.assertIsNone(dex.get_class('Ll/doesNotExist;'))


if __name__ == '__main__':
    unittest.main()
