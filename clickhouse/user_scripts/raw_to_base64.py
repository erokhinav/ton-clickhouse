#!/usr/bin/env python3
import sys
import base64


def crc16_ccitt(data: bytes) -> bytes:
    crc = 0
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc.to_bytes(2, "big")


def raw_to_user_friendly(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""

    if ":" not in raw:
        raise ValueError(f"invalid raw address: {raw}")

    wc_str, hex_part = raw.split(":", 1)
    wc = int(wc_str)

    hex_part = hex_part.strip()
    if len(hex_part) != 64:
        raise ValueError(f"invalid account id length: {raw}")

    account_id = bytes.fromhex(hex_part)

    tag = 0x11

    if wc == -1:
        wc_byte = 0xFF
    elif wc == 0:
        wc_byte = 0x00
    else:
        if not -128 <= wc <= 127:
            raise ValueError(f"invalid workchain: {wc}")
        wc_byte = wc & 0xFF

    addr = bytes([tag, wc_byte]) + account_id
    checksum = crc16_ccitt(addr)
    full = addr + checksum

    return base64.urlsafe_b64encode(full).decode("ascii").rstrip("=")


def main():
    for line in sys.stdin:
        line = line.rstrip("\n")
        try:
            print(raw_to_user_friendly(line))
        except Exception:
            print("")
        sys.stdout.flush()


if __name__ == "__main__":
    main()