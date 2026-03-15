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


def user_friendly_to_raw(b64: str) -> str:
    b64 = b64.strip()
    if not b64:
        return ""

    padding = 4 - (len(b64) % 4)
    if padding != 4:
        b64 += "=" * padding

    try:
        full = base64.urlsafe_b64decode(b64)
    except Exception:
        raise ValueError(f"invalid base64: {b64}")

    if len(full) != 36:
        raise ValueError(f"invalid address length: {len(full)}")

    addr = full[:34]
    checksum = full[34:36]
    if crc16_ccitt(addr) != checksum:
        raise ValueError("checksum mismatch")

    tag = addr[0]
    wc_byte = addr[1]
    account_id = addr[2:34]

    if wc_byte == 0xFF:
        wc = -1
    elif wc_byte == 0x00:
        wc = 0
    else:
        wc = wc_byte if wc_byte < 128 else wc_byte - 256

    return f"{wc}:{account_id.hex()}"


def main():
    for line in sys.stdin:
        line = line.rstrip("\n")
        try:
            print(user_friendly_to_raw(line))
        except Exception:
            print("")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
