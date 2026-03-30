#!/usr/bin/env python3
import sys
import base64
import argparse


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


def raw_to_user_friendly(raw: str, *, bounce: bool = True) -> str:
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

    # TON user-friendly flag byte:
    # 0x11 - bounceable (mainnet), 0x51 - non-bounceable (mainnet).
    tag = 0x11 if bounce else 0x51

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
    parser = argparse.ArgumentParser(
        description="Convert TON raw address (wc:hex) to user-friendly base64url.",
        add_help=False,
    )
    parser.add_argument(
        "bounce_mode",
        nargs="?",
        default=None,
        help="Optional bounce override for CLI usage: `bounce|non-bounce|true|false|1|0`.",
    )
    parser.add_argument(
        "--bounce",
        dest="bounce",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use bounceable addresses (default). Use --no-bounce for non-bounceable.",
    )

    args, _unknown = parser.parse_known_args()

    default_bounce = args.bounce

    def parse_bounce_override(v: str) -> bool:
        """
        ClickHouse passes arguments as strings; for UInt8 we expect `0` or `1`.
        """
        s = v.strip().lower()
        if s == "":
            raise ValueError("empty bounce value")

        try:
            n = int(s, 10)
            if n == 0:
                return False
            if n == 1:
                return True
        except Exception:
            pass

        if s in {"1", "true", "bounce", "bounceable", "yes", "y"}:
            return True
        if s in {"0", "false", "non-bounce", "nonbounce", "non-bounceable", "no", "n"}:
            return False
        raise ValueError(f"invalid bounce value: {v}")

    if args.bounce_mode is not None:
        try:
            default_bounce = parse_bounce_override(args.bounce_mode)
        except Exception:
            pass

    try:
        for line in sys.stdin:
            line = line.rstrip("\n")
            try:
                if "\t" in line:
                    raw_address, bounce_val = line.split("\t", 1)
                    bounce = parse_bounce_override(bounce_val)
                else:
                    raw_address = line
                    bounce = default_bounce

                print(raw_to_user_friendly(raw_address, bounce=bounce))
            except Exception:
                print("")
            sys.stdout.flush()
    except Exception:
        try:
            print("")
            sys.stdout.flush()
        except Exception:
            pass


if __name__ == "__main__":
    main()