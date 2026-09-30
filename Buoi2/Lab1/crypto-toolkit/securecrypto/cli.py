"""securecrypto-cli: mã hoá / giải mã file từ dòng lệnh.

    securecrypto-cli --encrypt <file> --password <mật khẩu>
    securecrypto-cli --decrypt <file.enc> --password <Key base64 hoặc mật khẩu>
"""
import argparse
import sys

from cryptography.exceptions import InvalidTag

from securecrypto import aes_utils


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securecrypto-cli",
                                     description="SecureCrypto CLI - AES-256-GCM file encryption")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--encrypt", metavar="FILE", help="file cần mã hoá")
    action.add_argument("--decrypt", metavar="FILE", help="file .enc cần giải mã")
    parser.add_argument("--password", required=True,
                        help="mật khẩu (khi giải mã có thể dùng Key do --encrypt in ra)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.encrypt:
            key = aes_utils.encrypt_file_aes(args.encrypt, args.password)
            print(key)
        else:
            out = aes_utils.decrypt_file_aes(args.decrypt, args.password)
            print(f"Decrypted. Output: {out}")
    except FileNotFoundError as e:
        print(f"Error: file not found: {e.filename}", file=sys.stderr)
        return 1
    except InvalidTag:
        print("Error: decryption failed - wrong password/key or the file was modified.",
              file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":   # cho phép chạy: python -m securecrypto.cli ...
    sys.exit(main())
