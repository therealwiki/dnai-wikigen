"""CLI for testing the captcha solver."""

import argparse
import sys
import time
from pathlib import Path

from PIL import Image


def main():
    parser = argparse.ArgumentParser(description="cock.li captcha solver (CPU-only)")
    sub = parser.add_subparsers(dest="command")

    # Solve from a local image file
    solve_file = sub.add_parser("file", help="Solve captcha from an image file")
    solve_file.add_argument("path", help="Path to captcha image")

    # Fetch and solve from live site
    fetch = sub.add_parser("fetch", help="Fetch captcha from cock.li and solve")
    fetch.add_argument("-n", type=int, default=1, help="Number of captchas to fetch and solve")
    fetch.add_argument("--save-dir", help="Directory to save captcha images")
    fetch.add_argument("--delay", type=float, default=2.0, help="Delay between fetches (seconds)")

    # Benchmark: fetch N captchas and report stats
    bench = sub.add_parser("bench", help="Benchmark solver accuracy on live captchas")
    bench.add_argument("-n", type=int, default=20, help="Number of captchas")
    bench.add_argument("--delay", type=float, default=2.0, help="Delay between fetches")

    # Template DB info
    sub.add_parser("info", help="Show template database stats")

    args = parser.parse_args()

    if args.command == "file":
        from captcha_solver.solver import solve_from_file
        result = solve_from_file(args.path)
        print(result)

    elif args.command == "fetch":
        from captcha_solver.fetcher import fetch_captcha
        from captcha_solver.parser import parse_box_shadow_pixels, pixels_to_image
        from captcha_solver.solver import solve_from_image

        save_dir = Path(args.save_dir) if args.save_dir else None
        if save_dir:
            save_dir.mkdir(parents=True, exist_ok=True)

        for i in range(args.n):
            try:
                html, captcha_key = fetch_captcha()
                pixels = parse_box_shadow_pixels(html)
                img = pixels_to_image(pixels, scale=1)
                solution = solve_from_image(img)
                print(f"[{i+1}/{args.n}] {solution}  (key: {captcha_key[:12]}...)")
                if save_dir:
                    scaled = pixels_to_image(pixels, scale=4)
                    path = save_dir / f"captcha_{i:03d}_{solution}.png"
                    scaled.save(path)
            except Exception as e:
                print(f"[{i+1}/{args.n}] ERROR: {e}", file=sys.stderr)
            if i < args.n - 1:
                time.sleep(args.delay)

    elif args.command == "bench":
        from captcha_solver.fetcher import fetch_captcha
        from captcha_solver.parser import parse_box_shadow_pixels, pixels_to_image
        from captcha_solver.solver import solve_template

        ok = 0
        unknown = 0
        errors = 0
        for i in range(args.n):
            try:
                html, _ = fetch_captcha()
                pixels = parse_box_shadow_pixels(html)
                img = pixels_to_image(pixels, scale=1)
                solution, distances = solve_template(img)
                if "?" in solution:
                    unknown += 1
                    print(f"  [{i+1}] UNKNOWN: {solution}")
                else:
                    ok += 1
            except Exception as e:
                errors += 1
            time.sleep(args.delay)

        total = ok + unknown
        print(f"\nFetched: {ok + unknown + errors} ({errors} server errors)")
        if total > 0:
            print(f"Solved:  {ok}/{total} ({100*ok/total:.0f}%)")
            print(f"Unknown: {unknown}/{total}")

    elif args.command == "info":
        from captcha_solver.templates import TemplateDB
        db = TemplateDB()
        db.load()
        chars = sorted(db.templates.keys())
        print(f"Characters: {len(chars)} unique")
        print(f"Templates:  {db.template_count} total")
        print(f"Charset:    {''.join(chars)}")
        missing = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") - set(chars)
        if missing:
            print(f"Missing:    {''.join(sorted(missing))}")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
