"""
Elf 🧝 — Command-Line Interface
Usage: elf check <github-url> [options]
"""

import argparse
import os
import sys

BANNER = """
  🧝  Elf — GitHub Repository Safety Scanner  v1.0.0
      136 checks · 8 threat categories · Safe | Warn | Not Safe
      github.com/aegiswizard/elf  ·  MIT License
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="elf",
        description="🧝 Elf — Run 136 security checks on any GitHub repository",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  elf check https://github.com/owner/repo
  elf check https://github.com/owner/repo --token ghp_xxxx
  elf check https://github.com/owner/repo --output json
  elf check owner/repo --quiet

environment variables:
  GITHUB_TOKEN   GitHub personal access token (strongly recommended)
                 Without: 60 req/hr  —  will rate-limit most repos
                 With:  5,000 req/hr —  full 136-check scan in ~90 seconds
                 Get one free: https://github.com/settings/tokens
                 Required scopes: none (public repo access only)

exit codes:
  0  SAFE     — all 136 checks passed
  1  ERROR    — scan could not complete
  2  WARN     — medium/low findings only
  3  NOT SAFE — critical or high findings detected
        """,
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    check_p = subparsers.add_parser(
        "check",
        help="Run all 136 security checks on a GitHub repository",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    check_p.add_argument("url",     help="GitHub repository URL or owner/repo")
    check_p.add_argument("--token", "-t",
        default=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
        metavar="TOKEN",
        help="GitHub personal access token  (default: $GITHUB_TOKEN)",
    )
    check_p.add_argument("--output", "-o",
        choices=["text", "json"],
        default="text",
        help="Output format  (default: text)",
    )
    check_p.add_argument("--quiet", "-q",
        action="store_true",
        help="Suppress progress messages",
    )

    subparsers.add_parser("version", help="Print version and exit")

    args = parser.parse_args()

    if not args.command:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    if args.command == "version":
        print("elf 1.0.0")
        sys.exit(0)

    if args.command == "check":
        from elf.scanner import scan
        from elf.report  import format_text_report, format_json_report
        from elf.models  import Verdict

        def progress(msg: str) -> None:
            if not args.quiet and args.output == "text":
                print(f"  ⏳ {msg}", file=sys.stderr)

        print(BANNER, file=sys.stderr)

        if not args.token:
            print(
                "\n  ⚠️  No GitHub token detected.\n"
                "     Elf makes ~30–50 API calls per scan.\n"
                "     Without a token: 60 req/hr — this will rate-limit.\n\n"
                "     ➜  Set a token:  export GITHUB_TOKEN=ghp_xxxx\n"
                "     ➜  Or pass one:  elf check <url> --token ghp_xxxx\n"
                "     ➜  Get one free: https://github.com/settings/tokens\n",
                file=sys.stderr,
            )

        print(f"  🧝 Scanning → {args.url}\n", file=sys.stderr)

        try:
            result = scan(url=args.url, token=args.token, progress=progress)
        except ValueError as e:
            print(f"\n  ❌  {e}\n", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\n  Scan interrupted.\n", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"\n  ❌  Unexpected error: {e}\n", file=sys.stderr)
            sys.exit(1)

        if args.output == "json":
            print(format_json_report(result))
        else:
            print(format_text_report(result))

        # Exit codes
        if result.verdict == Verdict.SAFE:
            sys.exit(0)
        elif result.verdict == Verdict.WARN:
            sys.exit(2)
        else:
            sys.exit(3)


if __name__ == "__main__":
    main()
