"""
CLI entry point for ghascan.

Author: Sergio Cabrera
        https://www.linkedin.com/in/sergio-cabrera-878766239/
"""

import os
import sys


def _enable_windows_ansi():
    """Enable ANSI escape codes on Windows 10+ terminals."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # STD_OUTPUT_HANDLE = -11
        handle = kernel32.GetStdHandle(-11)
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _ensure_utf8_stdout():
    """Force UTF-8 on stdout/stderr for Windows (avoids cp1252 crashes with emojis)."""
    if sys.platform == "win32":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def main():
    """Main entry point — called by the `ghascan` command."""
    _enable_windows_ansi()
    _ensure_utf8_stdout()

    from gha_vuln_scanner import __version__, __author__, __author_url__

    # Show banner (only in interactive terminals)
    is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    if is_tty:
        print(f"\033[1m")
        print(f"   ██████╗ ██╗  ██╗ █████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗")
        print(f"  ██╔════╝ ██║  ██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║")
        print(f"  ██║  ███╗███████║███████║    ███████╗██║     ███████║██╔██╗ ██║")
        print(f"  ██║   ██║██╔══██║██╔══██║    ╚════██║██║     ██╔══██║██║╚██╗██║")
        print(f"  ╚██████╔╝██║  ██║██║  ██║    ███████║╚██████╗██║  ██║██║ ╚████║")
        print(f"   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝")
        print(f"\033[0m  \033[2mv{__version__} — GitHub Actions Vulnerability Scanner")
        print(f"  By {__author__} — {__author_url__}\033[0m")
        print()

    # Check for token before doing anything
    from gha_vuln_scanner.tokens import has_token
    if not has_token():
        if len(sys.argv) > 1 and "--help" not in sys.argv and "-h" not in sys.argv:
            is_offline = "--offline" in sys.argv
            is_version = "--version" in sys.argv
            if not is_offline and not is_version:
                print("\033[93m⚠  No GITHUB_TOKEN found.\033[0m")
                if sys.platform == "win32":
                    print('   Set it with: set GITHUB_TOKEN=ghp_your_token_here')
                    print('   Or permanent: setx GITHUB_TOKEN "ghp_your_token_here"')
                else:
                    print("   Set it with: export GITHUB_TOKEN='ghp_your_token_here'")
                print("   Without a token, API rate limits are very restrictive (60 req/hr).")
                print("   Get a token at: https://github.com/settings/tokens\n")

    # Import and run the scanner
    from gha_vuln_scanner.scanner import main as scanner_main
    scanner_main()


if __name__ == "__main__":
    main()
