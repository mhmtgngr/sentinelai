"""CLI interface for the DNS Pentest Scanner."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .report import ReportGenerator
from .scanner import DNSPentestScanner

# ANSI colors for terminal output
RED = "\033[91m"
ORANGE = "\033[93m"
YELLOW = "\033[33m"
BLUE = "\033[94m"
GRAY = "\033[90m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
  ____             _   _            _        _    ___
 / ___|  ___ _ __ | |_(_)_ __   ___| |      / \\  |_ _|
 \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |____ / _ \\  | |
  ___) |  __/ | | | |_| | | | |  __/ |____/ ___ \\ | |
 |____/ \\___|_| |_|\\__|_|_| |_|\\___|_|   /_/   \\_\\___|

 DNS Penetration Testing Scanner v1.0.0
 Red Team DNS Reconnaissance & Security Assessment
{RESET}"""

SEVERITY_COLORS_MAP = {
    "Critical": RED,
    "High": ORANGE,
    "Medium": YELLOW,
    "Low": BLUE,
    "Info": GRAY,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sentinel-AI DNS Penetration Testing Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s -d example.com\n"
            "  %(prog)s -d example.com --azure-tenant-id TENANT --azure-client-id ID "
            "--azure-client-secret SECRET --azure-subscription-id SUB\n"
            "  %(prog)s --azure-tenant-id TENANT --azure-client-id ID "
            "--azure-client-secret SECRET --azure-subscription-id SUB\n"
        ),
    )

    # Target
    target_group = parser.add_argument_group("Scan Target")
    target_group.add_argument(
        "-d", "--domain",
        help="Target domain (omit to auto-discover all Azure DNS zones)",
    )

    # Azure auth
    azure_group = parser.add_argument_group(
        "Azure Authentication",
        "Credentials can also be set via environment variables",
    )
    azure_group.add_argument(
        "--azure-tenant-id",
        help="Azure AD tenant ID (env: AZURE_TENANT_ID)",
    )
    azure_group.add_argument(
        "--azure-client-id",
        help="Service principal client ID (env: AZURE_CLIENT_ID)",
    )
    azure_group.add_argument(
        "--azure-client-secret",
        help="Service principal secret (env: AZURE_CLIENT_SECRET)",
    )
    azure_group.add_argument(
        "--azure-subscription-id",
        help="Azure subscription ID (env: AZURE_SUBSCRIPTION_ID)",
    )

    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "-n", "--nameserver",
        help="Custom DNS resolver IP",
    )
    scan_group.add_argument(
        "-w", "--wordlist",
        help="Custom subdomain wordlist file (one per line)",
    )
    scan_group.add_argument(
        "-c", "--concurrency",
        type=int, default=50,
        help="Max concurrent DNS queries (default: 50)",
    )
    scan_group.add_argument(
        "-t", "--timeout",
        type=float, default=5.0,
        help="Per-query timeout in seconds (default: 5.0)",
    )
    scan_group.add_argument(
        "--no-brute",
        action="store_true",
        help="Skip subdomain brute force",
    )
    scan_group.add_argument(
        "--no-zone-transfer",
        action="store_true",
        help="Skip zone transfer (AXFR) attempts",
    )

    # Output
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output-dir",
        default="./reports",
        help="Report output directory (default: ./reports)",
    )
    output_group.add_argument(
        "--format",
        choices=["json", "html", "both"],
        default="both",
        dest="report_format",
        help="Report format (default: both)",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Validate: need either domain or Azure creds
    import os

    has_azure = any([
        args.azure_tenant_id or os.environ.get("AZURE_TENANT_ID"),
        args.azure_client_id or os.environ.get("AZURE_CLIENT_ID"),
        args.azure_client_secret or os.environ.get("AZURE_CLIENT_SECRET"),
        args.azure_subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID"),
    ])

    if not args.domain and not has_azure:
        parser.error("Either --domain or Azure credentials must be provided.")

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    print(BANNER)

    # Create scanner
    scanner = DNSPentestScanner(
        domain=args.domain,
        nameserver=args.nameserver,
        wordlist_path=args.wordlist,
        timeout=args.timeout,
        concurrency=args.concurrency,
        output_dir=args.output_dir,
        report_format=args.report_format,
        skip_brute=args.no_brute,
        skip_zone_transfer=args.no_zone_transfer,
        verbose=args.verbose,
        azure_tenant_id=args.azure_tenant_id,
        azure_client_id=args.azure_client_id,
        azure_client_secret=args.azure_client_secret,
        azure_subscription_id=args.azure_subscription_id,
    )

    # Run scan
    try:
        results = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Scan interrupted by user.{RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{RED}Error: {e}{RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    if not results:
        print(f"{YELLOW}No results generated.{RESET}")
        sys.exit(0)

    # Generate reports
    report_gen = ReportGenerator(args.output_dir)
    all_paths: list[str] = []

    for result in results:
        paths = report_gen.generate(result, args.report_format)
        all_paths.extend(paths)

        # Print findings summary with colors
        print(f"\n{BOLD}{'=' * 60}{RESET}")
        print(f"{BOLD}Results for: {CYAN}{result.target_domain}{RESET}")
        print(f"{BOLD}{'=' * 60}{RESET}")

        summary = result.severity_summary
        total = len(result.findings)
        print(f"\n  DNS Records:  {len(result.dns_records)}")
        print(f"  Subdomains:   {len(result.subdomains)}")
        print(f"  Total Issues: {total}\n")

        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = summary.get(sev, 0)
            if count > 0:
                color = SEVERITY_COLORS_MAP.get(sev, RESET)
                print(f"    {color}{BOLD}{sev:12s}{RESET} {count}")

        if result.findings:
            print(f"\n  {BOLD}Top Findings:{RESET}")
            for f in sorted(
                result.findings, key=lambda x: x.severity.sort_key
            )[:5]:
                color = SEVERITY_COLORS_MAP.get(f.severity.value, RESET)
                print(f"    {color}[{f.severity.value}]{RESET} {f.title}")

    # Print report paths
    print(f"\n{GREEN}{BOLD}Reports generated:{RESET}")
    for p in all_paths:
        print(f"  {GREEN}{p}{RESET}")

    print()


if __name__ == "__main__":
    main()
