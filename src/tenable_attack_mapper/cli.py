"""Command-line interface.

Entry point declared in ``pyproject.toml`` as ``tenable-attack-mapper``:

    tenable-attack-mapper run --repo 1 --out layer.json

Subcommands:
  run       Pull findings from Security Center, map them, write a Navigator layer.
  techniques  Reverse lookup — which findings map to given technique IDs.
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import load_config
from .pipeline import findings_for_techniques, run


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return _cmd_run(args)
    if args.command == "techniques":
        return _cmd_techniques(args)

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tenable-attack-mapper",
        description=(
            "Map Tenable Security Center findings to MITRE ATT&CK techniques "
            "and export a VPR-scored ATT&CK Navigator layer."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Pull findings and export a Navigator layer.")
    scope = run_p.add_mutually_exclusive_group()
    scope.add_argument("--repo", dest="repo", help="Security Center repository ID.")
    scope.add_argument("--query", dest="query", help="Security Center saved query ID.")
    run_p.add_argument(
        "--severity",
        action="append",
        dest="severities",
        help="Severity to include (repeatable), e.g. --severity High --severity Critical.",
    )
    run_p.add_argument(
        "--out",
        default="layer.json",
        help="Output path for the Navigator layer JSON (default: layer.json).",
    )
    run_p.add_argument(
        "--report",
        dest="report",
        help="Optional path for a Markdown coverage summary.",
    )
    run_p.add_argument(
        "--no-semantic",
        action="store_true",
        help="Disable the Claude semantic fallback (deterministic chain only).",
    )
    run_p.add_argument(
        "--json",
        action="store_true",
        help="Print the full result as JSON to stdout instead of a summary.",
    )

    tech_p = sub.add_parser(
        "techniques",
        help="Which findings map to the given ATT&CK technique IDs?",
    )
    tech_p.add_argument(
        "technique_ids",
        nargs="+",
        help="One or more ATT&CK technique IDs, e.g. T1190 T1059.",
    )
    tech_p.add_argument("--repo", dest="repo", help="Security Center repository ID.")
    tech_p.add_argument("--query", dest="query", help="Security Center saved query ID.")
    tech_p.add_argument("--no-semantic", action="store_true")

    return parser


def _cmd_run(args) -> int:
    try:
        config = load_config()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.no_semantic:
        config.enable_semantic = False

    result = run(
        config,
        repository_id=args.repo,
        query_id=args.query,
        severities=args.severities,
        out_path=args.out,
        report_path=args.report,
    )

    if args.json:
        json.dump(result.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    _print_summary(result, args.out, args.report)
    return 0


def _cmd_techniques(args) -> int:
    try:
        config = load_config()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.no_semantic:
        config.enable_semantic = False

    result = run(config, repository_id=args.repo, query_id=args.query)
    matches = findings_for_techniques(result.mappings, args.technique_ids)
    by_plugin = {f.plugin_id: f for f in result.findings}

    for technique, plugin_ids in matches.items():
        print(f"\n{technique} — {len(plugin_ids)} finding(s):")
        for pid in plugin_ids:
            finding = by_plugin.get(pid)
            name = finding.plugin_name if finding else ""
            print(f"  - {pid}: {name}")
    return 0


def _print_summary(result, out_path, report_path) -> None:
    s = result.summary
    print(f"Findings mapped : {s['findings_mapped']}/{s['findings_total']}")
    print(
        f"Mappings        : {s['mappings_total']} "
        f"({s['mappings_deterministic']} deterministic, "
        f"{s['mappings_semantic']} semantic)"
    )
    print(
        f"Techniques      : {s['techniques_total']} "
        f"({s['techniques_needs_review']} need review)"
    )
    print(f"Navigator layer : {out_path}")
    if report_path:
        print(f"Coverage report : {report_path}")
    for warning in result.warnings:
        print(f"  ! {warning}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
