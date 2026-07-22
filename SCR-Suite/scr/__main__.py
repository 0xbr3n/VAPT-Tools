"""SCR Automater entry point.

    python -m scr --target "C:\\path\\to\\client\\source" [--pdf] [--out DIR]
                  [--only semgrep,gitleaks] [--skip depcheck] [--config FILE]

Pipeline: detect languages -> run every applicable offline tool -> normalise
-> dedupe across tools -> false-positive triage -> HTML/PDF/JSON/CSV report.
"""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

from . import __version__
from .adapters import ALL as ADAPTERS
from .dedupe import dedupe
from .drg_export import write_drg_csv
from .llm_triage import backend_info, review_findings, suggest_vectors, write_vectors_file
from .report import make_snippet_reader, write_reports
from .toolinfo import collect_versions, write_versions_file
from .triage import triage
from .util import BASE_DIR, detect_profile, load_config, log, set_log_file, set_raw_dir


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scr", description="Offline source code review automater")
    ap.add_argument("--target", required=True, help="folder containing the source code to review")
    ap.add_argument("--out", default=None, help="output folder (default: reports/<timestamp>)")
    ap.add_argument("--config", default=None, help="config json (default: config.json / config.default.json)")
    ap.add_argument("--pdf", action="store_true", help="also export report.pdf via Edge/Chrome headless")
    ap.add_argument("--only", default="", help="comma list: run only these adapters")
    ap.add_argument("--skip", default="", help="comma list: skip these adapters")
    ap.add_argument("--no-blackhole", action="store_true",
                    help="disable the outbound-network black-hole proxy (not recommended)")
    ap.add_argument("--all-tools", action="store_true",
                    help="force EVERY enabled tool to run even if it looks inapplicable "
                         "to the detected languages (e.g. run depcheck/bandit anyway)")
    ap.add_argument("--drg-per-instance", action="store_true",
                    help="DRG CSV: one row per finding instead of grouping by vulnerability type")
    ap.add_argument("--drg-include-info", action="store_true",
                    help="DRG CSV: also include info-severity findings")
    ap.add_argument("--drg-include-fp", action="store_true",
                    help="DRG CSV: also include findings flagged as likely false positives")
    ap.add_argument("--no-llm", action="store_true",
                    help="disable the LLM reasoning pass (per-finding FP review + vector suggestions)")
    ap.add_argument("--llm-backend", default=None, choices=["poc", "onprem", "disabled"],
                    help="LLM backend: poc (offline deterministic, default), onprem (internal model), disabled")
    args = ap.parse_args(argv)

    target = Path(args.target).resolve()
    if not target.is_dir():
        log(f"ERROR: target folder not found: {target}")
        return 2

    cfg = load_config(args.config)
    if args.no_blackhole:
        cfg["network_blackhole"] = False

    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    outdir = Path(args.out) if args.out else BASE_DIR / cfg.get("reports_dir", "reports") / f"{target.name}_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "raw_tool_output"   # kept as evidence for the working papers
    workdir.mkdir(exist_ok=True)
    set_log_file(outdir / "scan.log")      # full run log (evidence every tool ran)
    set_raw_dir(workdir)                    # per-tool stdout/stderr .log capture

    log(f"SCR Automater v{__version__} — offline scan of {target}")
    log(f"network black-hole for child tools: {'ON' if cfg.get('network_blackhole', True) else 'OFF'}")
    profile = detect_profile(target, cfg.get("exclude_dirs", []))
    log(f"detected languages: {', '.join(profile['languages']) or 'none'}; "
        f"manifests: {len(profile['manifests'])}; IaC: {profile['iac']}")

    only = {s.strip() for s in args.only.split(",") if s.strip()}
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}

    all_findings, tools_run, tools_skipped = [], [], []
    for adapter in ADAPTERS:
        name = adapter.NAME
        conf = cfg.get("adapters", {}).get(name, {})
        enabled = conf.get("enabled", True)
        if only and name not in only:
            continue
        if name in skip or not enabled:
            tools_skipped.append(name)
            continue
        if not args.all_tools and not adapter.applicable(profile, cfg):
            log(f"{name}: not applicable to this codebase - skipping "
                f"(use --all-tools to force)")
            tools_skipped.append(name)
            continue
        log(f"--- running {name} ---")
        try:
            found = adapter.run(target, cfg, workdir)
        except Exception as e:  # one broken tool must never kill the whole scan
            log(f"{name} FAILED: {e!r}")
            tools_skipped.append(name)
            continue
        if found is None:  # tool missing / produced nothing usable
            tools_skipped.append(name)
            continue
        tools_run.append(name)
        all_findings.extend(found)

    log("collecting scanning tool versions...")
    tool_versions = collect_versions(cfg)
    write_versions_file(tool_versions, outdir / "tool_versions.txt")
    for tv in tool_versions:
        log(f"  {tv['tool']}: {tv['version']}")

    log(f"raw findings: {len(all_findings)}")
    merged = dedupe(all_findings)
    log(f"after cross-tool dedupe: {len(merged)} unique findings")
    triage(merged, make_snippet_reader(target))
    likely_fp = sum(1 for f in merged if f.fp_likelihood == "high")
    log(f"triage: {likely_fp} flagged as likely false positives (kept, down-ranked)")

    # --- optional LLM reasoning pass (advisory; never deletes) ----------------
    llm_cfg = dict(cfg.get("llm", {}))
    if args.llm_backend:
        llm_cfg["backend"] = args.llm_backend
    if args.no_llm:
        llm_cfg["backend"] = "disabled"
    cfg["llm"] = llm_cfg
    vectors = []
    if llm_cfg.get("backend", "poc") != "disabled":
        binfo = backend_info(cfg)
        log(f"LLM reasoning pass: backend={binfo['backend']} egress={binfo['data_egress']}")
        rstats = review_findings(merged, cfg)
        log(f"  per-finding review: TP={rstats.get('true_positive',0)} "
            f"likely-FP={rstats.get('likely_false_positive',0)} needs-review={rstats.get('needs_review',0)}"
            + (f" (model calls: {rstats.get('model_calls',0)})" if binfo['backend'] == 'onprem' else ""))
        vectors = suggest_vectors(profile, merged, cfg)
        vpath = outdir / "llm_vectors.md"
        write_vectors_file(vectors, vpath, {"target": str(target), "llm_backend": binfo["backend"]})
        log(f"  suggested {len(vectors)} additional attack vectors to check -> {vpath.name}")
    else:
        log("LLM reasoning pass: disabled")

    meta = {
        "target": str(target), "timestamp": ts.replace("_", " "),
        "tools_run": tools_run, "tools_skipped": tools_skipped,
        "languages": profile["languages"], "version": __version__,
        "raw_findings": len(all_findings), "unique_findings": len(merged),
        "tool_versions": tool_versions,
    }
    outputs = write_reports(merged, meta, outdir, want_pdf=args.pdf)

    # DRG import CSV — ready to upload into the Report Generator's
    # Source Code Review template
    drg_path = outdir / "drg_import.csv"
    n_drg = write_drg_csv(
        merged, drg_path,
        grouped=not args.drg_per_instance,
        include_info=args.drg_include_info,
        include_fp=args.drg_include_fp,
    )
    outputs["drg_csv"] = f"{drg_path}  ({n_drg} rows, "
    outputs["drg_csv"] += "grouped by type" if not args.drg_per_instance else "per instance"
    outputs["drg_csv"] += ", likely-FPs excluded)" if not args.drg_include_fp else ", all incl. FPs)"

    if vectors:
        outputs["llm_vectors"] = f"{outdir / 'llm_vectors.md'}  ({len(vectors)} additional vectors to check manually)"

    sev = {}
    for f in merged:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    log("=" * 60)
    log(f"DONE. {len(merged)} unique findings "
        f"(crit:{sev.get('critical', 0)} high:{sev.get('high', 0)} med:{sev.get('medium', 0)} "
        f"low:{sev.get('low', 0)} info:{sev.get('info', 0)})")
    for k, v in outputs.items():
        log(f"  {k.upper()}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
