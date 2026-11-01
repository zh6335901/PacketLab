import json
import math


def execution_errors(log):
    errors = {}
    for block in log.split("\n// Benchmark: ")[1:]:
        scenario, _, details = block.partition("\n")
        for line in details.split("// ** Remained", 1)[0].splitlines():
            if "Exception:" in line and (line.startswith(" ---> ") or not line[:1].isspace()):
                errors[scenario] = line.strip().removeprefix("---> ").strip()
    return errors


def collect_results(side, folder):
    errors = execution_errors((folder / "run.log").read_text(encoding="utf-8"))
    for file in sorted((folder / "results").glob("*full.json")):
        try:
            raw = json.loads(file.read_text(encoding="utf-8-sig"))
            host = raw["HostEnvironmentInfo"]
            environment = (host["DotNetCliVersion"], host["RuntimeVersion"], host["Architecture"])
            if "environment" in side and side["environment"] != environment:
                side["errors"].append(f"{file.name}: inconsistent benchmark environments")
            side["environment"] = environment
            for row in raw["Benchmarks"]:
                key = row["FullName"]
                if key in side["results"]:
                    side["results"][key] = None
                    side["errors"].append(f"Duplicate result for {key}")
                    continue
                if not row.get("Statistics") and row.get("DisplayInfo") in errors:
                    side["execution_errors"][key] = errors[row["DisplayInfo"]]
                side["results"][key] = row
        except (KeyError, TypeError, ValueError, OSError) as exc:
            side["errors"].append(f"{file.name}: {exc}")


def read_measurement(side, key):
    if key not in side["results"]:
        return None, None, "Missing result"
    row = side["results"][key] or {}
    stats = row.get("Statistics") or {}
    median = stats.get("Median")
    allocation = (row.get("Memory") or {}).get("BytesAllocatedPerOperation")
    errors = []
    failure = side["execution_errors"].get(key)
    if failure or not stats.get("OriginalValues") or median is None or not math.isfinite(median) or median <= 0:
        errors.append(failure or "Execution failed or timing samples missing")
        median = None
    if allocation is None or allocation < 0 or not math.isfinite(allocation):
        errors.append("Missing allocation measurement")
        allocation = None
    return median, allocation, ", ".join(errors)


def write_report(output, project, scenarios, sides, threshold, comparer_rev, compare):
    base, candidate = sides["base"], sides["candidate"]
    lines = ["# Benchmark comparison", "", f"- Benchmark source: `{candidate['sha']}` / `{project.as_posix()}`",
             f"- ResultsComparer: `{comparer_rev}`, threshold {threshold}, noise filter 0.3 ns"]
    failed = False
    for name, side in sides.items():
        lines.append(f"- {name} product: `{side['sha']}` ([run log]({name}/run.log))")
        if "environment" in side:
            lines.append("  - SDK / runtime / architecture: " + " / ".join(side["environment"]))
        for path, artifact in side["products"].items():
            lines.append(f"  - `{path}` — `{artifact}`")
        for error in side["errors"]:
            failed = True
            lines.append(f"  - {error}")

    lines += ["", "| Scenario | Base median (ns) | Candidate median (ns) | Change | Base B/op | Candidate B/op | Verdict / diagnostic |",
              "|---|---:|---:|---:|---:|---:|---|"]
    unexpected = (set(base["results"]) | set(candidate["results"])) - set(scenarios)
    for key in [*scenarios, *sorted(unexpected)]:
        diagnostics = []
        if key in unexpected:
            diagnostics.append("Scenario absent from candidate manifest")
        left, left_alloc, left_error = read_measurement(base, key)
        right, right_alloc, right_error = read_measurement(candidate, key)
        for name, error in [("base", left_error), ("candidate", right_error)]:
            if error:
                reason = " / ".join([error, *sides[name]["errors"]])
                diagnostics.append(f"{name}: {reason} ([log]({name}/run.log))")
        change = f"{(right / left - 1):+.2%}" if left and right else "—"
        if not diagnostics:
            if base.get("environment") != candidate.get("environment"):
                diagnostics.append("SDK, runtime or architecture mismatch")
            else:
                try:
                    verdict = compare(base["results"][key], candidate["results"][key])
                except (OSError, ValueError) as exc:
                    diagnostics.append(f"ResultsComparer: {exc} ([log](comparer.log))")
        if diagnostics:
            failed = True
            verdict = " / ".join(diagnostics)
        cells = [f"`{key}`", f"{left:.2f}" if left else "—", f"{right:.2f}" if right else "—",
                 change, left_alloc, right_alloc, verdict]
        lines.append("| " + " | ".join(str(v).replace("|", "\\|").replace("\n", " ")
                                       if v is not None else "—" for v in cells) + " |")
    report = output / "report.md"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(report)
    return int(failed)
