"""Compare candidate-defined BenchmarkDotNet scenarios on two committed product trees."""

import hashlib
import json
import os
from functools import partial
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from benchmark_report import collect_results, write_report


ROOT = Path(__file__).resolve().parents[1]
COMPARER_REV = "8588cdaa63ba6dd580067a654f175452a36513cf"
THRESHOLD = "5%"
BDN_ARGS = ["--filter", "*", "--inProcess", "--iterationCount", "12", "--warmupCount",
            "3", "--iterationTime", "250", "--exporters", "fulljson"]


def run(args, cwd, log=None, env=None):
    proc = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
    if log:
        with log.open("a", encoding="utf-8") as stream:
            print("$", subprocess.list2cmdline(list(map(str, args))), file=stream)
            print(proc.stdout, file=stream)
    if proc.returncode:
        lines = proc.stdout.strip().splitlines()
        reason = next((line for line in lines if "error " in line.lower()), None)
        raise ValueError(f"{args[0]} {args[1]} exited {proc.returncode}: "
                         f"{reason or (lines[-1] if lines else 'no output')}")
    return proc.stdout.strip()


def export(repo, revision, destination, *paths):
    archive = destination.with_suffix(".zip")
    run(["git", "archive", "--format=zip", "-o", archive, revision, *paths], repo)
    with zipfile.ZipFile(archive) as files:
        files.extractall(destination)
    archive.unlink()


def build_comparer(temp, sdk_root, log):
    remote = temp / "upstream"
    run(["git", "init", "-q", remote], temp, log)
    run(["git", "remote", "add", "origin", "https://github.com/dotnet/performance.git"], remote, log)
    run(["git", "fetch", "--depth=1", "--filter=blob:none", "origin", COMPARER_REV], remote, log)
    source = temp / "comparer"
    project = Path("src/tools/ResultsComparer/ResultsComparer.csproj")
    export(remote, COMPARER_REV, source, project.parent)
    out = temp / "tool"
    run(["dotnet", "build", source / project, "-c", "Release", "-p:PERFLAB_TARGET_FRAMEWORKS=net11.0",
         "-o", out], sdk_root, log)
    return out / "ResultsComparer.dll"


def run_side(name, revision, candidate, project, temp, output):
    folder = output / name
    folder.mkdir()
    log = folder / "run.log"
    product = temp / name / "product"
    harness = product.parent / "harness"
    log.touch()
    side = {"sha": revision, "products": {}, "results": {}, "execution_errors": {}, "errors": []}
    try:
        product.parent.mkdir()
        export(ROOT, revision, product)
        export(ROOT, candidate, harness)
        env = {**os.environ, "PacketLabProductRoot": str(product), "DOTNET_CLI_UI_LANGUAGE": "en-US"}
        bench = harness / project
        run(["dotnet", "build", bench, "-c", "Release"], harness, log, env)
        metadata = json.loads(run(["dotnet", "msbuild", bench, "-t:ResolveReferences",
                                   "-p:Configuration=Release", "-getProperty:TargetPath",
                                   "-getItem:ReferenceCopyLocalPaths"], harness, env=env))
        target = Path(metadata["Properties"]["TargetPath"])
        for item in metadata["Items"]["ReferenceCopyLocalPaths"]:
            if item.get("ReferenceSourceTarget") != "ProjectReference":
                continue
            path = Path(item["MSBuildSourceProjectFile"]).resolve()
            if not path.is_relative_to(product):
                raise ValueError(f"Project reference outside the {name} product tree: {path}")
            dll = target.parent / item.get("DestinationSubDirectory", "") / Path(item["FullPath"]).name
            side["products"][str(path)] = f"{dll.name} SHA-256 {hashlib.sha256(dll.read_bytes()).hexdigest()}"
        if not side["products"]:
            raise ValueError("No product project references in the benchmark output")
        run(["dotnet", target, *BDN_ARGS, "--artifacts", folder], bench.parent, log, env)
    except (OSError, ValueError, KeyError) as exc:
        side["errors"].append(str(exc))
    collect_results(side, folder)
    return side


def statistical_verdict(temp, log, comparer, setup_error, left, right):
    if setup_error:
        raise ValueError(setup_error)
    # ResultsComparer omits unchanged cases. Give it one matched pair so the
    # summary identifies the case without parsing its formatted Markdown table.
    for label, row in [("base", left), ("candidate", right)]:
        (temp / f"{label}-full.json").write_text(json.dumps({"Benchmarks": [row]}), encoding="utf-8")
    stdout = run(["dotnet", comparer, "--base", temp / "base-full.json", "--diff",
                  temp / "candidate-full.json", "--threshold", THRESHOLD], temp, log)
    if stdout.startswith("No differences found"):
        return "No difference detected above threshold"
    for marker, verdict in [("better: 1,", "Faster"), ("worse: 1,", "Slower")]:
        if marker in stdout:
            return verdict
    raise ValueError(f"Unexpected ResultsComparer output: {stdout}")


def main(project_arg, base_ref, candidate_ref):
    base, candidate = [run(["git", "rev-parse", "--verify", "--end-of-options", ref + "^{commit}"], ROOT)
                       for ref in (base_ref, candidate_ref)]
    project = Path(project_arg)
    if project.is_absolute() or ".." in project.parts:
        raise ValueError("Project must be a repository-relative path")
    manifest = (project.parent / "scenarios.json").as_posix()
    scenarios = json.loads(run(["git", "show", f"{candidate}:{manifest}"], ROOT))
    if (not isinstance(scenarios, list) or not scenarios or not all(isinstance(s, str) and s for s in scenarios)
            or len(set(scenarios)) != len(scenarios)):
        raise ValueError(f"{manifest} must list unique BenchmarkDotNet FullName strings")

    results = ROOT / "artifacts" / "benchmarks"
    results.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(dir=results, prefix="compare-"))
    print(f"Benchmark comparison: {output}", flush=True)
    with tempfile.TemporaryDirectory(prefix="pl-") as scratch:
        temp = Path(scratch)
        sides = {}
        for name, revision in [("base", base), ("candidate", candidate)]:
            print(f"Measuring {name} {revision}", flush=True)
            sides[name] = run_side(name, revision, candidate, project, temp, output)

        log = output / "comparer.log"
        comparer = None
        setup_error = None
        if sides["base"]["results"].keys() & sides["candidate"]["results"].keys():
            try:
                comparer = build_comparer(temp, temp / "candidate/harness", log)
            except (OSError, ValueError) as exc:
                setup_error = str(exc)
        compare = partial(statistical_verdict, temp, log, comparer, setup_error)
        return write_report(output, project, scenarios, sides, THRESHOLD, COMPARER_REV, compare)


if __name__ == "__main__":
    try:
        sys.exit(main(*sys.argv[1:]))
    except (OSError, ValueError) as error:
        sys.exit(str(error))
