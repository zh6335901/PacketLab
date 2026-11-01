open System
open System.Diagnostics
open System.Globalization
open System.IO
open System.IO.Compression
open System.Security.Cryptography
open System.Text.Json.Nodes

let (</>) a b = Path.Combine(a, b)
let root = Path.GetFullPath(__SOURCE_DIRECTORY__ </> "..")
let comparerRev = "8588cdaa63ba6dd580067a654f175452a36513cf"
let threshold = "5%"
let directory path = Directory.CreateDirectory(path).FullName

let run cwd log environment program (args: string list) =
    let start = ProcessStartInfo(program, WorkingDirectory = cwd, UseShellExecute = false,
                                 RedirectStandardOutput = true, RedirectStandardError = true)
    for arg in args do start.ArgumentList.Add(arg)
    for key, value in environment do start.Environment[key] <- value
    use child = Process.Start(start)
    let stdout = child.StandardOutput.ReadToEndAsync()
    let stderr = child.StandardError.ReadToEndAsync()
    child.WaitForExit()
    let output = stdout.Result
    let transcript = output + "\n" + stderr.Result
    log |> Option.iter (fun path ->
        let arguments = String.concat " " args
        File.AppendAllText(path, $"$ {program} {arguments}\n{transcript}\n"))
    if child.ExitCode <> 0 then
        let lines = transcript.Split('\n', StringSplitOptions.RemoveEmptyEntries ||| StringSplitOptions.TrimEntries)
        let reason =
            lines |> Array.tryFind (fun line -> line.Contains("error ", StringComparison.OrdinalIgnoreCase))
            |> Option.orElseWith (fun () -> Array.tryLast lines) |> Option.defaultValue "No output"
        failwith $"{program} {List.head args} exited {child.ExitCode}: {reason}"
    output.Trim()

let git cwd args = run cwd None [] "git" args
let export repo sha destination paths =
    let archive = destination + ".zip"
    git repo (["archive"; "--format=zip"; "-o"; archive; sha] @ paths) |> ignore
    ZipFile.ExtractToDirectory(archive, destination)
    File.Delete(archive)

let buildComparer temp log =
    let upstream = directory (temp </> "upstream")
    let runGit args = run upstream (Some log) [] "git" args |> ignore
    runGit ["init"; "-q"]
    runGit ["remote"; "add"; "origin"; "https://github.com/dotnet/performance.git"]
    runGit ["fetch"; "--depth=1"; "--filter=blob:none"; "origin"; comparerRev]
    let source = temp </> "comparer"
    let path = "src/tools/ResultsComparer"
    export upstream comparerRev source [path]
    let output = temp </> "tool"
    run (temp </> "candidate/harness") (Some log) [] "dotnet"
        ["build"; source </> path </> "ResultsComparer.csproj"; "-c"; "Release"
         "-p:PERFLAB_TARGET_FRAMEWORKS=net11.0"; "-o"; output] |> ignore
    output </> "ResultsComparer.dll"

let field (key: string) (node: JsonNode) = if isNull node then null else node[key]
let optionalString node = if isNull node then None else Some (node.ToString())
let requiredString key node =
    field key node |> optionalString |> Option.defaultWith (fun () -> failwith $"Missing {key}")

type Measurement = {
    Raw: JsonNode
    Median: float option
    Allocation: int64 option
    Errors: string list
}

let readMeasurement (raw: JsonNode) failure =
    let stats = field "Statistics" raw
    let median =
        match field "Median" stats, field "OriginalValues" stats with
        | value, (:? JsonArray as samples) when not (isNull value) && samples.Count > 0 ->
            let ns = value.GetValue<float>()
            if Double.IsFinite(ns) && ns > 0. then Some ns else None
        | _ -> None
    let allocation =
        match field "Memory" raw |> field "BytesAllocatedPerOperation" with
        | null -> None
        | value -> Some (value.GetValue<int64>()) |> Option.filter ((<=) 0L)
    { Raw = raw; Median = median; Allocation = allocation
      Errors = [ if median.IsNone then defaultArg failure "Execution failed or timing samples missing"
                 if allocation.IsNone then "Missing allocation measurement" ] }

let executionErrors log =
    let mutable scenario = None
    let mutable errors = Map.empty
    for line in File.ReadLines(log) do
        if line.StartsWith("// Benchmark: ") then scenario <- Some (line.Substring(14))
        elif line.StartsWith("// ** Remained") then scenario <- None
        elif line.Contains("Exception:") && (line.StartsWith(" ---> ") || not (Char.IsWhiteSpace(line[0]))) then
            scenario |> Option.iter (fun key -> errors <- Map.add key (line.Trim().Replace("---> ", "")) errors)
    errors

type Side = {
    Name: string
    Sha: string
    Products: ResizeArray<string>
    Environments: Set<string>
    Rows: Map<string, Measurement>
    Errors: ResizeArray<string>
}

let runSide temp output project candidate (name, revision) =
    printfn "Measuring %s %s" name revision
    let folder = directory (output </> name)
    let log = folder </> "run.log"
    File.WriteAllText(log, "")
    let sideRoot = directory (temp </> name)
    let product, harness = sideRoot </> "product", sideRoot </> "harness"
    let bench = harness </> project
    let env = ["PacketLabProductRoot", product; "DOTNET_CLI_UI_LANGUAGE", "en-US"]
    let products, errors = ResizeArray(), ResizeArray()
    try
        export root revision product []
        export root candidate harness []
        let dotnet args = run harness (Some log) env "dotnet" args
        dotnet ["build"; bench; "-c"; "Release"] |> ignore
        let metadata = JsonNode.Parse(dotnet ["msbuild"; bench; "-t:ResolveReferences"; "-p:Configuration=Release"
                                              "-getProperty:TargetPath"; "-getItem:ReferenceCopyLocalPaths"])
        let target = requiredString "TargetPath" (metadata["Properties"])
        for item in (metadata["Items"]["ReferenceCopyLocalPaths"]).AsArray() do
            if (field "ReferenceSourceTarget" item |> optionalString) = Some "ProjectReference" then
                let path = requiredString "MSBuildSourceProjectFile" item |> Path.GetFullPath
                let relative = Path.GetRelativePath(product, path)
                if Path.IsPathRooted(relative) || relative.Split(Path.DirectorySeparatorChar)[0] = ".." then
                    failwith $"Project reference outside the {name} product tree: {path}"
                let subdir = field "DestinationSubDirectory" item |> optionalString |> Option.defaultValue ""
                let file = requiredString "FullPath" item |> Path.GetFileName
                use assembly = File.OpenRead(Path.GetDirectoryName(target) </> subdir </> file)
                let hash = SHA256.HashData(assembly) |> Convert.ToHexString
                products.Add($"{path} — {file} SHA-256 {hash}")
        if products.Count = 0 then failwith "No product project references in the benchmark output"
        run (Path.GetDirectoryName bench) (Some log) env "dotnet"
            [target; "--filter"; "*"; "--inProcess"; "--iterationCount"; "12"; "--warmupCount"; "3"
             "--iterationTime"; "250"; "--exporters"; "fulljson"; "--artifacts"; folder] |> ignore
    with ex -> errors.Add(ex.Message)
    let failures = executionErrors log
    let mutable rows, environments = Map.empty, Set.empty
    let results = folder </> "results"
    if Directory.Exists(results) then
        for file in Directory.GetFiles(results, "*full.json") do
            try
                let raw = JsonNode.Parse(File.ReadAllText(file))
                let host = raw["HostEnvironmentInfo"]
                let environment = ["DotNetCliVersion"; "RuntimeVersion"; "Architecture"]
                                  |> List.map (fun key -> requiredString key host) |> String.concat " / "
                environments <- Set.add environment environments
                for row in (raw["Benchmarks"]).AsArray() do
                    let key = requiredString "FullName" row
                    if Map.containsKey key rows then errors.Add($"Duplicate result for {key}")
                    else
                        let failure = field "DisplayInfo" row |> optionalString |> Option.bind (fun id -> Map.tryFind id failures)
                        rows <- Map.add key (readMeasurement row failure) rows
            with ex -> errors.Add($"{Path.GetFileName(file)}: {ex.Message}")
    { Name = name; Sha = revision; Products = products; Errors = errors; Rows = rows; Environments = environments }

let comparePair temp log comparer left right =
    // ResultsComparer omits unchanged cases. Compare a single matched pair so its summary identifies the verdict.
    let input label (row: Measurement) =
        let path = temp </> (label + "-full.json")
        File.WriteAllText(path, "{\"Benchmarks\":[" + row.Raw.ToJsonString() + "]}")
        path
    let output = run temp (Some log) [] "dotnet"
                     [comparer; "--base"; input "base" left; "--diff"; input "candidate" right; "--threshold"; threshold]
    if output.StartsWith("No differences found") then "No difference detected above threshold"
    elif output.Contains("better: 1,") then "Faster"
    elif output.Contains("worse: 1,") then "Slower"
    else failwith $"Unexpected ResultsComparer output: {output}"

let report output project scenarios baseline candidate compare =
    let lines = ResizeArray<string>()
    let mutable failed = false
    lines.Add("# Benchmark comparison\n")
    lines.Add($"- Benchmark source: {candidate.Sha} / {project}")
    lines.Add($"- ResultsComparer: {comparerRev}, threshold {threshold}, noise filter 0.3 ns")
    for side in [baseline; candidate] do
        lines.Add($"- {side.Name} product: {side.Sha} ([run log]({side.Name}/run.log))")
        for env in side.Environments do lines.Add($"  - SDK / runtime / architecture: {env}")
        for path in side.Products do lines.Add("  - " + path)
        for error in side.Errors do
            failed <- true
            lines.Add("  - " + error)
    lines.Add("\n| Scenario | Base median (ns) | Candidate median (ns) | Change | Base B/op | Candidate B/op | Verdict / diagnostic |")
    lines.Add("|---|---:|---:|---:|---:|---:|---|")
    let expected = Set.ofList scenarios
    let observed = Seq.append baseline.Rows.Keys candidate.Rows.Keys |> Set.ofSeq
    for key in scenarios @ Set.toList (Set.difference observed expected) do
        let diagnostics = ResizeArray<string>()
        if not (expected.Contains key) then diagnostics.Add("Scenario absent from candidate manifest")
        let lookup side =
            let row = Map.tryFind key side.Rows
            let problems = row |> Option.map _.Errors |> Option.defaultValue ["Missing result"]
            if not problems.IsEmpty then
                let reason = Seq.append problems side.Errors |> String.concat " / "
                diagnostics.Add($"{side.Name}: {reason} ([log]({side.Name}/run.log))")
            row
        let left, right = lookup baseline, lookup candidate
        let median row = row |> Option.bind _.Median
        let ns row = median row |> Option.map (sprintf "%.2f") |> Option.defaultValue "—"
        let allocation row = row |> Option.bind _.Allocation |> Option.map string |> Option.defaultValue "—"
        let change =
            match median left, median right with
            | Some a, Some b -> sprintf "%+.2f%%" ((b / a - 1.) * 100.)
            | _ -> "—"
        let verdict =
            match left, right with
            | Some a, Some b when diagnostics.Count = 0 ->
                if baseline.Environments <> candidate.Environments || baseline.Environments.Count <> 1 then
                    diagnostics.Add("SDK, runtime or architecture mismatch")
                    ""
                else
                    try compare a b
                    with ex -> diagnostics.Add($"ResultsComparer: {ex.Message} ([log](comparer.log))"); ""
            | _ -> ""
        if diagnostics.Count <> 0 then failed <- true
        let result = if diagnostics.Count = 0 then verdict else String.concat " / " diagnostics
        let cells = [key; ns left; ns right; change; allocation left; allocation right; result]
        lines.Add("| " + (cells |> List.map (fun s -> s.Replace("|", "\\|").ReplaceLineEndings(" ")) |> String.concat " | ") + " |")
    let path = output </> "report.md"
    File.WriteAllLines(path, lines)
    printfn "%s" path
    if failed then 1 else 0

let main project baseRef candidateRef =
    let resolve reference = git root ["rev-parse"; "--verify"; "--end-of-options"; reference + "^{commit}"]
    let baseline, candidate = resolve baseRef, resolve candidateRef
    let project = (project: string).Replace('\\', '/')
    if Path.IsPathRooted(project) || Array.contains ".." (project.Split('/')) then
        failwith "Project must be a repository-relative path"
    let manifest = (Path.GetDirectoryName(project) </> "scenarios.json").Replace('\\', '/')
    let scenarios = JsonNode.Parse(git root ["show"; $"{candidate}:{manifest}"]).AsArray()
                    |> Seq.map (fun node -> node.GetValue<string>()) |> List.ofSeq
    if scenarios.IsEmpty || List.exists String.IsNullOrWhiteSpace scenarios || List.distinct scenarios <> scenarios then
        failwith $"{manifest} must list unique BenchmarkDotNet FullName strings"
    let output = directory (root </> "artifacts/benchmarks" </> ("compare-" + Guid.NewGuid().ToString("N")))
    printfn "Benchmark comparison: %s" output
    let temp = Directory.CreateTempSubdirectory("pl-").FullName
    try
        let measure = runSide temp output project candidate
        let left = measure ("base", baseline)
        let right = measure ("candidate", candidate)
        let log = output </> "comparer.log"
        let comparer = lazy (buildComparer temp log)
        report output project scenarios left right (fun a b -> comparePair temp log comparer.Value a b)
    finally
        // Git pack files can be read-only on Windows.
        for file in Directory.EnumerateFiles(temp, "*", SearchOption.AllDirectories) do
            if File.GetAttributes(file).HasFlag(FileAttributes.ReadOnly) then File.SetAttributes(file, FileAttributes.Normal)
        Directory.Delete(temp, true)

let status =
    try
        match fsi.CommandLineArgs |> Array.tail with
        | [| project; baseline |] -> main project baseline "HEAD"
        | [| project; baseline; candidate |] -> main project baseline candidate
        | _ -> failwith "Usage: dotnet fsi scripts/Compare-Benchmarks.fsx <project> <base> [candidate]"
    with ex ->
        eprintfn "%s" ex.Message
        1
exit status
