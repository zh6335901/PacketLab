module BenchmarkAffinity

open System
open System.ComponentModel
open System.Diagnostics
open System.Runtime.InteropServices

type Policy =
    | Inherit of reason: string * expected: nativeint option
    | Bind of mask: nativeint * efficiencyClass: byte * processors: int list

let describe = function
    | Inherit (reason, _) -> $"inherited ({reason})"
    | Bind (mask, level, processors) ->
        let indices = processors |> List.map string |> String.concat ", "
        $"efficiency class {level}, logical CPUs [{indices}], mask 0x{mask.ToInt64():X}"

[<DllImport("kernel32.dll", SetLastError = true)>]
extern bool private GetSystemCpuSetInformation([<Out>] byte[] buffer, int capacity, int& size, nativeint processHandle, int flags)

[<DllImport("kernel32.dll", SetLastError = true)>]
extern bool private GetProcessDefaultCpuSets(nativeint processHandle, [<Out>] uint32[] ids, int capacity, int& count)

let private windowsPolicy (current: Process) =
    let handle = current.Handle
    let mutable size = 0
    if not (GetSystemCpuSetInformation(null, 0, &size, handle, 0)) && Marshal.GetLastPInvokeError() <> 122 then
        raise (Win32Exception(Marshal.GetLastPInvokeError()))
    let data = Array.zeroCreate size
    if not (GetSystemCpuSetInformation(data, data.Length, &size, handle, 0)) then
        raise (Win32Exception(Marshal.GetLastPInvokeError()))

    // SYSTEM_CPU_SET_INFORMATION is a sequence of variable-sized native records.
    let cores = ResizeArray<_>()
    let mutable offset = 0
    while offset < size do
        let length = BitConverter.ToInt32(data, offset)
        if length < 8 || length > size - offset then invalidOp "Invalid Windows CPU set record length"
        if BitConverter.ToInt32(data, offset + 4) = 0 then
            if length < 20 then invalidOp "Incomplete Windows CPU set record"
            cores.Add(BitConverter.ToUInt32(data, offset + 8), BitConverter.ToUInt16(data, offset + 12),
                      int data[offset + 14], data[offset + 15], data[offset + 18], data[offset + 19])
        offset <- offset + length

    if cores.Count = 0 || cores |> Seq.exists (fun (_, group, cpu, _, _, _) -> group <> 0us || cpu >= IntPtr.Size * 8) then
        Inherit ("topology unavailable or spans processor groups", None)
    else
        let allowed = current.ProcessorAffinity
        let ids = Array.zeroCreate cores.Count
        let mutable count = 0
        if not (GetProcessDefaultCpuSets(handle, ids, ids.Length, &count)) then
            raise (Win32Exception(Marshal.GetLastPInvokeError()))
        let defaults = Set.ofArray ids[..count - 1]
        let available =
            [ for id, _, cpu, core, level, flags in cores do
                let reservedElsewhere = flags &&& 0x06uy = 0x02uy
                if not reservedElsewhere && (defaults.IsEmpty || defaults.Contains id) &&
                   allowed &&& (1n <<< cpu) <> 0n then yield cpu, core, level ]
        match available |> List.map (fun (_, _, level) -> level) |> List.distinct |> List.sortDescending with
        | [] -> Inherit ("no usable CPU sets reported", Some allowed)
        | [level] -> Inherit ($"one visible efficiency class {level}", Some allowed)
        | highest :: _ ->
            let processors =
                available |> List.filter (fun (_, _, level) -> level = highest)
                |> List.sortBy (fun (cpu, _, _) -> cpu) |> List.distinctBy (fun (_, core, _) -> core)
                |> List.truncate 4 |> List.map (fun (cpu, _, _) -> cpu)
            Bind (processors |> List.fold (fun mask cpu -> mask ||| (1n <<< cpu)) 0n, highest, processors)

let detect () =
    if OperatingSystem.IsWindows() then
        use current = Process.GetCurrentProcess()
        try windowsPolicy current
        with
        | :? EntryPointNotFoundException -> Inherit ("Windows CPU set API unavailable", None)
        | :? Win32Exception as ex -> Inherit ($"CPU topology unavailable: {ex.Message}", None)
    else Inherit ("CPU efficiency classes not queried on this OS", None)

let start policy (info: ProcessStartInfo) =
    match policy with
    | Inherit _ -> Process.Start(info)
    | Bind (mask, _, _) ->
        // The child inherits the mask before the CLR starts. Restore the launcher for subsequent builds.
        use launcher = Process.GetCurrentProcess()
        let original = launcher.ProcessorAffinity
        try
            launcher.ProcessorAffinity <- mask
            Process.Start(info)
        finally launcher.ProcessorAffinity <- original

let verify policy (child: Process) =
    let expected = match policy with Bind (mask, _, _) -> Some mask | Inherit (_, mask) -> mask
    expected |> Option.map (fun mask ->
        let actual = child.ProcessorAffinity
        if actual <> mask then failwith $"Expected affinity 0x{mask.ToInt64():X}, observed 0x{actual.ToInt64():X}"
        $"0x{actual.ToInt64():X}")
