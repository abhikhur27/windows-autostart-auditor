using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

var options = CliOptions.Parse(args);
var entries = new List<AutostartEntry>();

entries.AddRange(AutostartScanner.ScanRegistryEntries());
entries.AddRange(AutostartScanner.ScanStartupFolder(
    Environment.GetFolderPath(Environment.SpecialFolder.Startup),
    "Startup folder",
    "Current user"));
entries.AddRange(AutostartScanner.ScanStartupFolder(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
    "Startup folder",
    "All users"));
entries.AddRange(AutostartScanner.ScanScheduledTasks());

entries = entries
    .OrderByDescending(entry => entry.RiskScore)
    .ThenBy(entry => entry.SourceType)
    .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
    .ToList();

var report = ReportBuilder.Build(entries);
Printer.Print(report);

if (options.JsonOut is not null)
{
    Directory.CreateDirectory(options.JsonOut.Directory?.FullName ?? Environment.CurrentDirectory);
    File.WriteAllText(options.JsonOut.FullName, JsonSerializer.Serialize(report, new JsonSerializerOptions
    {
        WriteIndented = true
    }));
    Console.WriteLine($"\nWrote JSON report: {options.JsonOut}");
}

if (options.MarkdownOut is not null)
{
    Directory.CreateDirectory(options.MarkdownOut.Directory?.FullName ?? Environment.CurrentDirectory);
    File.WriteAllText(options.MarkdownOut.FullName, MarkdownWriter.Write(report));
    Console.WriteLine($"Wrote Markdown report: {options.MarkdownOut}");
}

return;

sealed record CliOptions(FileInfo? JsonOut, FileInfo? MarkdownOut)
{
    public static CliOptions Parse(string[] args)
    {
        FileInfo? jsonOut = null;
        FileInfo? markdownOut = null;

        for (var index = 0; index < args.Length; index += 1)
        {
            switch (args[index])
            {
                case "--json-out":
                    jsonOut = new FileInfo(RequireValue(args, ref index, "--json-out"));
                    break;
                case "--markdown-out":
                    markdownOut = new FileInfo(RequireValue(args, ref index, "--markdown-out"));
                    break;
                case "--help":
                case "-h":
                    PrintUsage();
                    Environment.Exit(0);
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: {args[index]}");
            }
        }

        return new CliOptions(jsonOut, markdownOut);
    }

    private static string RequireValue(string[] args, ref int index, string flag)
    {
        if (index + 1 >= args.Length)
        {
            throw new ArgumentException($"{flag} requires a path value.");
        }

        index += 1;
        return args[index];
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Windows Autostart Auditor");
        Console.WriteLine("=========================");
        Console.WriteLine("Scans registry Run keys, startup folders, and scheduled tasks.");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet run -- --json-out reports/audit.json --markdown-out reports/audit.md");
    }
}

sealed record AutostartEntry(
    string SourceType,
    string Scope,
    string Name,
    string Command,
    string? ResolvedPath,
    bool TargetExists,
    int RiskScore,
    IReadOnlyList<string> RiskSignals,
    string? Status);

sealed record AuditReport(
    string MachineName,
    string GeneratedAt,
    int EntryCount,
    int HighRiskCount,
    int MissingTargetCount,
    int ScriptHostCount,
    IReadOnlyList<AutostartEntry> Entries);

static class AutostartScanner
{
    private static readonly (RegistryHive Hive, RegistryView View, string Scope, string Path)[] RunKeyTargets =
    [
        (RegistryHive.CurrentUser, RegistryView.Default, "Current user", @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, RegistryView.Default, "Current user", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, "All users", @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, "All users", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, "All users (32-bit)", @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, "All users (32-bit)", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ];

    [SupportedOSPlatform("windows")]
    public static IEnumerable<AutostartEntry> ScanRegistryEntries()
    {
        var entries = new List<AutostartEntry>();
        foreach (var target in RunKeyTargets)
        {
            RegistryKey? baseKey = null;
            RegistryKey? subKey = null;
            try
            {
                baseKey = RegistryKey.OpenBaseKey(target.Hive, target.View);
                subKey = baseKey.OpenSubKey(target.Path);
                if (subKey is null)
                {
                    continue;
                }

                foreach (var valueName in subKey.GetValueNames())
                {
                    var rawValue = subKey.GetValue(valueName)?.ToString();
                    if (string.IsNullOrWhiteSpace(rawValue))
                    {
                        continue;
                    }

                    entries.Add(BuildEntry("Registry Run key", target.Scope, valueName, rawValue, null));
                }
            }
            catch
            {
                // Skip inaccessible keys and keep the rest of the audit usable.
            }
            finally
            {
                subKey?.Dispose();
                baseKey?.Dispose();
            }
        }

        return entries;
    }

    public static IEnumerable<AutostartEntry> ScanStartupFolder(string folderPath, string sourceType, string scope)
    {
        if (string.IsNullOrWhiteSpace(folderPath) || !Directory.Exists(folderPath))
        {
            yield break;
        }

        foreach (var path in Directory.EnumerateFiles(folderPath))
        {
            yield return BuildEntry(sourceType, scope, Path.GetFileName(path), path, path);
        }
    }

    [SupportedOSPlatform("windows")]
    public static IEnumerable<AutostartEntry> ScanScheduledTasks()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "schtasks.exe",
            Arguments = "/Query /FO CSV /V",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var process = Process.Start(psi);
        if (process is null)
        {
            yield break;
        }

        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit(15000);
        if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
        {
            yield break;
        }

        var rows = Csv.Parse(output);
        if (rows.Count <= 1)
        {
            yield break;
        }

        var header = rows[0];
        var taskNameIndex = header.FindIndex("TaskName");
        var taskToRunIndex = header.FindIndex("Task To Run");
        var statusIndex = header.FindIndex("Status");
        if (taskNameIndex < 0 || taskToRunIndex < 0)
        {
            yield break;
        }

        for (var index = 1; index < rows.Count; index += 1)
        {
            var row = rows[index];
            var name = row.GetValueOrDefault(taskNameIndex);
            var command = row.GetValueOrDefault(taskToRunIndex);
            var status = statusIndex >= 0 ? row.GetValueOrDefault(statusIndex) : null;
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(command))
            {
                continue;
            }

            yield return BuildEntry("Scheduled task", "Task Scheduler", name, command, null, status);
        }
    }

    private static AutostartEntry BuildEntry(string sourceType, string scope, string name, string command, string? directPath, string? status = null)
    {
        var resolvedPath = directPath ?? CommandInspection.ResolvePath(command);
        var targetExists = CommandInspection.TargetExists(resolvedPath);
        var signals = CommandInspection.RiskSignals(command, resolvedPath, targetExists, status);
        var riskScore = Score(signals);
        return new AutostartEntry(sourceType, scope, name, command, resolvedPath, targetExists, riskScore, signals, status);
    }

    private static int Score(IReadOnlyList<string> signals)
    {
        var score = 0;
        foreach (var signal in signals)
        {
            score += signal switch
            {
                "missing target" => 35,
                "script host" => 20,
                "temp or downloads path" => 15,
                "network path" => 20,
                "disabled task" => 5,
                _ => 10,
            };
        }

        return Math.Min(score, 100);
    }
}

static class CommandInspection
{
    public static string? ResolvePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        if (expanded.StartsWith("\"", StringComparison.Ordinal))
        {
            var endQuote = expanded.IndexOf('"', 1);
            if (endQuote > 1)
            {
                return expanded[1..endQuote];
            }
        }

        var exeIndex = expanded.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIndex >= 0)
        {
            return expanded[..(exeIndex + 4)].Trim();
        }

        var firstToken = expanded.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return firstToken;
    }

    public static bool TargetExists(string? resolvedPath)
    {
        if (string.IsNullOrWhiteSpace(resolvedPath))
        {
            return false;
        }

        if (resolvedPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return true;
        }

        return File.Exists(resolvedPath) || Directory.Exists(resolvedPath);
    }

    public static IReadOnlyList<string> RiskSignals(string command, string? resolvedPath, bool targetExists, string? status)
    {
        var signals = new List<string>();
        var lowerCommand = command.ToLowerInvariant();
        var lowerPath = resolvedPath?.ToLowerInvariant() ?? string.Empty;

        if (!targetExists)
        {
            signals.Add("missing target");
        }

        if (lowerCommand.Contains("powershell") || lowerCommand.Contains("cmd.exe") || lowerCommand.Contains("wscript") || lowerCommand.Contains("cscript"))
        {
            signals.Add("script host");
        }

        if (lowerPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            signals.Add("network path");
        }

        if (lowerPath.Contains(@"\appdata\local\temp\") || lowerPath.Contains(@"\downloads\"))
        {
            signals.Add("temp or downloads path");
        }

        if (!string.IsNullOrWhiteSpace(status) && status.Contains("Disabled", StringComparison.OrdinalIgnoreCase))
        {
            signals.Add("disabled task");
        }

        return signals;
    }
}

static class ReportBuilder
{
    public static AuditReport Build(IReadOnlyList<AutostartEntry> entries)
    {
        return new AuditReport(
            Environment.MachineName,
            DateTimeOffset.Now.ToString("O"),
            entries.Count,
            entries.Count(entry => entry.RiskScore >= 35),
            entries.Count(entry => !entry.TargetExists),
            entries.Count(entry => entry.RiskSignals.Contains("script host")),
            entries);
    }
}

static class Printer
{
    public static void Print(AuditReport report)
    {
        Console.WriteLine("Windows Autostart Auditor");
        Console.WriteLine("=========================");
        Console.WriteLine($"Machine:            {report.MachineName}");
        Console.WriteLine($"Generated:          {report.GeneratedAt}");
        Console.WriteLine($"Entries scanned:    {report.EntryCount}");
        Console.WriteLine($"High-risk entries:  {report.HighRiskCount}");
        Console.WriteLine($"Missing targets:    {report.MissingTargetCount}");
        Console.WriteLine($"Script hosts:       {report.ScriptHostCount}");
        Console.WriteLine();

        if (report.Entries.Count == 0)
        {
            Console.WriteLine("No autostart entries were found.");
            return;
        }

        Console.WriteLine($"{"Source",-18} {"Risk",4} {"Name",-32} {"Signals"}");
        Console.WriteLine(new string('-', 92));
        foreach (var entry in report.Entries.Take(12))
        {
            var signalText = entry.RiskSignals.Count == 0 ? "none" : string.Join(", ", entry.RiskSignals);
            Console.WriteLine($"{Trim(entry.SourceType, 18),-18} {entry.RiskScore,4} {Trim(entry.Name, 32),-32} {signalText}");
        }
    }

    private static string Trim(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : $"{value[..(maxLength - 3)]}...";
    }
}

static class MarkdownWriter
{
    public static string Write(AuditReport report)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Windows Autostart Audit");
        builder.AppendLine();
        builder.AppendLine($"- Machine: `{report.MachineName}`");
        builder.AppendLine($"- Generated: `{report.GeneratedAt}`");
        builder.AppendLine($"- Entries scanned: `{report.EntryCount}`");
        builder.AppendLine($"- High-risk entries: `{report.HighRiskCount}`");
        builder.AppendLine($"- Missing targets: `{report.MissingTargetCount}`");
        builder.AppendLine($"- Script hosts: `{report.ScriptHostCount}`");
        builder.AppendLine();
        builder.AppendLine("## Highest-risk entries");
        builder.AppendLine();
        builder.AppendLine("| Source | Risk | Name | Signals | Command |");
        builder.AppendLine("| --- | ---: | --- | --- | --- |");
        foreach (var entry in report.Entries.Take(12))
        {
            builder.Append("| ")
                .Append(Escape(entry.SourceType)).Append(" | ")
                .Append(entry.RiskScore).Append(" | ")
                .Append(Escape(entry.Name)).Append(" | ")
                .Append(Escape(entry.RiskSignals.Count == 0 ? "none" : string.Join(", ", entry.RiskSignals))).Append(" | ")
                .Append(Escape(entry.Command)).AppendLine(" |");
        }

        return builder.ToString();
    }

    private static string Escape(string value)
    {
        return value.Replace("|", "\\|");
    }
}

static class Csv
{
    public static List<List<string>> Parse(string input)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        var inQuotes = false;

        for (var index = 0; index < input.Length; index += 1)
        {
            var ch = input[index];
            if (inQuotes)
            {
                if (ch == '"' && index + 1 < input.Length && input[index + 1] == '"')
                {
                    field.Append('"');
                    index += 1;
                }
                else if (ch == '"')
                {
                    inQuotes = false;
                }
                else
                {
                    field.Append(ch);
                }

                continue;
            }

            if (ch == '"')
            {
                inQuotes = true;
                continue;
            }

            if (ch == ',')
            {
                row.Add(field.ToString());
                field.Clear();
                continue;
            }

            if (ch == '\r')
            {
                continue;
            }

            if (ch == '\n')
            {
                row.Add(field.ToString());
                field.Clear();
                rows.Add(row);
                row = new List<string>();
                continue;
            }

            field.Append(ch);
        }

        if (field.Length > 0 || row.Count > 0)
        {
            row.Add(field.ToString());
            rows.Add(row);
        }

        return rows;
    }

    public static int FindIndex(this IReadOnlyList<string> header, string name)
    {
        for (var index = 0; index < header.Count; index += 1)
        {
            if (string.Equals(header[index], name, StringComparison.OrdinalIgnoreCase))
            {
                return index;
            }
        }

        return -1;
    }

    public static string GetValueOrDefault(this IReadOnlyList<string> row, int index)
    {
        return index >= 0 && index < row.Count ? row[index] : string.Empty;
    }
}
