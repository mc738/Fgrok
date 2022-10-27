﻿namespace Fgrok

open System
open System.Text.RegularExpressions

[<AutoOpen>]
module private Internal =
    let private grokRegex =
        Regex("%{(\\w+):(\\w+)(?::\\w+)?}", RegexOptions.Compiled)

    let private grokRegexWithType =
        Regex("%{(\\w+):(\\w+):(\\w+)?}", RegexOptions.Compiled)

    let private grokRegexWithoutName =
        Regex("%{(\\w+)}", RegexOptions.Compiled)


    let replaceWithName (patterns: Map<string, string>) (m: Match) =
        let group1 = m.Groups[2]
        let group2 = m.Groups[1]

        match patterns.TryFind group2.Value with
        | Some str -> $"(?<{group1}>({str}))"
        | None -> $"(?<{group1}>)"

    let replaceWithoutName (patterns: Map<string, string>) (m: Match) =
        let group = m.Groups[1]

        match patterns.TryFind group.Value with
        | Some v -> $"({v})"
        | None -> "()"

    let parseGrokString (patterns: Map<string, string>) (str: string) =

        let rec build (pattern: string) =
            let matches =
                grokRegexWithType.Matches(pattern)

            let newStr =
                grokRegexWithoutName.Replace(
                    grokRegex.Replace(pattern, replaceWithName patterns),
                    MatchEvaluator(fun m -> replaceWithoutName patterns m)
                )

            match newStr.Equals(pattern, StringComparison.CurrentCultureIgnoreCase) with
            | true -> newStr
            | false -> build newStr

        build str

    let compileRegex (pattern: string) =
        Regex(
            pattern,
            RegexOptions.Compiled
            ||| RegexOptions.ExplicitCapture
        )

type Grok =
    private
        { Regex: Regex
          GroupNames: string list }

    static member Create(patterns: Map<string, string>, str: string) =
        let compiled =
            parseGrokString patterns str |> compileRegex

        { Regex = compiled
          GroupNames = compiled.GetGroupNames() |> List.ofSeq }

    member grok.GetRegex() = grok.Regex

    member grok.GetGroupNames() = grok.GroupNames

    member grok.Run(str: string) =
        let m = grok.Regex.Match(str)

        m.Groups
        |> List.ofSeq
        |> List.choose (fun g ->
            match g.Name <> "0" with
            | true ->
                grok.GroupNames
                |> List.tryFind (fun gn -> gn.Equals(g.Name, StringComparison.CurrentCultureIgnoreCase))
                |> Option.map (fun gn -> gn, g.Value)
            | false -> None)
        |> Map.ofList