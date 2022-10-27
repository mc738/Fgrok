

open System.Text.RegularExpressions
open Fgrok

let patterns =
    [
        "ZIPCODE", "[1-9]{1}[0-9]{2}\s{0,1}[0-9]{3}"
        "EMAILADDRESS", "[a-zA-Z][a-zA-Z0-9_.+-=:]+@\\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\\b)"
        "EMAILLOCALPART", "[a-zA-Z][a-zA-Z0-9_.+-=:]+"
        "HOSTNAME", "\\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\\b)"
        "MONTHDAY", "(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])"
        "SYSLOGTIMESTAMP", "%{MONTH} %{MONTHDAY} %{TIME}"
        "MONTH", "\\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?|[Jj]un(?:e|i)?|[Jj]ul(?:y)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\\b"
        "TIME", "(?!<[0-9])%{HOUR}:%{MINUTE}(?::%{SECOND})(?![0-9])"
        "HOUR", "(?:2[0123]|[01]?[0-9])"
        "MINUTE", "(?:[0-5][0-9])"
        "SECOND", "(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)"
        "SYSLOGHOST", "%{IPORHOST}"
        "IPORHOST", "(?:%{IP}|%{HOSTNAME})"
        "HOSTNAME", "\\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\\b)"
        "IP", "(?:%{IPV6}|%{IPV4})"
        "IPV4", "(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])"
        "IPV6", "((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?"
    ]
    |> Map.ofList


let test = "Feb 21 08:35:22 localhost sshd[5774]: Failed password for root from 116.31.116.24 port 29160 ssh2"

let t = Grok.Create(patterns, "%{SYSLOGTIMESTAMP:system_auth_timestamp} %{SYSLOGHOST:system_auth_hostname}")

let r1 = t.Run(test)

let grok = Grok.Create(patterns, "%{ZIPCODE:zipcode}:%{EMAILADDRESS:email}")

let r = grok.Run("122001:Bob.Davis@microsoft.com")

let logTest = "%{SYSLOGTIMESTAMP:system.auth.timestamp} %{SYSLOGHOST:system.auth.hostname} sshd(?:\\[%{POSINT:system.auth.pid}\\])?: %{DATA:system.auth.ssh.event} %{DATA:system.auth.ssh.method} for (invalid user )?%{DATA:system.auth.user} from %{IPORHOST:system.auth.ip} port %{NUMBER:system.auth.port} ssh2(: %{GREEDYDATA:system.auth.ssh.signature})?"



//let str = Grok.parseGrokString patterns "%{ZIPCODE:zipcode}:%{EMAILADDRESS:email}"

//let r = Regex(str, RegexOptions.Compiled ||| RegexOptions.ExplicitCapture)

//let regex = r.Match("122001:Bob.Davis@microsoft.com").Groups

//let keys = regex.Keys |> List.ofSeq
//let gns = r.GetGroupNames()

// For more information see https://aka.ms/fsharp-console-apps
printfn "Hello from F#"