// so what i analysed that this luckyware rat is fetching domains from github repositories,
// the latest version of this rat has nothing changed since the source-code leak also,
// the way to decrypt the domain is to use xor with "NtExploreProcess" as the key,
// keep in mind it only works for the short xor code, the longer one is the malw config.
// the malw also creates random temp files with short 2-3 chracter startings the rest is current timestamp
// the timestamp is fetched from chrono::system_clock::now() function using milliseconds.

// fuck yara idk how to make it not detect false shit
//rule Luckyware_TempFile_Detection
//{
//    meta:
//        description = "Detects Luckyware in AppData and Temp"
//        author = "Kamerzystanasyt"
//        date = "2026-01-07"
//        category = "RAT"
//        severity = "Critical"
//        actor_type = "LUCKYWARE"
//        reference = "https://github.com/Emree1337/Luckyware/blob/main/LuckywareCode/InfDLL/TheDLL.cpp#L59"
//
//    strings:
//        $temp_naming = /\b[A-Z]{2,3}[0-9]{10,13}(\.exe)?/
//
//    condition:
//        $temp_naming
//}

rule Luckyware_ImGui_Infection
{
    meta:
        description = "Detects obfuscated hex strings in Luckyware ImGui source"
        author = "Kamerzystanasyt"
        category = "RAT"
        severity = "Critical"
        actor_type = "LUCKYWARE"

    strings:
        $hex_blob = /std::string F[a-zA-Z0-9]{5,}\s*=\s*"(\\x[0-9a-fA-F]{2}){20,}"/

    condition:
        $hex_blob
}

rule Luckyware_PE_Infection
{
    meta:
        description = "Detects Luckyware PE infection via appended executable in .rcdata section"
        author = "Kamerzystanasyt"
        category = "RAT"
        severity = "Critical"
        actor_type = "LUCKYWARE"

    strings:
        $mz = { 4D 5A }
        $rcd = ".rcdata" ascii
        $xor_key = "NtExploreProcess" ascii
        $pe_header = { 50 45 00 00 }
        
    condition:
        $mz at 0 and 
        $rcd and 
        (
            $xor_key or
            (#mz > 1) or
            ($pe_header and @pe_header > 0x1000)
        )
}


rule Luckyware_SUO_Replacement
{
    meta:
        description = "Detects Luckyware's malicious .suo file replacement"
        author = "Kamerzystanasyt"
        date = "2026-01-07"
        category = "RAT"
        severity = "Critical"
        actor_type = "LUCKYWARE"
        reference = "https://github.com/Emree1337/Luckyware/blob/main/LuckywareCode/LuckywareStub/Infector.h#L418"

    strings:
        $magic_header = { D0 CF 11 E0 }
        $xor_key = "NtExploreProcess"

    condition:
        $magic_header and $xor_key
}

rule Luckyware_VCXPROJ_Infection
{
    meta:
        description = "Detects Luckyware in Visual Studio projects"
        author = "Kamerzystanasyt"
        date = "2026-01-07"
        severity = "Critical"
        category = "RAT"
        actor_type = "LUCKYWARE"
        reference = "https://github.com/Emree1337/Luckyware/blob/main/LuckywareCode/LuckywareStub/Infector.h#L163"

    strings:
        $ps_hidden = "powershell -WindowStyle Hidden" nocase
        $iwr = "iwr -Uri" nocase

        // Those are useless because it will detect it anyways
        // even when the file name changes because normal person does not use ps in vxproj.
        // $rat_file1 = "Berok.exe" nocase
        // $rat_file2 = "Zetolac.exe" nocase
        // $rat_file3 = "HPSR.exe" nocase

        $cmd_shell = "cmd.exe /b /c" nocase

    condition:
        $ps_hidden and $iwr and $cmd_shell
}


rule Luckyware_C2_Indicators
{
    meta:
        description = "Detects confirmed Luckyware C2 domains and URL patterns"
        author = "Kamerzystanasyt"
        category = "RAT"
        severity = "Critical"
        actor_type = "LUCKYWARE"
        reference = "https://github.com/Emree1337/Luckyware/blob/main/LuckywareCode/LoaderPRE/Loader.cpp#L231"

    strings:
        $d1 = "devruntime.cy" nocase
        $d2 = "zetolacs-cloud.top" nocase
        $d3 = "frozi.cc" nocase
        $d4 = "exo-api.tf" nocase
        $d5 = "nuzzyservices.com" nocase
        $d6 = "darkside.cy" nocase
        $d7 = "balista.lol" nocase
        $d8 = "phobos.top" nocase
        $d9 = "phobosransom.com" nocase
        $d10 = "pee-files.nl" nocase
        $d11 = "vcc-library.uk" nocase
        $d12 = "luckyware.co" nocase
        $d13 = "luckyware.cc" nocase
        $d14 = "91.92.243.218" nocase
        $d15 = "dhszo.darkside.cy" nocase
        $d16 = "188.114.96.11" nocase
        $d17 = "risesmp.net" nocase
        $d18 = "i-like.boats" nocase
        $d19 = "luckystrike.pw" nocase
        $d20 = "krispykreme.top" nocase
        $d21 = "vcc-redistrbutable.help" nocase

        /* From what i understand those are used for downloading. */
        $path1 = "/Stb/Retev.php" nocase // configuration downloader
        $path2 = "/Stb/PokerFace/" nocase // main api endpoint
        $param = "bl=" nocase // build id

        /* Exactly this one, it uses id for the download */
        /* @Father is the main payload that is an dll */
        /* @Popocum is the data stealer and file infector */
        $path3 = "/Stb/PokerFace/init.php" nocase
        $param2 = "id=" nocase // software id

    condition:
        any of ($d*) or
        (
            any of ($path*) and
            any of ($param*)
        )
}


rule Luckyware_SDK_Namespace
{
    meta:
        description = "Detects Luckyware namespace and function markers in SDK headers"
        author = "Kamerzystanasyt"
        category = "RAT"
        severity = "Critical"
        actor_type = "LUCKYWARE"
        reference = "https://github.com/Emree1337/Luckyware/blob/main/LuckywareCode/LuckywareStub/Infector.h#L552"

    strings:
        $ns1 = "namespace VccLibaries" nocase
        $ns2 = "namespace SDKInfector" nocase

        $func1 = "Bombakla" nocase
        $func2 = "Rundollay" nocase
        $func3 = "InfectSDK" nocase
        $func4 = "InfectINIT" nocase

    condition:
        any of ($ns*) and any of ($func*)
}
