rule Detect_PS1_Scripts {
    meta:
        description = "Detects PowerShell script files based on hex signature .ps1"
        author = "El Ignite"
        date = "2025-04-01"
        reference = "Internal Threat Detection"

    strings:
        $zip_header = { 50 4B 03 04 } // .zip
        $ps1_ext = { 2E 70 73 31 } // .ps1 in hex
        $exe_ext = { 2E 65 78 65 } // .exe in hex
        $exe_header = { 4D 5A }       // 'MZ' header for Windows executables


    condition:
         $zip_header and ($ps1_ext or $exe_header or $exe_ext)
}
