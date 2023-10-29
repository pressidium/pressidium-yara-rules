/*
Author: Spyros Maris
Date: 26/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */


rule common_unix_commands
{
    meta:
        description = "This rule detects common unix commands that are used by attackers to perform malicious actions."
        author = "Spyros Maris"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
        date = "26/10/2023"
    strings:
        $cmd1 = "wget"
        $cmd2 = "curl"
        $cmd3 = "crontab"
        $cmd4 = "chmod"
        $cmd5 = "chown"
        $cmd6 = "kill"
        $cmd7 = "rm"
        $cmd8 = "rmdir"
        $cmd9 = "mkdir"
        $cmd10 = "tar"
        $cmd11 = "zip"
        $cmd12 = "unzip"
        $cmd13 = "ps"
        $cmd14 = "cat"
        $cmd15 = "grep"
        $cmd16 = "find"
        $cmd17 = "nano"
        $cmd18 = "vim"
        $cmd19 = "vi"
        $cmd20 = "mv"
    condition:
        any of them
}

rule common_uxin_commands_base64
{
    meta:
        description = "This rule detects common unix commands used in webshells encoded in base64"
        author = "Spyros Maris"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
        date = "26/10/2023"
    strings:
        $wget = "d2dldA==" base64
        $curl = "Y3VybA==" base64
        $crontab = "Y3JvbnRhYg==" base64
        $chmod = "Y2htb2Q=" base64
        $chown = "Y2hvd24=" base64
        $kill = "a2lsbA==" base64
        $rm = "cm0=" base64
        $rmdir = "cm1kaXI=" base64
        $mkdir = "bWtkaXI=" base64
        $tar = "dGFy" base64
        $zip = "emlw" base64
        $unzip = "dW56aXA=" base64
        $ps = "cHM=" base64
        $cat = "Y2F0" base64
        $grep = "Z3JlcA==" base64
        $find = "ZmluZA==" base64
        $nano = "bmFubw==" base64
        $vim = "dmlt" base64
        $vi = "dmk=" base64
        $mv = "bXY=" base64
    condition:
        any of them
}
