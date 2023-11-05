/*
Author: Spyros Maris
Date: 27/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */


rule common_encoding_php
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects common encoding functions in malicious PHP code snippets"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $base64 = "base64_decode"
        $gzinflate = "gzinflate"
        $str_rot13 = "str_rot13"
    condition:
        2 of them and not ".js"
}

rule obfuscated_common_encodings_php
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects common obfuscated encoding functions in malicious PHP code snippets"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $base64 = "YmFzZTY0X2RlY29kZQ=="
        $gzinflate = "Z3ppbmZsYXRl"
        $str_rot13 = "c3RyX3JvdDEz"
        $base64_reg = /(b[._]a[._]se[._]6[._]4[._]d[._]ec[._]od[._]e|ba[._]se[._]64[._]_d[._]ecode)/ ascii wide nocase
        $str_rot13_reg = /(s[._]tr[._]_r[._]ot[._]13|s[._]tr[._]_ro[._]t13|s[._]t[._]rrev)/ ascii wide nocase
        $gzinflate_reg = /(g[._]z[._]in[._]fl[._]at[._]e|gzin[._]flat[._]e)/ ascii wide nocase
    condition:
        1 of them
}