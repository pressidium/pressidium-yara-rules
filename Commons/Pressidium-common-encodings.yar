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
        any of them
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
        $base64_related = /b.*a.*se6.*4_.*d.*ec.*od.*e|ba.*se.*64.*_d.*ecode/ ascii wide nocase
        $string_related = /s.*tr.*_.*r.*ot.*13|s.*tr.*_ro.*t13|s.*t.*rrev/ ascii wide nocase
        $gzip_related = /g.*z.*in.*fl.*at.*e|gzin.*flat.*e/ ascii wide nocase
    condition:
        any of them
}