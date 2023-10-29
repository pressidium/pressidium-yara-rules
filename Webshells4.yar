/*
Author: Spyros Maris
Date: 27/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */
/* 
This rules set detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium.
*/
include "Pressidium-commons-init.yar"

rule malicious_PHP_code_snippet1
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $password_assignment = "password = " ascii wide nocase
        $leaf_version_assignment = "['version']=" ascii wide nocase
        $leaf_website_assignment = "['website']=" ascii wide nocase
        $session_start = "session_start();" ascii wide nocase
        $session_md5 = "md5(__FILE__)" ascii wide nocase
        $session_code_check = "$_SESSION[" ascii wide nocase
        $request_pass_check = "isset($_REQUEST['pass'])" ascii wide nocase

    condition:
        any of them and Pressidium_Commons
}

rule Obfuscated_PHP_code_snippet2
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $string5 = "28c754cd-7e52-42c6-9c21-792cd3873e65" ascii wide nocase
        $string6 = "2343d8d3-1d44-49e7-a1f6-455c2badd978" ascii wide nocase
        $string7 = "<?=123*4;echo `$_GET[0]`; ?>" ascii wide nocase
        $chr_pattern = /chr\(\d+(-\d+)?\)/ ascii wide nocase
        $hex_pattern = /\\x[0-9A-Fa-f]{2}/ ascii wide nocase
    condition:
        any of them and Pressidium_Commons
}

rule Obfuscated_malicous_PHP_code_snippet1
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $obfuscated_function = /\$lwibrwbof\(\d+-\d+\)/
        $hex_string = /\x5c\x78[0-9a-fA-F]{2}/
        $function_sequence = /function.*_nkk_or\(\$rofegia,\s+\$eesmlbfmew\)/
        $cookie_merge_post = /\$_COOKIE;\s*\$szrspxsp\s*=\s*array_merge\(\$szrspxsp,\s*\$_POST\);/
        $encoded_string = /"\x37\x64-\x36\x34-\x34\x36\x38\x35-\x62\x37\x65\x62-\x37\x63\x31"/
        $hex_string2 = /\x5c\x78[0-9a-fA-F]{2}/
        $chr_function = /chr\s*\(\s*\d+\s*-\s*\d+\s*\)/
        $string_concat = /"\x73".*?"\x72".*?chr/
        $array_merge_pattern = /foreach\s*\(.*Array\(.*\$_POST,.*\$_COOKIE,.*\)\s*as\s*\$[a-zA-Z_]\w*\)/
        $malicious_package = "@package AKWH9WV2" ascii wide nocase
        $string_concat2 = /'\w+'.'\w+'.'\w+'.'\w+'/
        $array_merge_pattern2 = /array_merge\(\$_GET, \$_COOKIE, \$_POST\);/
    condition:
       	any of them and Pressidium_Commons

}


rule DrunkShell_webshell_detection
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects DrunkShell webshell"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $fileheader = "DrunkShell v 1.0.0" ascii wide nocase
        $pattern1 = /\$[A-Za-z0-9_]+\s*=\s*\$ABC\[\d+\]\.\$ABC\[\d+\];/ // This regex pattern searches for a sequence where a variable is being assigned a value formed by accessing and concatenating elements from an array named $ABC. 
        $php_session1 = /\$_SESSION\["mysql"\]/
        $php_session2 = /\["(\?:server|username|pwd|database)"\]/
        $mysqli_conn = /new mysqli\(.+?\);/        
        $authvar = "$auth = " ascii wide nocase
        $string = "DRUNK SHELL BETA" ascii wide nocase
        $string2 = "s4ndal.py" ascii wide nocase
        $base64_encoded_string = /ZmQ"."0"."NWR"."jZ"."GI0NGF"."iODVi"."Yj"."M2N"."WVmY"."TE4Zj"."Q4MTM3OGQ=/
    condition:
        any of them and Pressidium_Commons
}



