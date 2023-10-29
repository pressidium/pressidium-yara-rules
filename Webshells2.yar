/* 
This rules set detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium.
*/
include "Pressidium-commons-init.yar"

rule malicious_PHP_code_snippet4
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium."
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $function_yq1 = "function yq1" wide ascii
        $array_access = /\[\d+\]/  wide ascii // Detects the usage of array access, e.g., $array[0]
        $string_obfuscation = /"cF;" ."26@m*47 1bgp" ."akru" ."?vh\/nd3sL-<e\)xo9y85\(I'_" ."fi.EHl" ."t"/ wide ascii
        $cookie_post_access = /\$_COOKIE, \$_POST/ wide ascii 
    condition:
        any of them and Pressidium_Commons
}

rule malicious_PHP_code_snippet5
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium."
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $obfuscation_chr = /chr\(\d+-\d+\)/  wide ascii  // Detects the usage of chr() function for obfuscation, e.g., chr(128-23)
        $obfuscation_hex = /x[0-9a-fA-F]{2}/ wide ascii // Detects the usage of hexadecimal values for obfuscation, e.g., \x66                      
        $func_file_io = /f[^ ]{0,10}p[^ ]{0,10}t[^ ]{0,10}_c[^ ]{0,10}t[^ ]{0,10}s/ wide ascii // Detects the usage of file_put_contents function or similar obfuscated function calls
        $xor_function = /for\s*\([^)]*\)\s*{\s*[^}]*\s*chr\s*\(.*\^.*ord\s*\(.*\)\s*\)\s*;?\s*}/ // Detects a function that iterates through two strings and applies XOR operation
    condition:
        any of them and Pressidium_Commons
}