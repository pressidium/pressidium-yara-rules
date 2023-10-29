/*
Author: Spyros Maris
Date: 27/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */


rule SuspiciousIncludeUsage
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule created to detect suspicious header usage in PHP files."
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $suspicious_include = /include\(\s*['"]\s*header.php\s*['"]\s*\)/
        $include_pattern = /include\(\w+\(\w+\)\['uri'\]\);/
        $include_string = /@include\s*\("\S+"\);/
        $include_string2 = "@package AKWH9WV2" ascii wide nocase
        $suspicious_include3 = /@\$yh6\[\d+\]\(\$kw13\);@include\(\$kw13\);@\$yh6\[\d+\]\(\$kw13\);exit\(\);/ wide ascii // Detects the usage of @\$yh6[0]($kw13);@include($kw13);@\$yh6[1]($kw13);exit();
    condition:
        1 of them
}