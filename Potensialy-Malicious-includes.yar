/*
Author: Spyros Maris
Date: 27/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */

include "Commons/Pressidium-common-encodings.yar" // rulenames: common_encoding_php , obfuscated_common_encodings_php 
include "Commons/Pressidium-common-eval-usage.yar" // rulenames: Detect_Eval_Usage
include "Commons/Pressidium-common-shell-commands.yar" // rulenames: common_unix_commands, common_uxin_commands_base64
include "Commons/Pressidium-common-PHP-functions.yar" // rulenames: common_PHP_functions, common_PHP_functions_base64_encoded
include "Commons/Pressidium-common-error-reporting.yar" //rulenames: common_disable_error_reporting


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
	$include_pattern2 = /@include\("[\\0-7a-fA-Fx]+?"\);/
	$include_octal_pattern = /@include\s*\("[\\0-7]{1,3}\\[\\0-7]{1,3}\\[\\0-7]{1,3}.*"\);/
	$php_include_same_line = /@\s*include\s*/ nocase 
	condition:
        any of them and (1 of (common_encoding_php, obfuscated_common_encodings_php, Detect_Eval_Usage, common_unix_commands, common_uxin_commands_base64, common_PHP_functions, common_PHP_functions_base64_encoded, common_disable_error_reporting))
}

/*
Author: Stefanos Mpatsios
Date: 31/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */

rule SuspiciousAsciiAndIncludes 
{
   meta:
      author = "Stefanos Mpatsios"
      date = "31/10/2023"
      description = "This rule created to detect suspicious ascii paths usage and inclusions from wp-storage on chrooted env in PHP files."
      reference = "https://github.com/pressidium/pressidium-yara-rules" 
   strings:
      $s1 = /@include/
      $s2 = /\/\*[A-Za-z0-9]{5}\*\//
      $s3 = /@include ?\("\/wp-storage\/c(0|[1-9][0-9]*)\/[^)]*\"\)/
      $s4 = /@include ?\("\\([0-9]+(\\[0-9]+)+)\\?"\);/
      $s5 = /\\?([0-9]+(\\[0-9]+)+)/
   condition:
      ($s2 and $s1) or $s3 or $s4 or $s2 or $s5
}
