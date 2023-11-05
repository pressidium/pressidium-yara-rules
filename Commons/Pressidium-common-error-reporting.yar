/*
Author: Spyros Maris
Date: 26/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */


rule common_disable_error_reporting
{
    meta:
        description = "This rule detects common PHP error reporting disablement techniques."
        author = "Spyros Maris"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
        date = "26/10/2023"
    strings:
        $error_reporting1 = "error_reporting(0);" wide ascii
        $error_reporting2 = "ini_set('log_errors', 0)" wide ascii 
        $error_reporting3 = "ini_set('display_errors', 0)" wide ascii
        $error_reporting4 = "ini_set('error_log', NULL)" wide ascii
        $error_reporting7 = "ini_set('display_errors','Off');" wide ascii
        $error_reporting8 = "ini_set('display_errors', FALSE);" wide ascii
    condition:
        1 of them
}
