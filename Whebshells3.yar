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

rule malicious_PHP_code_snippet6
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium."
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $obfuscated_function= "function O_0O_O0_0O(" ascii wide nocase
        $obfuscated_string = "$O_OO0O0_0_=urldecode" ascii wide nocase
        $obfuscated_string1 = { 4f 4f 30 4f 30 5f 5f 30 4f 5f }  
        $obfuscated_string2 = "echo $O0__O00O_O;die();}}O_O_O_000O($O__O0_OO00);" ascii wide nocase
        $obfuscated_string3 = "if(isset($_REQUEST[" ascii wide nocase
        $obfuscated_string4 = "CURLOPT" ascii wide nocase
        $obfuscated_string5 = "$O_0OO_O_00" ascii wide nocase
        $obfuscated_string6 = /(\[\d+\]\.)*\[\d+\]/ /* This regex pattern matches a sequence of array accesses and concatenations, e.g., $array[0].$array[1].$array[2] */
    condition:
        any of them and Pressidium_Commons
}

rule malicious_PHP_code_snippet7
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium."
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $urldecode_pattern = "urldecode" ascii wide nocase
        $concat_pattern1 = {38 24 30 30 30 4F 4F 5F 30 5F 4F 5F 7B 33 38 7D 2E 24 30 30 30 4F 4F 5F 30 5F 4F 5F 7B 31 32 7D} // $O00OO_0_O_=$O00OO_0_O_{38}.$O00OO_0_O_{12}
        $concat_pattern2 = {24 4F 30 30 4F 4F 5F 30 5F 4F 5F 7B 33 32 7D 2E 24 4F 30 30 4F 4F 5F 30 5F 4F 5F 7B 32 34 7D} // $O0O0O0_0_O_=$O00OO_0_O_{32}.$O00OO_0_O_{24}
        $regex_pattern = /(\[\d+\]\.)*\[\d+\]/ /* This regex pattern matches a sequence of array accesses and concatenations, e.g., $array[0].$array[1].$array[2] */
        $globalvar = "__GLOBALS" ascii wide nocase
        $curlopt_pattern = "CURLOPT" ascii wide nocase
        $isset_pattern = "isset" ascii wide nocase
        $request_pattern = "_REQUEST" ascii wide nocase
        $server_pattern = "_SERVER" ascii wide nocase
    condition:
        any of them and Pressidium_Commons
}

rule malicious_PHP_code_snippet8
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $password_assignment = "DSCRXtbVQAp" ascii wide nocase
        $leaf_version = "2.8" ascii wide nocase
        $leaf_website = "leafmailer.pw" ascii wide nocase
        $session_code_check = "$_SESSION[$sessioncode]" ascii wide nocase
        $request_pass_check = "isset($_REQUEST['pass'])" ascii wide nocase
        $password_check = "and $_REQUEST['pass'] == $password" ascii wide nocase
    condition:
        any of them and Pressidium_Commons
}
