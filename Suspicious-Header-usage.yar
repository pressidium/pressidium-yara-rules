/*
Author: Spyros Maris
Date: 27/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */
/* 
This rules set detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium.
*/

/*TODO we need to find from our malware samples more ways atters use headers for their attacks*/

rule SuspiciousHeaderUsage
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects suspicious usage of PHP headers."
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $get_headers = "getallheaders();" ascii wide nocase
        $header_check = "isset($_HEADERS['If-Unmodified-Since'])" ascii wide nocase
        $nested_request = /\$request\s*=\s*\$_HEADERS\['If-Unmodified-Since'\]\('',\s*\$_HEADERS\['If-Modified-Since'\]\(\$_HEADERS\['Feature-Policy'\]\)\);/
        $request_execution = "$request();" ascii wide nocase
        $header1 = /header\("X-XSS-Protection: 0"\);/
    condition:
        2 of them
}