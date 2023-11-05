/*
Author: Spyros Maris
Date: 26/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */


rule Detect_Eval_Usage
{
    meta:  // Meta section for rule metadata
        description = "This rule detects the usage of eval() function in different variations and encodings"
        author = "Spyros Maris"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
        date = "26/10/2023"
    strings:
        $eval1 = "eval(" wide ascii 
        $eval2 = { 65 76 41 4C 28 } // Hex encoded eval(
        $eval3 = /e"."val\(/ wide ascii 
        $eval4 = /(\$[a-zA-Z0-9_]+)\s*\(\s*['"][^'"]+['"]\s*\)/ wide ascii nocase // Variable function call, nocase for case-insensitive matching
        $eval5 = /e\s*\/\*\s*\/\s*v\s*\/\*\s*\/\s*a\s*\/\*\s*\/\s*l\s*\/\*\s*\/\s*\(/ wide ascii // Comments/whitespace obfuscation
        $eval6 = "lave(" wide ascii // Reversed eval
        $eval7 = /base64_decode\s*\(\s*['"][^'"]+['"]\s*\)\s*\)/ wide ascii // Encoding/decoding before eval
        $eval8 = "assert(" wide ascii // Assertion obfuscation
        $remote_code_execution = /eval\(\s*\$php\s*\);/ wide ascii
        $eval_CRgwR = "eval(CRgwR()" ascii
        $eval_function = /@?eval\(\w+\(\w+\['\w+'\]\)\);/ wide ascii
        $eval_function2 = /eval\s*\(\s*\$[a-zA-Z_]\w*\s*\[\d+\]\s*\(.*\)\s*\);/ wide ascii
		$eval9 = "eVAL(\"?>\".$b($a))" wide ascii 
    condition:  
        1 of them  
}
