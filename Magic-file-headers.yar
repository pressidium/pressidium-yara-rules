/*
Author: Spyros Maris
Date: 27/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */
/* 
This rules set detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium.
*/

rule magic_file_headers
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detecs the presence of magic file headers with the <?php tag in the beginning of the file. "
        reference = "https://github.com/pressidium/pressidium-yara-rules"
    strings:
        $PDF = "%PDF-" ascii
        $JPG = "JFIF" ascii
        $GIF = "GIF8" ascii
        $PNG = "PNG" ascii
        $BMP = "BM" ascii
        $ZIP = "PK" ascii
        $RAR = "Rar!" ascii
        $DOC = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" 
        $php = "<?php" ascii
    condition:
        1 of ($PDF, $JPG, $GIF, $PNG, $BMP, $ZIP, $RAR, $DOC) and $php  
}
