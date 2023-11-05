/*
Author: Spyros Maris
Date: 27/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */
/* 
This rules set detects specific malicious PHP code snippets that found in some wordpress sites hosted in Pressidium.
*/
include "Commons/Pressidium-common-encodings.yar" // rulenames: common_encoding_php , obfuscated_common_encodings_php 
include "Commons/Pressidium-common-eval-usage.yar" // rulenames: Detect_Eval_Usage
include "Commons/Pressidium-common-shell-commands.yar" // rulenames: common_unix_commands, common_uxin_commands_base64
include "Commons/Pressidium-common-PHP-functions.yar" // rulenames: common_PHP_functions, common_PHP_functions_base64_encoded
include "Commons/Pressidium-common-error-reporting.yar" //rulenames: common_disable_error_reporting


rule magic_file_headers
{
    meta:
        author = "Spyros Maris"
        date = "27/10/2023"
        description = "This rule detects the presence of magic file headers with the <?php tag in the beginning of the file."
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
        $BOM = { EF BB BF } // UTF-8 BOM
        $EXE = "MZ" ascii
        $ELF = "\x7FELF" 
        $MP4 = "ftyp" ascii
        $AVI = "RIFF" ascii
        $WAV = "RIFF" ascii
        $MP3 = { FF FB }
        $MIDI = "MThd" ascii
        $TAR = { 75 73 74 61 72 } // ustar
        $SQLITE = "SQLite format 3" ascii
        $HTML = "<!DOCTYPE html" ascii
        $XML = "<?xml" ascii
    condition:
        1 of ($PDF, $JPG, $GIF, $PNG, $BMP, $ZIP, $RAR, $DOC, $BOM, $EXE, $ELF, $MP4, $AVI, $WAV, $MP3, $MIDI, $TAR, $SQLITE, $HTML, $XML) at 0 and $php  
}
