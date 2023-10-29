/*
Author: Spyros Maris
Date: 27/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/


include "Commons/Pressidium-common-encodings.yar" // rulenames: common_encoding_php , obfuscated_common_encodings_php 
include "Commons/Pressidium-common-eval-usage.yar" // rulenames: Detect_Eval_Usage
include "Commons/Pressidium-common-shell-commands.yar" // rulenames: common_unix_commands, common_uxin_commands_base64
include "Commons/Pressidium-common-PHP-functions.yar" // rulenames: common_PHP_functions, common_PHP_functions_base64_encoded
include "Commons/Pressidium-common-error-reporting.yar" //rulenames: common_disable_error_reporting


private rule Pressidium_Commons
{
	condition:
		common_encoding_php or obfuscated_common_encodings_php or Detect_Eval_Usage or common_unix_commands or common_uxin_commands_base64 or common_PHP_functions or common_PHP_functions_base64_encoded or common_disable_error_reporting
}
