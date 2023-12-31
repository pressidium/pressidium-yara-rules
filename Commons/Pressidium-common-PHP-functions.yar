/*
Author: Spyros Maris
Date: 26/10/2023
GitHub: https://github.com/pressidium/pressidium-yara-rules
*/

/* ------------------------------ Rule Set ------------------------------ */



rule common_PHP_functions
{
    meta:
        description = "Detects common PHP functions and strings used in WordPress web shells"
        author = "Spyros Maris"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
        date = "26/10/2023"
    strings:
        $file_get_contents = "file_get_contents" wide ascii
        $shell_exec = "shell_exec" wide ascii
        $exec = "exec" wide ascii
        $passthru = "passthru" wide ascii
        $system = "system" wide ascii
        $proc_open = "proc_open" wide ascii
        $assert = "assert" wide ascii
        $create_function = "create_function" wide ascii
        $preg_replace = /preg_replace\s*\(\s*["']\/\.\*\/e["']\s*,/ wide ascii // preg_replace with /e modifier is often used for code execution
        $move_uploaded_file = "move_uploaded_file" wide ascii
        $wp_nonce_field = "wp_nonce_field" wide ascii
        $wp_verify_nonce = "wp_verify_nonce" wide ascii
        $upload_dir = "wp_upload_dir" wide ascii
        $current_user = "wp_get_current_user" wide ascii
        $update_option = "update_option" wide ascii
        $curl_exec = "curl_exec" wide ascii
        $curl_setopt = "curl_setopt" wide ascii
        $ob_start = "ob_start" wide ascii
        $unserialize = "unserialize" wide ascii
        $ini_set = "ini_set" wide ascii
        $file_put_contents = "file_put_contents" wide ascii
        $fopen = "fopen" wide ascii
        $fwrite = "fwrite" wide ascii
        $fclose = "fclose" wide ascii
        $fsockopen = "fsockopen" wide ascii
        $fread = "fread" wide ascii
        $fgets = "fgets" wide ascii
        $fputs = "fputs" wide ascii
        $ftruncate = "ftruncate" wide ascii
        $unlink = "unlink" wide ascii
        $set_time_limit = "set_time_limit" wide ascii
        $md5 = "md5" wide ascii
        $rawurldecode = "rawurldecode" wide ascii
        $chr = "chr" wide ascii
        $session_start = "session_start" wide ascii
		$getallheaders = "getallheaders" wide ascii
		$isset = "isset" wide ascii
		$gettype = "gettype" wide ascii
		$inarray = "in_array" wide ascii
		$count = "count" wide ascii
		$explode = "explode" wide ascii
		$strpos = "strpos" wide ascii
		$empty = "empty" wide ascii
		$Array = "Array" wide ascii
		$foreach = "foreach" wide ascii
		$die = "die" wide ascii
		$str_pad = "str_pad" wide ascii
		$strlen = "strlen" wide ascii
		$array_push = "array_push" wide ascii
		$is_writable = "is_writable" wide ascii
		$is_dir = "is_dir" wide ascii
		$scandir = "scandir" wide ascii
    condition:
        3 of them 
}


rule common_PHP_functions_base64_encoded
{
    meta:
        description = "Detects common PHP functions and strings used in WordPress web shells (Base64-encoded)"
        author = "Spyros Maris"
        reference = "https://github.com/pressidium/pressidium-yara-rules"
        date = "26/10/2023"
    strings:
        $str_rot13 = "c3RyX3JvdDEzKA==" base64
        $gzinflate = "Z3ppbmZsYXRlKA==" base64
        $file_get_contents = "ZmlsZV9nZXRfY29udGVudHMo" base64
        $shell_exec = "c2hlbGxfZXhlYyg=" base64
        $exec = "ZXhlYyg=" base64
        $passthru = "cGFzc3RocnUo" base64
        $system = "c3lzdGVtKA==" base64
        $proc_open = "cHJvY19vcGVuKA==" base64
        $assert = "YXNzZXJ0KA==" base64
        $create_function = "Y3JlYXRlX2Z1bmN0aW9uKA==" base64
        $move_uploaded_file = "bW92ZV91cGxvYWRlZF9maWxlKA==" base64
        $wp_nonce_field = "d3Bfbm9uY2VfZmllbGQo" base64
        $wp_verify_nonce = "d3BfdmVyaWZ5X25vbmNlKA==" base64
        $upload_dir = "d3BfdXBsb2FkX2Rpcig=" base64
        $current_user = "d3BfZ2V0X2N1cnJlbnRfdXNlcig=" base64
        $update_option = "dXBkYXRlX29wdGlvbig=" base64
        $curl_exec = "Y3VybF9leGVjKA==" base64
        $curl_setopt = "Y3VybF9zZXRvcHQK" base64
        $ob_start = "b2Jfc3RhcnQo" base64
        $unserialize = "dW5zZXJpYWxpemUo" base64
        $ini_set = "aW5pX3NldCg=" base64
        $file_put_contents = "ZmlsZV9wdXRfY29udGVudHMo" base64
        $fopen = "ZmlsZV9mb3JtYXQo" base64
        $fwrite = "ZmlsZV93cml0ZSg=" base64
        $fclose = "ZmlsZV9jbG9zZSg=" base64
        $fsockopen = "ZmlsZV9zb2NrZXQo" base64
        $fread = "ZmlsZV9yZWFkKA==" base64
        $fgets = "ZmlsZV9nZXRzKA==" base64
        $fputs = "ZmlsZV9wdXRzKA==" base64
        $ftruncate = "ZmlsZV90cnVuY3R1cmUo" base64
        $unlink = "ZmlsZV91bmxpbms=" base64
        $set_time_limit = "c2V0X3RpbWVfbGltaXQo" base64
        $md5 = "bWQ1KCk=" base64
        $rawurldecode = "cmF3dXJsZGVjb2RlKA==" base64
        $chr = "Y2hyKA==" base64
        $session_start = "c2Vzc2lvbl9zdGFydCg=" base64
		$getallheaders = "Z2V0YWxsZGVhZGVycygp" base64
		$isset = "aXNzZXQo" base64
		$gettype = "Z2V0dHlwZSgp" base64
		$inarray = "aW5fYXJyYXko" base64
		$count = "Y291bnQo" base64
		$explode = "ZXhwbG9kZSgp" base64
		$strpos = "c3RybXBsb2FkKCk=" base64
		$empty = "ZW1wdHko" base64
		$Array = "QXJyYXk=" base64
		$foreach = "Zm9yZXRjaCgp" base64
		$die = "ZGllKCk=" base64
		$str_pad = "c3RyX3BhZCgp" base64
		$strlen = "c3RyX2xlbmd0aCgp" base64
		$array_push = "YXJyYXlfcHVzaCgp" base64
		$is_writable = "aXNfd3JpdGFiZWwo" base64
		$is_dir = "aXNfZGlyKCk=" base64
		$scandir = "c2NhbmRpcig=" base64
    condition:
        3 of them 
}
