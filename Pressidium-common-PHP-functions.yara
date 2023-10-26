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
        $base64_decode = "base64_decode(" wide ascii
        $str_rot13 = "str_rot13(" wide ascii
        $gzinflate = "gzinflate(" wide ascii
        $file_get_contents = "file_get_contents(" wide ascii
        $shell_exec = "shell_exec(" wide ascii
        $exec = "exec(" wide ascii
        $passthru = "passthru(" wide ascii
        $system = "system(" wide ascii
        $proc_open = "proc_open(" wide ascii
        $assert = "assert(" wide ascii
        $create_function = "create_function(" wide ascii
        $preg_replace = /preg_replace\s*\(\s*["']\/\.\*\/e["']\s*,/ wide ascii // preg_replace with /e modifier is often used for code execution
        $move_uploaded_file = "move_uploaded_file(" wide ascii
        $wp_nonce_field = "wp_nonce_field(" wide ascii
        $wp_verify_nonce = "wp_verify_nonce(" wide ascii
        $upload_dir = "wp_upload_dir(" wide ascii
        $current_user = "wp_get_current_user(" wide ascii
        $update_option = "update_option(" wide ascii
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
    condition:
        3 of them 
}
