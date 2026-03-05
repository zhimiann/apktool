# apk/apks/xapk/zip 四种格式的安装包安装包信息提取
提取信息如下：
 pkg_name_var.set(extract_result["包名"])
            ver_name_var.set(extract_result["游戏版本"])
            ver_code_var.set(str(extract_result["Version Code"]))
            arch_var.set(extract_result["架构"])
            sha1_var.set(extract_result["签名SHA1"])
            sha256_var.set(extract_result["签名SHA256"])
            md5_var.set(extract_result["签名MD5"])
            sig_files_var.set(extract_result["签名文件"])
            sig_verify_var.set(extract_result["签名验证"])
            cert_validity_var.set(extract_result["证书有效期"])
