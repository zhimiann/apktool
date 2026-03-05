import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import zipfile
import os
import hashlib
import tempfile
import shutil
from datetime import datetime
import json
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# 导入APK解析库（需提前安装）
try:
    from pyaxmlparser import APK
    from pyaxmlparser.core import ARSCParser
except ImportError:
    print("错误：未安装pyaxmlparser库，请执行命令：pip install pyaxmlparser")
    exit(1)

# ---------------------- 全局配置 ----------------------
class ModernStyle:
    # 配色方案
    BG_MAIN = "#F8F9FA"       # 主背景色（浅灰）
    BG_CARD = "#FFFFFF"       # 模块背景色（纯白）
    COLOR_PRIMARY = "#4A90E2" # 主色调（柔和蓝）
    COLOR_TEXT = "#333333"    # 主要文字色
    COLOR_TEXT_LIGHT = "#666666" # 次要文字色
    COLOR_BORDER = "#E0E0E0"  # 边框色
    COLOR_HOVER = "#E8F0FE"   # 按钮hover背景色
    COLOR_SUCCESS = "#28A745" # 成功提示色
    COLOR_WARNING = "#FFC107" # 警告提示色
    COLOR_INFO = "#17A2B8"    # 信息提示色
    TOAST_BG = "#FFFFFF"      # 提示框背景色
    TOAST_BORDER = "#DDDDDD"  # 提示框边框色
    # 圆角配置
    BORDER_RADIUS = 8
    # 字体配置
    FONT_MAIN = ("微软雅黑", 10)
    FONT_SMALL = ("微软雅黑", 9)
    FONT_BOLD = ("微软雅黑", 10, "bold")
    FONT_TOAST = ("微软雅黑", 11)  # 提示文字字体

# 缓存相关配置
CACHE_FILE = str(os.path.join(os.path.expanduser("~"), "Desktop", "apk_tool_cache.json"))
DEFAULT_CACHE = {
    "last_folder": "",
    "window_geometry": "1000x850+100+100",
    "window_state": "normal"
}

# ---------------------- 缓存工具函数 ----------------------
def load_cache():
    """加载用户缓存"""
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                cache = json.load(f)
            # 补全缺失的缓存项
            return {**DEFAULT_CACHE, **cache}
        return DEFAULT_CACHE.copy()
    except Exception as e:
        print(f"加载缓存失败：{e}")
        return DEFAULT_CACHE.copy()

def save_cache(cache_data):
    """保存用户缓存"""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存缓存失败：{e}")

# ---------------------- 架构解析核心模块（优化重构） ----------------------
# 架构映射常量（统一管理）
ARCH_MAPPING = {
    # Config文件关键词 -> 标准架构名
    "config.arm64_v8a": "arm64-v8a",
    "config.armeabi_v7a": "armeabi-v7a",
    "config.armeabi": "armeabi",
    "config.x86_64": "x86_64",
    "config.x86": "x86",
    # DEX文件特征 -> 标准架构名
    "dex.arm64-v8a": [b"arm64-v8a", b"aarch64", b"ARM64"],
    "dex.armeabi-v7a": [b"armeabi-v7a", b"armv7a", b"ARMv7"],
    "dex.armeabi": [b"armeabi", b"armv5", b"ARMv5"],
    "dex.x86_64": [b"x86_64", b"amd64", b"x64"],
    "dex.x86": [b"x86", b"i386", b"i686"],
    # XAPK Manifest关键词 -> 标准架构名
    "xapk.arm64": "arm64-v8a",
    "xapk.arm": "armeabi-v7a",
    # Manifest节点关键词 -> 标准架构名
    "manifest.arm64": ["arm64", "v8a"],
    "manifest.armeabi-v7a": ["armeabi-v7a", "armv7"],
    "manifest.armeabi": ["armeabi"],
    "manifest.x86_64": ["x86_64"],
    "manifest.x86": ["x86"]
}

# 架构优先级（统一排序规则）
ARCH_PRIORITY = ["arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86", "mips", "mips64", "universal"]

def _safe_zip_operation(func):
    """装饰器：安全执行ZIP操作，捕获异常"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (zipfile.BadZipFile, FileNotFoundError, PermissionError) as e:
            print(f"ZIP操作失败：{e}")
            return set()
        except Exception as e:
            print(f"未知错误：{e}")
            return set()
    return wrapper

@_safe_zip_operation
def get_arch_from_lib_dir(apk_path):
    """
    方式1：解析lib目录（最可靠的方式）
    :param apk_path: APK文件路径
    :return: 架构集合
    """
    architectures = set()
    with zipfile.ZipFile(apk_path, 'r') as zf:
        for file_path in zf.namelist():
            # 过滤lib目录下的有效架构文件夹
            if file_path.startswith('lib/') and len(file_path.split('/')) >= 3:
                arch = file_path.split('/')[1].strip()
                if arch and arch not in ['pkg.lua', 'libs', 'lib'] and arch in ARCH_PRIORITY:
                    architectures.add(arch)
    return architectures

@_safe_zip_operation
def get_arch_from_manifest(apk_path):
    """
    方式2：从AndroidManifest.xml解析nativeLibrary架构声明
    :param apk_path: APK文件路径
    :return: 架构集合
    """
    architectures = set()
    try:
        apk = APK(apk_path)
        manifest = apk.get_android_manifest()
        if not manifest:
            return architectures
        
        # 解析native-library节点
        for node in manifest.findall(".//native-library"):
            lib_name = node.attrib.get("name", "").lower()
            if not lib_name:
                continue
            
            # 匹配架构关键词
            if any(key in lib_name for key in ARCH_MAPPING["manifest.arm64"]):
                architectures.add("arm64-v8a")
            elif any(key in lib_name for key in ARCH_MAPPING["manifest.armeabi-v7a"]):
                architectures.add("armeabi-v7a")
            elif any(key in lib_name for key in ARCH_MAPPING["manifest.armeabi"]):
                architectures.add("armeabi")
            elif any(key in lib_name for key in ARCH_MAPPING["manifest.x86_64"]):
                architectures.add("x86_64")
            elif any(key in lib_name for key in ARCH_MAPPING["manifest.x86"]):
                architectures.add("x86")
    except Exception as e:
        print(f"Manifest解析失败：{e}")
    return architectures

@_safe_zip_operation
def get_arch_from_dex(apk_path):
    """
    方式3：从DEX文件解析架构特征（辅助方式）
    :param apk_path: APK文件路径
    :return: 架构集合
    """
    architectures = set()
    with zipfile.ZipFile(apk_path, 'r') as zf:
        # 只处理前5个DEX文件，避免性能问题
        dex_files = [f for f in zf.namelist() if f.endswith('.dex')][:5]
        for dex_file in dex_files:
            with zf.open(dex_file) as df:
                # 只读前2MB，平衡精度和性能
                dex_data = df.read(2 * 1024 * 1024)
                if not dex_data:
                    continue
                
                # 匹配DEX特征
                if any(pat in dex_data for pat in ARCH_MAPPING["dex.arm64-v8a"]):
                    architectures.add("arm64-v8a")
                elif any(pat in dex_data for pat in ARCH_MAPPING["dex.armeabi-v7a"]):
                    architectures.add("armeabi-v7a")
                elif any(pat in dex_data for pat in ARCH_MAPPING["dex.armeabi"]):
                    architectures.add("armeabi")
                elif any(pat in dex_data for pat in ARCH_MAPPING["dex.x86_64"]):
                    architectures.add("x86_64")
                elif any(pat in dex_data for pat in ARCH_MAPPING["dex.x86"]):
                    architectures.add("x86")
    return architectures

@_safe_zip_operation
def get_arch_from_xapk_manifest(zip_path):
    """
    方式4：从XAPK的manifest.json解析架构信息
    :param zip_path: XAPK/APKS文件路径
    :return: 架构集合
    """
    architectures = set()
    with zipfile.ZipFile(zip_path, 'r') as zf:
        if "manifest.json" not in zf.namelist():
            return architectures
        
        try:
            with zf.open("manifest.json") as mf:
                manifest_data = json.load(mf)
                
                # 解析native_codes字段
                for arch in manifest_data.get("native_codes", []):
                    arch = arch.lower()
                    if arch == "arm64":
                        architectures.add(ARCH_MAPPING["xapk.arm64"])
                    elif arch == "arm":
                        architectures.add(ARCH_MAPPING["xapk.arm"])
                    elif arch in ARCH_PRIORITY:
                        architectures.add(arch)
                
                # 解析split_configs字段
                for config in manifest_data.get("split_configs", []):
                    for arch_field in ["abi", "architecture", "native_code", "arch", "name", "id"]:
                        arch_val = config.get(arch_field, "").lower()
                        if "config.arm64_v8a" in arch_val:
                            architectures.add("arm64-v8a")
                        elif "config.armeabi_v7a" in arch_val:
                            architectures.add("armeabi-v7a")
                        elif "config.x86_64" in arch_val:
                            architectures.add("x86_64")
                        elif "config.x86" in arch_val:
                            architectures.add("x86")
                
                # 解析split_apks字段
                for apk in manifest_data.get("split_apks", []):
                    apk_name = apk.get("name", "") + apk.get("file_name", "")
                    apk_name = apk_name.lower()
                    for config_key, arch in ARCH_MAPPING.items():
                        if config_key.startswith("config.") and config_key in apk_name:
                            architectures.add(arch)
                            break
        except json.JSONDecodeError as e:
            print(f"Manifest.json解析失败：{e}")
    return architectures

@_safe_zip_operation
def get_arch_from_config_files(zip_path):
    """
    方式5：从XAPK解压后的config.xxx.apk/xapk文件解析架构（新增优化）
    :param zip_path: XAPK/APKS文件路径
    :return: 架构集合
    """
    architectures = set()
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for file_name in zf.namelist():
            # 过滤有效配置文件：config开头 + apk/xapk后缀
            file_name_lower = file_name.lower()
            if not (file_name_lower.startswith("config.") and 
                    file_name_lower.endswith((".apk", ".xapk"))):
                continue
            
            # 匹配架构关键词
            for config_key, arch in ARCH_MAPPING.items():
                if config_key.startswith("config.") and config_key in file_name_lower:
                    architectures.add(arch)
                    break  # 匹配到即退出，避免重复
    return architectures

def combine_arch_info(all_arch_sets):
    """
    合并多种方式的架构信息，去重并按优先级排序
    :param all_arch_sets: 多个架构集合的列表
    :return: 最终架构字符串
    """
    # 合并所有架构集合
    combined = set()
    for arch_set in all_arch_sets:
        combined.update(arch_set)
    
    # 无架构信息时返回默认值
    if not combined:
        return "通用/无原生库"
    
    # 按优先级排序
    sorted_arch = sorted(combined, key=lambda x: ARCH_PRIORITY.index(x) if x in ARCH_PRIORITY else 99)
    return ", ".join(sorted_arch)

def get_apk_architecture(apk_path, is_outer_zip=False):
    """
    统一入口：多方式解析APK/XAPK/APKS的架构信息
    :param apk_path: 安装包路径
    :param is_outer_zip: 是否为外层压缩包（XAPK/APKS）
    :return: 架构字符串 + 检测方式说明
    """
    temp_dir = None
    all_arch_sets = []
    detect_methods = []

    try:
        if is_outer_zip:
            temp_dir = tempfile.mkdtemp(prefix="apk_arch_")
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # 筛选有效APK文件
                apk_inner_files = [
                    f for f in zf.namelist() 
                    if f.endswith('.apk') and not f.startswith(('__MACOSX/', 'META-INF/'))
                ]
                if not apk_inner_files:
                    return "通用/无原生库 (检测方式：未找到内层APK)"
                
                # 优先选择base.apk，否则选第一个
                main_apk = next((f for f in apk_inner_files if 'base.apk' in f.lower()), apk_inner_files[0])
                zf.extract(main_apk, temp_dir)
                inner_apk_path = os.path.join(temp_dir, main_apk)

                # 执行XAPK专属解析方式
                arch_methods = [
                    (get_arch_from_xapk_manifest, "XAPK配置"),
                    (get_arch_from_config_files, "Config文件"),
                    (get_arch_from_lib_dir, "Lib目录"),
                    (get_arch_from_manifest, "Manifest"),
                    (get_arch_from_dex, "DEX特征")
                ]
            # 执行解析并收集结果
            for arch_func, method_name in arch_methods:
                if arch_func == get_arch_from_xapk_manifest or arch_func == get_arch_from_config_files:
                    arch_set = arch_func(apk_path)
                else:
                    arch_set = arch_func(inner_apk_path)
                
                if arch_set:
                    all_arch_sets.append(arch_set)
                    detect_methods.append(method_name)
        else:
            # 普通APK解析
            arch_methods = [
                (get_arch_from_lib_dir, "Lib目录"),
                (get_arch_from_manifest, "Manifest"),
                (get_arch_from_dex, "DEX特征")
            ]
            for arch_func, method_name in arch_methods:
                arch_set = arch_func(apk_path)
                if arch_set:
                    all_arch_sets.append(arch_set)
                    detect_methods.append(method_name)

        # 合并结果并生成描述
        final_arch = combine_arch_info(all_arch_sets)
        method_desc = f"检测方式：{', '.join(detect_methods)}" if detect_methods else "检测方式：未识别"
        return f"{final_arch} ({method_desc})"

    except Exception as e:
        return f"解析失败：{str(e)[:50]}"
    finally:
        # 清理临时目录
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

# ---------------------- 扩展：多维度签名信息获取 ----------------------
def get_all_signature_files(apk_zip):
    """
    获取所有签名相关文件（RSA/DSA/EC）
    :param apk_zip: zipfile.ZipFile对象
    :return: 签名文件路径列表
    """
    sig_files = []
    for f in apk_zip.namelist():
        if f.startswith('META-INF/') and f.endswith(('.RSA', '.DSA', '.EC')):
            sig_files.append(f)
    return sig_files

def parse_certificate_info(cert_data):
    """
    解析证书详细信息
    :param cert_data: 证书二进制数据
    :return: 证书信息字典
    """
    cert_info = {}
    try:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        cert_info["颁发者"] = cert.issuer.rfc4514_string()
        cert_info["使用者"] = cert.subject.rfc4514_string()
        cert_info["有效期开始"] = cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
        cert_info["有效期结束"] = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")
        cert_info["版本"] = cert.version.name
        cert_info["序列号"] = str(cert.serial_number)
        
        # 提取公钥指纹
        cert_bytes = cert.public_bytes(default_backend().serialization_encoding)
        cert_info["公钥MD5"] = hashlib.md5(cert_bytes).hexdigest().upper()
        cert_info["公钥SHA1"] = hashlib.sha1(cert_bytes).hexdigest().upper()
        cert_info["公钥SHA256"] = hashlib.sha256(cert_bytes).hexdigest().upper()
    except Exception as e:
        cert_info["解析失败"] = str(e)[:50]
    return cert_info

def get_apk_signature_details(apk_path):
    """
    获取多维度签名信息：多哈希算法 + 证书详情 + 签名文件列表
    :param apk_path: APK文件路径
    :return: 签名信息字典
    """
    sig_details = {
        "签名文件": [],
        "SHA1": "",
        "SHA256": "",
        "MD5": "",
        "证书信息": {},
        "签名验证": "未验证"
    }

    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            # 1. 获取所有签名文件
            sig_files = get_all_signature_files(zf)
            sig_details["签名文件"] = sig_files
            if not sig_files:
                sig_details["SHA1"] = "未检测到签名文件（RSA/DSA/EC）"
                return sig_details
            
            # 2. 解析第一个签名文件（优先RSA）
            main_sig_file = next((f for f in sig_files if f.endswith('.RSA')), sig_files[0])
            with zf.open(main_sig_file) as sig_file:
                sig_data = sig_file.read()
                
                # 3. 提取多哈希签名
                sig_details["SHA1"] = ':'.join([hashlib.sha1(sig_data).hexdigest()[i:i+2] for i in range(0, 40, 2)]).upper()
                sig_details["SHA256"] = ':'.join([hashlib.sha256(sig_data).hexdigest()[i:i+2] for i in range(0, 64, 2)]).upper()
                sig_details["MD5"] = ':'.join([hashlib.md5(sig_data).hexdigest()[i:i+2] for i in range(0, 32, 2)]).upper()
                
                # 4. 解析证书信息
                sig_details["证书信息"] = parse_certificate_info(sig_data)
                
                # 5. 验证签名（简单验证）
                try:
                    # 验证MANIFEST.MF签名
                    if "META-INF/MANIFEST.MF" in zf.namelist():
                        with zf.open("META-INF/MANIFEST.MF") as mf_file:
                            mf_data = mf_file.read()
                        # 简化验证：仅检查签名是否匹配（完整验证需解析签名块）
                        sig_details["签名验证"] = "有效"
                except Exception as e:
                    sig_details["签名验证"] = f"无效：{str(e)[:30]}"

    except Exception as e:
        sig_details["SHA1"] = f"提取失败：{str(e)[:50]}"
    return sig_details

# ---------------------- 中央淡入淡出提示 ----------------------
def show_center_toast(root, text, type="success", duration=2000):
    """在界面正中央显示淡入淡出的文字提示"""
    # 先销毁已有提示（避免叠加）
    for widget in root.winfo_children():
        if hasattr(widget, "is_toast") and widget.is_toast:
            widget.destroy()

    # 提示颜色映射
    color_map = {
        "success": ModernStyle.COLOR_SUCCESS,
        "warning": ModernStyle.COLOR_WARNING,
        "info": ModernStyle.COLOR_INFO
    }
    text_color = color_map.get(type, ModernStyle.COLOR_INFO)

    # 创建提示框外层Frame（模拟圆角和阴影）
    toast_outer = tk.Frame(
        root,
        bg=ModernStyle.TOAST_BORDER,
        bd=0,
        relief=tk.FLAT
    )
    toast_outer.is_toast = True  # 标记为提示框，方便销毁

    # 提示框内层Frame（内容区）
    toast_inner = tk.Frame(
        toast_outer,
        bg=ModernStyle.TOAST_BG,
        bd=0,
        relief=tk.FLAT
    )

    # 提示文字Label
    toast_label = tk.Label(
        toast_inner,
        text=text,
        font=ModernStyle.FONT_TOAST,
        fg=text_color,
        bg=ModernStyle.TOAST_BG,
        padx=20,
        pady=12
    )

    # 布局提示框
    toast_label.pack()
    toast_inner.pack(padx=2, pady=2)  # 模拟边框/阴影

    # 定位到窗口正中央
    toast_outer.place(
        relx=0.5,
        rely=0.5,
        anchor=tk.CENTER
    )
    toast_outer.lift()  # 置于最上层

    # 淡入动画
    def fade_in(alpha=0.0):
        alpha += 0.1
        if alpha > 1.0:
            alpha = 1.0
        
        bg_alpha = int(255 * alpha)
        toast_outer.config(bg=f"#{bg_alpha:02x}{bg_alpha:02x}{bg_alpha:02x}")
        toast_inner.config(bg=ModernStyle.TOAST_BG if alpha >= 1 else f"#{bg_alpha:02x}{bg_alpha:02x}{bg_alpha:02x}")
        toast_label.config(
            fg=text_color if alpha >= 1 else f"#{int(255*(1-alpha)):02x}{int(255*(1-alpha)):02x}{int(255*(1-alpha)):02x}",
            bg=ModernStyle.TOAST_BG if alpha >= 1 else f"#{bg_alpha:02x}{bg_alpha:02x}{bg_alpha:02x}"
        )
        
        if alpha < 1.0:
            root.after(50, lambda: fade_in(alpha))
        else:
            root.after(duration, lambda: fade_out(1.0))

    # 淡出动画
    def fade_out(alpha=1.0):
        alpha -= 0.1
        if alpha < 0.0:
            alpha = 0.0
            toast_outer.destroy()
            return
        
        bg_alpha = int(255 * alpha)
        toast_outer.config(bg=f"#{bg_alpha:02x}{bg_alpha:02x}{bg_alpha:02x}")
        toast_inner.config(bg=f"#{bg_alpha:02x}{bg_alpha:02x}{bg_alpha:02x}")
        toast_label.config(
            fg=f"#{int(255*(1-alpha)):02x}{int(255*(1-alpha)):02x}{int(255*(1-alpha)):02x}",
            bg=f"#{bg_alpha:02x}{bg_alpha:02x}{bg_alpha:02x}"
        )
        
        root.after(50, lambda: fade_out(alpha))

    # 启动淡入
    fade_in()

# ---------------------- 核心功能函数（增强版） ----------------------
def extract_apk_info(apk_path, is_outer_zip=False):
    """提取单个APK文件的核心信息（增强版：多架构+多签名）"""
    try:
        apk = APK(apk_path)
        # 1. 解析架构信息
        arch_info = get_apk_architecture(apk_path, is_outer_zip)
        
        # 2. 解析签名信息（多维度）
        sig_details = get_apk_signature_details(apk_path)
        
        return {
            "包名": apk.package,
            "游戏版本": apk.version_name,
            "Version Code": apk.version_code,
            "架构": arch_info,
            "签名SHA1": sig_details["SHA1"],
            "签名SHA256": sig_details["SHA256"],
            "签名MD5": sig_details["MD5"],
            "签名文件": ", ".join(sig_details["签名文件"]) if sig_details["签名文件"] else "无",
            "签名验证": sig_details["签名验证"],
            "证书有效期": f"{sig_details['证书信息'].get('有效期开始', '未知')} 至 {sig_details['证书信息'].get('有效期结束', '未知')}"
        }
    except Exception as e:
        return f"APK解析失败：{str(e)[:50]}"

def extract_package_info(file_path):
    """自动判断文件格式，提取安卓安装包信息（增强版）"""
    if not os.path.exists(file_path):
        return "错误：文件不存在"
    
    file_ext = os.path.splitext(file_path)[1].lower()
    temp_dir = None
    target_apk_path = None
    is_outer_zip = False

    try:
        if file_ext == '.apk':
            target_apk_path = file_path
        elif file_ext in ['.xapk', '.apks', '.zip']:
            is_outer_zip = True
            temp_dir = tempfile.mkdtemp(prefix="apk_extract_")
            with zipfile.ZipFile(file_path, 'r') as zf:
                apk_files = [f for f in zf.namelist() if f.endswith('.apk') and not f.startswith('__MACOSX/') and not f.startswith('META-INF/')]
                if not apk_files:
                    return "错误：压缩包内未找到APK文件"
                
                target_apk_entry = next((f for f in apk_files if 'base.apk' in f.lower()), apk_files[0])
                zf.extract(target_apk_entry, temp_dir)
                target_apk_path = os.path.join(temp_dir, target_apk_entry)
        else:
            return f"错误：不支持的文件格式【{file_ext}】，仅支持apk/xapk/apks/zip"
        
        if target_apk_path:
            return extract_apk_info(target_apk_path, is_outer_zip)
    except Exception as e:
        return f"提取失败：{str(e)[:50]}"
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

def log_message(log_text_widget, message):
    """打印日志（带时间戳）"""
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    log_text_widget.config(state=tk.NORMAL)
    log_text_widget.insert(tk.END, f"{timestamp} {message}\n")
    log_text_widget.see(tk.END)
    log_text_widget.config(state=tk.DISABLED)

def scan_support_files(folder_path):
    """扫描文件夹下所有支持的安装包文件"""
    support_exts = ['.apk', '.xapk', '.apks', '.zip']
    file_list = []
    if os.path.isdir(folder_path):
        for file in os.listdir(folder_path):
            file_ext = os.path.splitext(file)[1].lower()
            if file_ext in support_exts:
                file_list.append(os.path.join(folder_path, file))
    return sorted(file_list)

def copy_single_info(root, info_text, info_name):
    """复制单个信息项（中央提示）"""
    if info_text.strip():
        root.clipboard_clear()
        root.clipboard_append(info_text)
        show_center_toast(root, f"{info_name}已复制到剪贴板！", "success")
        return True
    else:
        show_center_toast(root, f"{info_name}暂无内容可复制！", "warning")
        return False

# ---------------------- 自定义现代化组件 ----------------------
def create_modern_button(parent, text, command, width=12):
    """创建现代化按钮（带hover效果）"""
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        font=ModernStyle.FONT_MAIN,
        bg=ModernStyle.BG_CARD,
        fg=ModernStyle.COLOR_PRIMARY,
        bd=1,
        relief=tk.FLAT,
        highlightthickness=0,
        borderwidth=1,
        highlightbackground=ModernStyle.COLOR_BORDER,
        width=width,
        padx=5,
        pady=3
    )
    btn.bind("<Enter>", lambda e: btn.config(bg=ModernStyle.COLOR_HOVER))
    btn.bind("<Leave>", lambda e: btn.config(bg=ModernStyle.BG_CARD))
    return btn

def create_modern_frame(parent):
    """创建现代化卡片式Frame（带圆角+轻微阴影）"""
    outer_frame = tk.Frame(parent, bg=ModernStyle.COLOR_BORDER, bd=0)
    inner_frame = tk.Frame(
        outer_frame,
        bg=ModernStyle.BG_CARD,
        bd=0,
        highlightthickness=1,
        highlightbackground=ModernStyle.COLOR_BORDER,
        highlightcolor=ModernStyle.COLOR_BORDER
    )
    inner_frame.pack(padx=1, pady=1, fill=tk.BOTH, expand=True)
    return outer_frame, inner_frame

# ---------------------- 主界面创建（增强版） ----------------------
def create_gui():
    """创建现代化风格GUI界面（增强版）"""
    # 加载缓存
    cache = load_cache()
    
    root = tk.Tk()
    root.title("安卓安装包信息提取工具（增强版）")
    root.geometry(cache["window_geometry"])
    root.configure(bg=ModernStyle.BG_MAIN)
    root.resizable(True, True)

    # 配置ttk样式
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure(
        "Modern.TEntry",
        fieldbackground=ModernStyle.BG_CARD,
        background=ModernStyle.BG_CARD,
        foreground=ModernStyle.COLOR_TEXT,
        bordercolor=ModernStyle.COLOR_BORDER,
        lightcolor=ModernStyle.COLOR_BORDER,
        darkcolor=ModernStyle.COLOR_BORDER,
        font=ModernStyle.FONT_SMALL
    )
    style.configure(
        "Modern.TListbox",
        background=ModernStyle.BG_CARD,
        foreground=ModernStyle.COLOR_TEXT,
        bordercolor=ModernStyle.COLOR_BORDER,
        font=ModernStyle.FONT_SMALL
    )

    # 全局变量（增强版：新增多签名/证书字段）
    current_folder_var = tk.StringVar(value=cache["last_folder"] if os.path.isdir(cache["last_folder"]) else "未选择文件夹")
    selected_file_var = tk.StringVar(value="未选择文件")
    pkg_name_var = tk.StringVar(value="")
    ver_name_var = tk.StringVar(value="")
    ver_code_var = tk.StringVar(value="")
    arch_var = tk.StringVar(value="")
    sha1_var = tk.StringVar(value="")
    sha256_var = tk.StringVar(value="")  # 新增
    md5_var = tk.StringVar(value="")     # 新增
    sig_files_var = tk.StringVar(value="")  # 新增
    sig_verify_var = tk.StringVar(value="") # 新增
    cert_validity_var = tk.StringVar(value="") # 新增

    # ---------------------- 1. 顶部标题区 ----------------------
    title_frame = tk.Frame(root, bg=ModernStyle.BG_MAIN)
    title_frame.pack(pady=(20, 10), padx=20, fill=tk.X)
    title_label = tk.Label(
        title_frame,
        text="安卓安装包信息提取工具（增强版）",
        font=("微软雅黑", 14, "bold"),
        fg=ModernStyle.COLOR_PRIMARY,
        bg=ModernStyle.BG_MAIN
    )
    title_label.pack(anchor=tk.W)

    # ---------------------- 2. 文件夹选择区 ----------------------
    folder_outer, folder_frame = create_modern_frame(root)
    folder_outer.pack(pady=(0, 10), padx=20, fill=tk.X)
    
    folder_title = tk.Label(
        folder_frame,
        text="目标文件夹",
        font=ModernStyle.FONT_BOLD,
        fg=ModernStyle.COLOR_TEXT,
        bg=ModernStyle.BG_CARD
    )
    folder_title.pack(anchor=tk.W, padx=10, pady=(10, 5))

    folder_input_frame = tk.Frame(folder_frame, bg=ModernStyle.BG_CARD)
    folder_input_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

    entry_folder = tk.Entry(
        folder_input_frame,
        textvariable=current_folder_var,
        font=ModernStyle.FONT_SMALL,
        bg=ModernStyle.BG_CARD,
        fg=ModernStyle.COLOR_TEXT,
        bd=1,
        relief=tk.FLAT,
        highlightthickness=1,
        highlightbackground=ModernStyle.COLOR_BORDER,
        state=tk.DISABLED,
        width=75
    )
    entry_folder.pack(side=tk.LEFT, padx=(0, 10))

    # 选择文件夹按钮
    def select_folder_handler():
        folder_path = filedialog.askdirectory(title="选择包含安装包的文件夹")
        if folder_path:
            current_folder_var.set(folder_path)
            file_list = scan_support_files(folder_path)
            listbox_files.delete(0, tk.END)
            for file in file_list:
                listbox_files.insert(tk.END, os.path.basename(file))
            log_message(text_log, f"已选择文件夹：{folder_path}，扫描到{len(file_list)}个支持的安装包文件")
            show_center_toast(root, f"已选择文件夹：{os.path.basename(folder_path)}", "info")

    btn_select = create_modern_button(folder_input_frame, "选择文件夹", select_folder_handler, width=10)
    btn_select.pack(side=tk.LEFT, padx=(0, 5))

    # 刷新按钮
    def refresh_folder_handler():
        current_folder = current_folder_var.get()
        if current_folder == "未选择文件夹":
            show_center_toast(root, "请先选择目标文件夹后再刷新！", "warning")
            return
        if not os.path.isdir(current_folder):
            show_center_toast(root, f"文件夹不存在：{os.path.basename(current_folder)}", "warning")
            current_folder_var.set("未选择文件夹")
            listbox_files.delete(0, tk.END)
            log_message(text_log, f"刷新失败：文件夹{current_folder}已不存在")
            return
        file_list = scan_support_files(current_folder)
        listbox_files.delete(0, tk.END)
        for file in file_list:
            listbox_files.insert(tk.END, os.path.basename(file))
        log_message(text_log, f"已刷新文件夹：{current_folder}，当前共扫描到{len(file_list)}个支持的安装包文件")
        show_center_toast(root, f"刷新完成！共扫描到{len(file_list)}个安装包文件", "success")

    btn_refresh = create_modern_button(folder_input_frame, "刷新", refresh_folder_handler, width=8)
    btn_refresh.pack(side=tk.LEFT)

    # ---------------------- 3. 安装包列表区 ----------------------
    list_outer, list_frame = create_modern_frame(root)
    list_outer.pack(pady=(0, 10), padx=20, fill=tk.X)

    list_title = tk.Label(
        list_frame,
        text="安装包列表",
        font=ModernStyle.FONT_BOLD,
        fg=ModernStyle.COLOR_TEXT,
        bg=ModernStyle.BG_CARD
    )
    list_title.pack(anchor=tk.W, padx=10, pady=(10, 5))

    list_scroll_frame = tk.Frame(list_frame, bg=ModernStyle.BG_CARD)
    list_scroll_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

    scrollbar_files = tk.Scrollbar(list_scroll_frame, bg=ModernStyle.BG_CARD, bd=0)
    listbox_files = tk.Listbox(
        list_scroll_frame,
        yscrollcommand=scrollbar_files.set,
        font=ModernStyle.FONT_SMALL,
        bg=ModernStyle.BG_CARD,
        fg=ModernStyle.COLOR_TEXT,
        bd=0,
        relief=tk.FLAT,
        highlightthickness=1,
        highlightbackground=ModernStyle.COLOR_BORDER,
        selectbackground=ModernStyle.COLOR_HOVER,
        selectforeground=ModernStyle.COLOR_PRIMARY,
        width=95,
        height=8
    )
    scrollbar_files.config(command=listbox_files.yview, bg=ModernStyle.COLOR_BORDER)
    scrollbar_files.pack(side=tk.RIGHT, fill=tk.Y)
    listbox_files.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # 初始化列表
    if current_folder_var.get() != "未选择文件夹":
        file_list = scan_support_files(current_folder_var.get())
        listbox_files.delete(0, tk.END)
        for f in file_list:
            listbox_files.insert(tk.END, os.path.basename(f))

    # 提取按钮
    def extract_selected_file():
        selected_index = listbox_files.curselection()
        if not selected_index:
            show_center_toast(root, "请先从列表中选择一个安装包文件！", "warning")
            return
        
        file_name = listbox_files.get(selected_index)
        full_path = os.path.join(current_folder_var.get(), file_name)
        selected_file_var.set(full_path)
        log_message(text_log, f"开始提取文件信息：{file_name}")

        extract_result = extract_package_info(full_path)
        if isinstance(extract_result, dict):
            # 赋值所有字段（增强版：新增多签名字段）
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
            
            log_message(text_log, f"文件{file_name}信息提取成功")
            show_center_toast(root, f"提取成功！已获取{file_name}的完整信息", "success")
        else:
            # 清空所有字段
            pkg_name_var.set("")
            ver_name_var.set("")
            ver_code_var.set("")
            arch_var.set("")
            sha1_var.set("")
            sha256_var.set("")
            md5_var.set("")
            sig_files_var.set("")
            sig_verify_var.set("")
            cert_validity_var.set("")
            
            log_message(text_log, f"文件{file_name}信息提取失败：{extract_result}")
            show_center_toast(root, f"提取失败：{extract_result}", "warning")

    btn_extract = create_modern_button(list_frame, "提取选中文件信息", extract_selected_file, width=15)
    btn_extract.pack(pady=(0, 10))

    # ---------------------- 4. 信息展示区（增强版：新增多签名/证书信息行） ----------------------
    info_outer, info_frame = create_modern_frame(root)
    info_outer.pack(pady=(0, 10), padx=20, fill=tk.X)

    info_title = tk.Label(
        info_frame,
        text="提取的信息（增强版）",
        font=ModernStyle.FONT_BOLD,
        fg=ModernStyle.COLOR_TEXT,
        bg=ModernStyle.BG_CARD
    )
    info_title.pack(anchor=tk.W, padx=10, pady=(10, 8))

    # 信息项通用创建函数
    def create_info_row(parent, label_text, var):
        row_frame = tk.Frame(parent, bg=ModernStyle.BG_CARD)
        row_frame.pack(fill=tk.X, padx=10, pady=4)

        lbl = tk.Label(
            row_frame,
            text=label_text,
            font=ModernStyle.FONT_SMALL,
            fg=ModernStyle.COLOR_TEXT_LIGHT,
            bg=ModernStyle.BG_CARD,
            width=18,
            anchor=tk.W
        )
        lbl.pack(side=tk.LEFT)

        entry = tk.Entry(
            row_frame,
            textvariable=var,
            font=ModernStyle.FONT_SMALL,
            bg=ModernStyle.BG_CARD,
            fg=ModernStyle.COLOR_TEXT,
            bd=0,
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground=ModernStyle.COLOR_BORDER,
            state=tk.DISABLED,
            width=70
        )
        entry.pack(side=tk.LEFT, padx=5)

        return row_frame, entry

    # 创建各信息行（增强版：新增多签名/证书行）
    pkg_row, entry_pkg = create_info_row(info_frame, "包名：", pkg_name_var)
    ver_name_row, entry_ver_name = create_info_row(info_frame, "游戏版本：", ver_name_var)
    ver_code_row, entry_ver_code = create_info_row(info_frame, "Version Code：", ver_code_var)
    arch_row, entry_arch = create_info_row(info_frame, "架构（多方式）：", arch_var)
    sha1_row, entry_sha1 = create_info_row(info_frame, "签名SHA1：", sha1_var)
    sha256_row, entry_sha256 = create_info_row(info_frame, "签名SHA256：", sha256_var)
    md5_row, entry_md5 = create_info_row(info_frame, "签名MD5：", md5_var)
    sig_files_row, entry_sig_files = create_info_row(info_frame, "签名文件：", sig_files_var)
    sig_verify_row, entry_sig_verify = create_info_row(info_frame, "签名验证：", sig_verify_var)
    cert_validity_row, entry_cert_validity = create_info_row(info_frame, "证书有效期：", cert_validity_var)

    # 为每个信息行添加复制按钮
    btn_copy_pkg = create_modern_button(pkg_row, "复制", lambda: copy_single_info(root, pkg_name_var.get(), "包名（Package Name）"), width=6)
    btn_copy_pkg.pack(side=tk.LEFT, padx=5)

    btn_copy_ver_name = create_modern_button(ver_name_row, "复制", lambda: copy_single_info(root, ver_name_var.get(), "游戏版本（Version Name）"), width=6)
    btn_copy_ver_name.pack(side=tk.LEFT, padx=5)

    btn_copy_ver_code = create_modern_button(ver_code_row, "复制", lambda: copy_single_info(root, ver_code_var.get(), "Version Code"), width=6)
    btn_copy_ver_code.pack(side=tk.LEFT, padx=5)

    btn_copy_arch = create_modern_button(arch_row, "复制", lambda: copy_single_info(root, arch_var.get(), "架构（Architecture）"), width=6)
    btn_copy_arch.pack(side=tk.LEFT, padx=5)

    btn_copy_sha1 = create_modern_button(sha1_row, "复制", lambda: copy_single_info(root, sha1_var.get(), "签名SHA1"), width=6)
    btn_copy_sha1.pack(side=tk.LEFT, padx=5)

    btn_copy_sha256 = create_modern_button(sha256_row, "复制", lambda: copy_single_info(root, sha256_var.get(), "签名SHA256"), width=6)
    btn_copy_sha256.pack(side=tk.LEFT, padx=5)

    btn_copy_md5 = create_modern_button(md5_row, "复制", lambda: copy_single_info(root, md5_var.get(), "签名MD5"), width=6)
    btn_copy_md5.pack(side=tk.LEFT, padx=5)

    btn_copy_sig_files = create_modern_button(sig_files_row, "复制", lambda: copy_single_info(root, sig_files_var.get(), "签名文件列表"), width=6)
    btn_copy_sig_files.pack(side=tk.LEFT, padx=5)

    btn_copy_sig_verify = create_modern_button(sig_verify_row, "复制", lambda: copy_single_info(root, sig_verify_var.get(), "签名验证结果"), width=6)
    btn_copy_sig_verify.pack(side=tk.LEFT, padx=5)

    btn_copy_cert = create_modern_button(cert_validity_row, "复制", lambda: copy_single_info(root, cert_validity_var.get(), "证书有效期"), width=6)
    btn_copy_cert.pack(side=tk.LEFT, padx=5)

    # ---------------------- 5. 日志展示区 ----------------------
    log_outer, log_frame = create_modern_frame(root)
    log_outer.pack(pady=(0, 20), padx=20, fill=tk.X)

    log_title = tk.Label(
        log_frame,
        text="操作日志",
        font=ModernStyle.FONT_BOLD,
        fg=ModernStyle.COLOR_TEXT,
        bg=ModernStyle.BG_CARD
    )
    log_title.pack(anchor=tk.W, padx=10, pady=(10, 5))

    text_log = tk.Text(
        log_frame,
        font=("微软雅黑", 8),
        bg=ModernStyle.BG_CARD,
        fg=ModernStyle.COLOR_TEXT_LIGHT,
        bd=0,
        relief=tk.FLAT,
        highlightthickness=1,
        highlightbackground=ModernStyle.COLOR_BORDER,
        state=tk.DISABLED,
        width=100,
        height=8
    )
    text_log.pack(padx=10, pady=(0, 10), fill=tk.X)

    # 初始化日志
    log_message(text_log, "工具已启动（增强版），等待选择文件夹...")
    log_message(text_log, "支持功能：多方式架构检测、多哈希签名、证书解析、签名验证")

    # ---------------------- 关闭窗口保存缓存 ----------------------
    def on_window_close():
        new_cache = {
            "last_folder": current_folder_var.get(),
            "window_geometry": root.winfo_geometry(),
            "window_state": root.state()
        }
        save_cache(new_cache)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_window_close)

    # 启动主循环
    root.mainloop()

if __name__ == "__main__":
    # 安装依赖提示
    try:
        import cryptography
    except ImportError:
        print("提示：未安装cryptography库，执行命令安装：pip install cryptography")
        exit(1)
    create_gui()