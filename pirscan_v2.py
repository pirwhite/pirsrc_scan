#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pirsrc_scan 6.2 - 高级木马扫描工具
# 融合了核心功能和扩展模块，支持自动导出CSV和病毒特征管理
# 基于Python 3.10，保持跨平台兼容性

import os
import sys
import re
import json
import csv
import time
import hashlib
import shutil
import zipfile
import random
import datetime
import subprocess
import glob
from typing import List, Dict, Tuple, Optional, Any, Set
import ipaddress

# 尝试导入psutil库，如未安装则尝试自动安装
try:
    import psutil
except ImportError:
    try:
        print("正在安装必要的依赖库psutil...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "psutil"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        import psutil
    except Exception:
        print("无法安装psutil库，部分功能将受限")
        psutil = None

# 常量定义
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
TEMP_DIR = os.path.join(BASE_DIR, "temp")
SIGNATURES_DIR = os.path.join(BASE_DIR, "signatures")

# 确保目录存在
for dir_path in [REPORTS_DIR, SAMPLES_DIR, QUARANTINE_DIR, TEMP_DIR, SIGNATURES_DIR]:
    os.makedirs(dir_path, exist_ok=True)

# 系统检测
IS_WINDOWS = sys.platform.startswith('win')
IS_LINUX = sys.platform.startswith('linux')
IS_MACOS = sys.platform.startswith('darwin')

# 颜色控制类
class Color:
    """终端颜色控制类"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    REVERSE = '\033[7m'
    
    # 文本颜色
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    @staticmethod
    def support_color() -> bool:
        """检查终端是否支持颜色"""
        if not sys.stdout.isatty():
            return False
        try:
            import curses
            curses.setupterm()
            return curses.tigetnum('colors') > 2
        except:
            return False

# ASCII艺术图标
HACKER_ICON_ASCII = """
                      .---.        .-----------
                     /     \  __  /    ------
                    / /     \(  )/    -----
                   //////   ' \/ `   ---
                  //// / // :    : ---
                 // /   /  /`    '--
                //          //..\\
                     ====UU====UU====
                         '//||\\`
                           ''``
"""

# 常见合法进程列表
COMMON_LEGIT_PROCESSES = [
    # Windows系统进程
    "system", "svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe",
    "lsass.exe", "services.exe", "taskmgr.exe", "dwm.exe", "conhost.exe",
    "rundll32.exe", "taskhostw.exe", "searchindexer.exe", "ctfmon.exe",
    
    # 浏览器进程
    "chrome.exe", "firefox.exe", "iexplore.exe", "edge.exe", "safari.exe",
    "opera.exe", "brave.exe", "chromium.exe",
    
    # 办公软件
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "wps.exe",
    "et.exe", "wpp.exe",
    
    # 开发工具
    "code.exe", "pycharm.exe", "idea.exe", "visualstudio.exe", "git.exe",
    
    # Linux进程
    "systemd", "bash", "zsh", "sh", "gnome-shell", "kdeinit5", "Xorg",
    "sshd", "sudo", "su", "apt", "yum", "dnf",
    
    # macOS进程
    "launchd", "WindowServer", "coreaudiod", "syslogd", "securityd",
    "cfprefsd", "mds", "finder"
]

# 中国IP地址段（简化版）
CHINA_IP_RANGES = [
    "1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "1.0.32.0/19",
    "1.1.0.0/24", "1.1.2.0/23", "1.1.4.0/22", "1.1.8.0/21",
    "1.1.16.0/20", "1.1.32.0/19", "1.2.0.0/23", "1.2.2.0/24",
    "223.255.252.0/22"
]

# 威胁情报中心配置
THREAT_INTEL_CONFIG = {
    "virustotal": {
        "name": "VirusTotal",
        "enabled": False,
        "api_key": "",
        "api_url": "https://www.virustotal.com/vtapi/v2/file/report",
        "upload_url": "https://www.virustotal.com/vtapi/v2/file/scan"
    },
    "threatbook": {
        "name": "微步在线",
        "enabled": False,
        "api_key": "",
        "api_url": "https://s.threatbook.cn/api/v3/file/report",
        "upload_url": "https://s.threatbook.cn/api/v3/file/upload"
    },
    "qianxin": {
        "name": "奇安信",
        "enabled": False,
        "api_key": "",
        "api_url": "https://ti.qianxin.com/v2/file/report",
        "upload_url": "https://ti.qianxin.com/v2/file/upload"
    },
    "nsfocus": {
        "name": "绿盟",
        "enabled": False,
        "api_key": "",
        "api_url": "https://ti.nsfocus.com/v2/file/report",
        "upload_url": "https://ti.nsfocus.com/v2/file/upload"
    }
}

# -------------------------- 病毒特征类 --------------------------
class VirusSignature:
    """病毒特征类，存储恶意软件的特征信息"""
    
    def __init__(
        self,
        signature_id: str,
        name: str,
        description: str,
        file_names: List[str],
        file_hashes: List[str],
        file_sizes: List[int],
        registry_paths: List[str],
        process_names: List[str],
        network_indicators: List[str],
        file_paths: List[str],
        creation_date: datetime.datetime,
        is_active: bool = True,
        threat_level: int = 3  # 1-5，5为最高威胁
    ):
        self.signature_id = signature_id
        self.name = name
        self.description = description
        self.file_names = file_names
        self.file_hashes = file_hashes
        self.file_sizes = file_sizes
        self.registry_paths = registry_paths
        self.process_names = process_names
        self.network_indicators = network_indicators
        self.file_paths = file_paths
        self.creation_date = creation_date
        self.is_active = is_active
        self.threat_level = max(1, min(5, threat_level))  # 确保在1-5范围内

# 默认病毒特征库
DEFAULT_SIGNATURES = [
    VirusSignature(
        signature_id="sig_agenttesla",
        name="AgentTesla窃密木马",
        description="AgentTesla是一种信息窃取恶意软件，主要窃取用户敏感信息如登录凭证、键盘记录等",
        file_names=["client.exe", "update.exe", "svc.exe", "wupdate.exe"],
        file_hashes=[
            "a6f9d7c3b8e5a1d2f3c4b5a6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",  # SHA256示例
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",  # MD5示例
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"  # SHA1示例
        ],
        file_sizes=[123456, 234567, 345678],
        registry_paths=[
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ClientUpdate",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemService"
        ],
        process_names=["client.exe", "svc.exe", "wupdate.exe"],
        network_indicators=["185.244.25.114", "91.215.154.112", "agenttesla[.]top"],
        file_paths=["C:\\ProgramData\\Client\\", "C:\\Users\\Public\\Update\\"],
        creation_date=datetime.datetime(2025, 5, 20),
        is_active=True,
        threat_level=4
    ),
    VirusSignature(
        signature_id="sig_emotet",
        name="Emotet银行木马",
        description="Emotet是一种模块化银行木马，主要用于窃取金融信息和传播其他恶意软件",
        file_names=["document.exe", "invoice.exe", "receipt.exe", "payment.exe"],
        file_hashes=[
            "e34688ef04b57e3b3ec673912919b0b699e127dcfd77698b86af8a391cc5148b",  # SHA256
            "24483dc38a96747dbb937d773a021d9e",  # MD5
            "e7563460dc00f65347512f9d670515e427df8eb1"  # SHA1
        ],
        file_sizes=[679000, 1250000, 2048000],
        registry_paths=[
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\DocumentUpdate",
            "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\WinUpdate"
        ],
        process_names=["document.exe", "invoice.exe", "svchost.exe"],
        network_indicators=["193.106.31.34", "85.193.88.221", "emotet[.]cc"],
        file_paths=["C:\\Windows\\Temp\\", "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp\\"],
        creation_date=datetime.datetime(2025, 5, 18),
        is_active=True,
        threat_level=5
    ),
    VirusSignature(
        signature_id="sig_sliver",
        name="Sliver远控木马",
        description="Sliver是一种开源的C2框架，常被用于红队评估和恶意活动",
        file_names=["wsservice.exe", "netupdate.exe", "winlog.exe", "svc_host.exe"],
        file_hashes=[],
        file_sizes=[870400, 1048576],
        registry_paths=[],
        process_names=["wsservice.exe", "netupdate.exe"],
        network_indicators=["51.15.123.45", "185.199.108.153"],
        file_paths=["C:\\ProgramData\\Microsoft\\Windows\\Services\\", "C:\\Windows\\System32\\"],
        creation_date=datetime.datetime(2025, 5, 22),
        is_active=True,
        threat_level=4
    ),
    VirusSignature(
        signature_id="sig_silverfox",
        name="银狐远控木马",
        description="银狐远控木马属于Agent家族，通过伪装成WPS程序传播，具备键盘监控和远程控制能力",
        file_names=["wpst-5.20r.exe", "6JvsB0X.exe", "QU5cD.DLL"],
        file_hashes=[
            "e34688ef04b57e3b3ec673912919b0b699e127dcfd77698b86af8a391cc5148b",  # SHA256
            "24483dc38a96747dbb937d773a021d9e",  # MD5
            "e7563460dc00f65347512f9d670515e427df8eb1"  # SHA1
        ],
        file_sizes=[67900000],  # 约67.9MB
        registry_paths=[],
        process_names=["wpst-5.20r.exe", "6JvsB0X.exe"],
        network_indicators=["202.79.175.117"],
        file_paths=["C:\\ProgramData\\work_\\", "C:\\ProgramData\\work_\\*.*"],
        creation_date=datetime.datetime(2025, 5, 22),
        is_active=True,
        threat_level=5
    )
]

# -------------------------- 火焰特效模块 --------------------------
class FlameEffect:
    """命令行火焰特效"""
    
    @staticmethod
    def print_flame():
        """打印火焰特效"""
        if not Color.support_color():
            return
            
        flames = ["▁", "▂", "▃", "▅", "▆", "▇", "█", "▇", "▆", "▅", "▃", "▂"]
        for _ in range(10):
            line = "".join(random.choice(flames) for _ in range(50))
            print(f"{Color.RED}{line}{Color.RESET}")
            time.sleep(0.1)
            # 清除当前行并回到上一行
            sys.stdout.write("\033[F" + " " * 50 + "\033[F")
            sys.stdout.flush()
        
        # 清除最后一行
        print(" " * 50)
        sys.stdout.write("\033[F")

# -------------------------- 文件类型识别模块 --------------------------
class FileTypeIdentifier:
    """文件类型识别类，不依赖外部库"""
    
    # 文件头特征数据库
    FILE_SIGNATURES = {
        b'\x4D\x5A': '.exe',          # EXE文件
        b'\x50\x4B\x03\x04': '.zip',  # ZIP压缩包
        b'\x52\x61\x72\x21': '.rar',  # RAR压缩包
        b'\x77\x4F\x44\x53': '.wps',  # WPS文件
        b'\xD0\xCF\x11\xE0': '.doc',  # Word文件
        b'\x25\x50\x44\x46': '.pdf',  # PDF文件
        b'\x89\x50\x4E\x47': '.png',  # PNG图片
        b'\xFF\xD8\xFF': '.jpg',      # JPG图片
        b'\x49\x44\x33': '.mp3',      # MP3音频
    }
    
    @staticmethod
    def get_file_type(file_path: str) -> Optional[str]:
        """获取文件类型，返回扩展名"""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return None
            
        # 先尝试通过扩展名判断
        ext = os.path.splitext(file_path)[1].lower()
        if ext in ['.exe', '.zip', '.rar', '.dll', '.sys', '.msi', '.bin', '.key']:
            return ext
            
        # 通过文件头签名判断
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)  # 读取文件头16字节
                
            for signature, ext in FileTypeIdentifier.FILE_SIGNATURES.items():
                if header.startswith(signature):
                    return ext
                    
            # 检查DLL特征 (MZ + PE签名)
            if len(header) >= 64 and header.startswith(b'\x4D\x5A'):
                pe_offset = int.from_bytes(header[60:64], byteorder='little', signed=False)
                if pe_offset + 4 <= len(header) and header[pe_offset:pe_offset+4] == b'\x50\x45\x00\x00':
                    # 检查是否为DLL
                    if len(header) >= pe_offset + 24:
                        characteristics = int.from_bytes(
                            header[pe_offset+20:pe_offset+22], 
                            byteorder='little', 
                            signed=False
                        )
                        if characteristics & 0x2000:  # DLL特征位
                            return '.dll'
                    return '.exe'
                    
        except Exception:
            pass
            
        return ext if ext else None
    
    @staticmethod
    def is_executable(file_type: str) -> bool:
        """判断是否为可执行文件"""
        return file_type in ['.exe', '.dll', '.sys', '.msi']
    
    @staticmethod
    def is_archive(file_type: str) -> bool:
        """判断是否为压缩包"""
        return file_type in ['.zip', '.rar', '.7z']

# -------------------------- 签名验证模块 --------------------------
class SignatureVerifier:
    """文件签名验证类"""
    
    @staticmethod
    def verify_file_signature(file_path: str) -> Tuple[bool, str]:
        """验证文件数字签名"""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return False, "文件不存在"
            
        try:
            if IS_WINDOWS:
                # Windows使用PowerShell验证签名
                cmd = [
                    "powershell",
                    "-Command",
                    f"(Get-AuthenticodeSignature -FilePath '{file_path}').Status"
                ]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True
                )
                status = result.stdout.strip()
                if status == "Valid":
                    return True, "签名有效"
                elif status == "NotSigned":
                    return False, "未签名"
                else:
                    return False, f"签名无效: {status}"
            elif IS_LINUX:
                # Linux简单检查文件属性和常见位置
                if os.path.exists("/usr/bin/" + os.path.basename(file_path)) or \
                   os.path.exists("/usr/sbin/" + os.path.basename(file_path)):
                    return True, "系统标准路径文件"
                return False, "Linux暂不支持详细签名验证"
            elif IS_MACOS:
                # macOS使用codesign命令
                cmd = ["codesign", "--verify", "--deep", file_path]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    return True, "签名有效"
                else:
                    return False, f"签名无效: {result.stderr.strip()}"
        except Exception as e:
            return False, f"验证失败: {str(e)}"
    
    @staticmethod
    def check_file_integrity(file_path: str) -> Tuple[bool, str]:
        """检查文件完整性（创建时间与修改时间对比）"""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return False, "文件不存在"
            
        try:
            # 获取文件创建时间和修改时间
            stat_info = os.stat(file_path)
            
            # 根据系统选择合适的时间戳
            if IS_WINDOWS:
                create_time = datetime.datetime.fromtimestamp(stat_info.st_ctime)
                modify_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
            else:
                # Unix系统没有创建时间，使用inode更改时间
                create_time = datetime.datetime.fromtimestamp(stat_info.st_ctime)
                modify_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
            
            # 计算时间差（秒）
            time_diff = (modify_time - create_time).total_seconds()
            
            # 如果修改时间早于创建时间，明显异常
            if modify_time < create_time:
                return False, f"异常: 修改时间({modify_time})早于创建时间({create_time})"
            
            # 新文件短时间内被修改可能正常，但长时间后被修改可能有问题
            if time_diff > 86400:  # 超过24小时
                return False, f"警告: 文件在创建后({time_diff:.0f}秒)被修改"
                
            return True, f"正常: 创建时间({create_time}), 修改时间({modify_time})"
        except Exception as e:
            return False, f"检查失败: {str(e)}"

# -------------------------- 沙盒模拟分析模块 --------------------------
class SandboxAnalyzer:
    """简易沙盒模拟分析器"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.temp_dir = os.path.join(TEMP_DIR, "sandbox")
        os.makedirs(self.temp_dir, exist_ok=True)
        
    def run_sandbox_analysis(self, file_path: str) -> Dict:
        """在模拟沙盒环境中分析文件"""
        result = {
            "status": "running",
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "activities": [],
            "suspicious_behaviors": [],
            "verdict": "unknown"
        }
        
        try:
            self.scanner.log(f"开始对{file_path}进行沙盒动态分析")
            
            # 1. 复制文件到沙盒环境
            sandbox_file = os.path.join(self.temp_dir, os.path.basename(file_path))
            shutil.copy2(file_path, sandbox_file)
            result["activities"].append(f"文件已复制到沙盒环境: {sandbox_file}")
            
            # 2. 记录初始状态
            initial_files = set(glob.glob(os.path.join(self.temp_dir, "*")))
            initial_network = self.scanner.check_network_connections()
            initial_processes = [p["pid"] for p in self.scanner.get_running_processes()]
            
            # 3. 尝试执行文件（仅在非关键目录且有执行权限时）
            file_type = FileTypeIdentifier.get_file_type(sandbox_file)
            if FileTypeIdentifier.is_executable(file_type):
                # 检查文件权限
                if os.access(sandbox_file, os.X_OK):
                    result["activities"].append(f"尝试执行文件: {sandbox_file}")
                    
                    # 执行文件并限制时间
                    proc = None
                    try:
                        proc = subprocess.Popen(
                            sandbox_file,
                            cwd=self.temp_dir,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            shell=False
                        )
                        
                        # 最多运行30秒
                        start_time = time.time()
                        while proc.poll() is None and time.time() - start_time < 30:
                            time.sleep(1)
                            
                        if proc.poll() is None:
                            proc.terminate()
                            result["activities"].append("文件执行超时，已终止")
                        else:
                            result["activities"].append(f"文件执行完成，退出码: {proc.returncode}")
                            
                    except Exception as e:
                        result["activities"].append(f"文件执行异常: {str(e)}")
                    finally:
                        if proc and proc.poll() is None:
                            try:
                                proc.kill()
                            except:
                                pass
                else:
                    result["activities"].append("文件没有执行权限，跳过执行步骤")
            
            # 4. 分析行为差异
            # 检查新创建的文件
            final_files = set(glob.glob(os.path.join(self.temp_dir, "*")))
            new_files = final_files - initial_files
            if new_files:
                result["activities"].append(f"检测到{len(new_files)}个新创建的文件")
                for f in new_files:
                    if os.path.basename(f) not in [os.path.basename(sandbox_file)]:
                        result["suspicious_behaviors"].append(f"创建未知文件: {f}")
            
            # 检查新建立的网络连接
            final_network = self.scanner.check_network_connections()
            new_connections = [
                conn for conn in final_network 
                if not any(c["remote_ip"] == conn["remote_ip"] for c in initial_network)
            ]
            if new_connections:
                result["activities"].append(f"检测到{len(new_connections)}个新网络连接")
                for conn in new_connections:
                    is_overseas, country = self.scanner.is_ip_overseas(conn["remote_ip"])
                    if is_overseas:
                        result["suspicious_behaviors"].append(
                            f"建立境外网络连接: {conn['remote_ip']} ({country})"
                        )
            
            # 检查新启动的进程
            final_processes = [p["pid"] for p in self.scanner.get_running_processes()]
            new_processes = [p for p in final_processes if p not in initial_processes]
            if new_processes:
                result["activities"].append(f"检测到{len(new_processes)}个新进程")
                for pid in new_processes:
                    try:
                        proc = psutil.Process(pid)
                        result["suspicious_behaviors"].append(f"启动未知进程: {proc.name()} (PID: {pid})")
                    except:
                        pass
            
            # 5. 特征匹配
            file_hash = self.scanner.calculate_file_hash(sandbox_file)
            matched = False
            for sig in self.scanner.signatures:
                if not sig.is_active:
                    continue
                    
                if (os.path.basename(file_path).lower() in [n.lower() for n in sig.file_names] or
                    file_hash in sig.file_hashes):
                    result["suspicious_behaviors"].append(f"匹配已知病毒特征: {sig.name}")
                    matched = True
            
            # 6. 判定结果
            if matched or len(result["suspicious_behaviors"]) > 0:
                result["verdict"] = "malicious"
            else:
                result["verdict"] = "clean"
                
            result["status"] = "completed"
            self.scanner.log(f"沙盒分析完成，结果: {result['verdict']}")
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            self.scanner.log(f"沙盒分析失败: {str(e)}", "ERROR")
        
        # 保存分析报告
        report_path = os.path.join(
            REPORTS_DIR, 
            f"sandbox_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        result["report_path"] = report_path
        return result

# -------------------------- 威胁情报中心接口模块 --------------------------
class ThreatIntelClient:
    """威胁情报中心客户端"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.name = config.get("name", "Unknown")
        self.api_key = config.get("api_key", "")
        self.api_url = config.get("api_url", "")
        self.upload_url = config.get("upload_url", "")
        
        # 延迟导入requests，确保在需要时才加载
        self.requests = None
        
    def _ensure_requests(self) -> bool:
        """确保requests库可用，如未安装则尝试安装"""
        if self.requests:
            return True
            
        try:
            import requests
            self.requests = requests
            return True
        except ImportError:
            try:
                # 尝试自动安装requests
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "requests"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                import requests
                self.requests = requests
                return True
            except Exception:
                return False
    
    def get_file_report(self, file_hash: str) -> Dict:
        """获取文件报告"""
        if not self.enabled or not self.api_key or not self.api_url:
            return {"status": "error", "message": f"{self.name}未配置或禁用"}
            
        if not self._ensure_requests():
            return {"status": "error", "message": "无法加载requests库，无法查询威胁情报"}
            
        try:
            if self.name == "VirusTotal":
                params = {"apikey": self.api_key, "resource": file_hash}
                response = self.requests.get(self.api_url, params=params, timeout=10)
            elif self.name == "微步在线":
                params = {"apikey": self.api_key, "hash": file_hash}
                response = self.requests.get(self.api_url, params=params, timeout=10)
            else:  # 奇安信和绿盟使用相似的参数格式
                params = {"key": self.api_key, "hash": file_hash}
                response = self.requests.get(self.api_url, params=params, timeout=10)
                
            if response.status_code == 200:
                result = response.json()
                result["status"] = "success"
                result["source"] = self.name
                return result
            else:
                return {
                    "status": "error", 
                    "message": f"{self.name}查询失败，状态码: {response.status_code}",
                    "source": self.name
                }
        except Exception as e:
            return {
                "status": "error", 
                "message": f"{self.name}查询出错: {str(e)}",
                "source": self.name
            }
    
    def get_ip_report(self, ip: str) -> Dict:
        """获取IP地址报告"""
        if not self.enabled or not self.api_key or not self.api_url:
            return {"status": "error", "message": f"{self.name}未配置或禁用"}
            
        if not self._ensure_requests():
            return {"status": "error", "message": "无法加载requests库，无法查询威胁情报"}
            
        try:
            if self.name == "VirusTotal":
                params = {"apikey": self.api_key, "ip": ip}
                response = self.requests.get("https://www.virustotal.com/vtapi/v2/ip-address/report", 
                                           params=params, timeout=10)
            elif self.name == "微步在线":
                params = {"apikey": self.api_key, "ip": ip}
                response = self.requests.get("https://s.threatbook.cn/api/v3/ip/report",
                                           params=params, timeout=10)
            else:  # 奇安信和绿盟
                params = {"key": self.api_key, "ip": ip}
                response = self.requests.get(f"{self.api_url.replace('file', 'ip')}",
                                           params=params, timeout=10)
                
            if response.status_code == 200:
                result = response.json()
                result["status"] = "success"
                result["source"] = self.name
                return result
            else:
                return {
                    "status": "error", 
                    "message": f"{self.name}IP查询失败，状态码: {response.status_code}",
                    "source": self.name
                }
        except Exception as e:
            return {
                "status": "error", 
                "message": f"{self.name}IP查询出错: {str(e)}",
                "source": self.name
            }
    
    def upload_file(self, file_path: str) -> Dict:
        """上传文件到威胁情报中心沙盒"""
        if not self.enabled or not self.api_key or not self.upload_url:
            return {"status": "error", "message": f"{self.name}未配置或禁用"}
            
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return {"status": "error", "message": "文件不存在"}
            
        if not self._ensure_requests():
            return {"status": "error", "message": "无法加载requests库，无法上传文件"}
            
        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                
                if self.name == "VirusTotal":
                    params = {"apikey": self.api_key}
                    response = self.requests.post(
                        self.upload_url, 
                        files=files, 
                        params=params,
                        timeout=30
                    )
                elif self.name == "微步在线":
                    params = {"apikey": self.api_key}
                    response = self.requests.post(
                        self.upload_url, 
                        files=files, 
                        params=params,
                        timeout=30
                    )
                else:  # 奇安信和绿盟
                    params = {"key": self.api_key}
                    response = self.requests.post(
                        self.upload_url, 
                        files=files, 
                        params=params,
                        timeout=30
                    )
                
            if response.status_code == 200:
                result = response.json()
                result["status"] = "success"
                result["source"] = self.name
                return result
            else:
                return {
                    "status": "error", 
                    "message": f"{self.name}上传失败，状态码: {response.status_code}",
                    "source": self.name
                }
        except Exception as e:
            return {
                "status": "error", 
                "message": f"{self.name}上传出错: {str(e)}",
                "source": self.name
            }

# -------------------------- 扫描结果导出模块 --------------------------
class ScanResultExporter:
    """扫描结果导出器，支持自动导出为CSV格式"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.csv_headers = [
            "扫描时间", "文件路径", "文件名称", "文件类型", "文件大小",
            "哈希值", "是否为恶意文件", "威胁名称", "威胁级别",
            "匹配的特征ID", "数字签名状态", "网络连接", "沙盒分析结果",
            "扫描状态", "错误信息"
        ]
        
        # 确保报告目录存在
        os.makedirs(REPORTS_DIR, exist_ok=True)
    
    def export_to_csv(self, scan_results: List[Dict], custom_path: Optional[str] = None) -> str:
        """
        将扫描结果导出为CSV文件
        
        Args:
            scan_results: 扫描结果列表
            custom_path: 自定义保存路径，None则使用默认路径
            
        Returns:
            保存的CSV文件路径
        """
        try:
            # 确保scan_results是列表类型
            if not isinstance(scan_results, list):
                scan_results = [scan_results]
                
            # 即使没有结果也创建CSV文件
            if not scan_results:
                scan_results = [{"timestamp": datetime.datetime.now(), 
                                "status": "无扫描结果", 
                                "error_message": ""}]
            
            # 确定保存路径
            if custom_path:
                csv_path = custom_path
            else:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                csv_path = os.path.join(REPORTS_DIR, f"scan_results_{timestamp}.csv")
            
            # 确保目录存在
            os.makedirs(os.path.dirname(csv_path), exist_ok=True)
            
            # 写入CSV文件
            with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(self.csv_headers)
                
                for result in scan_results:
                    # 确保result是字典类型
                    if not isinstance(result, dict):
                        result = {"status": "无效结果", "error_message": "结果格式不正确"}
                    
                    # 处理扫描时间戳
                    timestamp = result.get("timestamp")
                    if isinstance(timestamp, datetime.datetime):
                        timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    elif isinstance(timestamp, str):
                        timestamp_str = timestamp
                    else:
                        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # 处理扫描状态和错误信息
                    scan_status = "成功" if result.get("status") == "success" else "失败"
                    error_msg = result.get("error_message", "")
                    
                    # 处理网络连接信息
                    network_info = []
                    if "network_connections" in result and isinstance(result["network_connections"], list):
                        for conn in result["network_connections"]:
                            if isinstance(conn, dict):
                                network_info.append(f"{conn.get('remote_ip', '')}:{conn.get('remote_port', '')}")
                    network_str = ";".join(network_info)
                    
                    # 处理沙盒结果
                    sandbox_verdict = "未分析"
                    if "sandbox_analysis" in result and isinstance(result["sandbox_analysis"], dict):
                        sandbox_verdict = result["sandbox_analysis"].get("verdict", "未分析")
                    
                    # 处理威胁名称
                    threat_name = ""
                    if "matched_signatures" in result and isinstance(result["matched_signatures"], list):
                        threat_names = []
                        for sig in result["matched_signatures"]:
                            if isinstance(sig, dict) and "name" in sig:
                                threat_names.append(sig["name"])
                        threat_name = ", ".join(threat_names)
                    
                    # 处理威胁级别
                    threat_level = ""
                    if "matched_signatures" in result and isinstance(result["matched_signatures"], list) and result["matched_signatures"]:
                        levels = []
                        for sig in result["matched_signatures"]:
                            if isinstance(sig, dict) and "threat_level" in sig:
                                try:
                                    levels.append(int(sig["threat_level"]))
                                except (ValueError, TypeError):
                                    pass
                        if levels:
                            threat_level = max(levels)
                    
                    # 处理匹配的特征ID
                    matched_ids = ""
                    if "matched_signatures" in result and isinstance(result["matched_signatures"], list):
                        ids = []
                        for sig in result["matched_signatures"]:
                            if isinstance(sig, dict) and "signature_id" in sig:
                                ids.append(sig["signature_id"])
                        matched_ids = ", ".join(ids)
                    
                    # 处理数字签名状态
                    signature_status = ""
                    if "signature_verification" in result and isinstance(result["signature_verification"], dict):
                        signature_status = result["signature_verification"].get("message", "")
                    
                    # 写入行数据
                    row = [
                        timestamp_str,
                        result.get("file_path", ""),
                        result.get("file_name", ""),
                        result.get("file_type", ""),
                        result.get("file_size", ""),
                        result.get("file_hash", ""),
                        "是" if result.get("is_malicious", False) else "否",
                        threat_name,
                        threat_level,
                        matched_ids,
                        signature_status,
                        network_str,
                        sandbox_verdict,
                        scan_status,
                        error_msg
                    ]
                    writer.writerow(row)
            
            self.scanner.log(f"扫描结果已导出至: {csv_path}", "SUCCESS")
            return csv_path
        except Exception as e:
            self.scanner.log(f"导出扫描结果失败: {str(e)}", "ERROR")
            return ""

# -------------------------- 病毒特征管理模块 --------------------------
class SignatureManager:
    """病毒特征管理工具，支持导入、导出和标准化"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.required_fields = [
            "signature_id", "name", "description", "file_names",
            "file_hashes", "file_sizes", "registry_paths", "process_names",
            "network_indicators", "file_paths", "creation_date",
            "is_active", "threat_level"
        ]
        
        # 确保特征库目录存在
        os.makedirs(SIGNATURES_DIR, exist_ok=True)
    
    def export_signatures(self, file_path: Optional[str] = None) -> str:
        """
        导出病毒特征为JSON文件
        
        Args:
            file_path: 导出路径，None则使用默认路径
            
        Returns:
            保存的JSON文件路径
        """
        try:
            if not file_path:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                file_path = os.path.join(SIGNATURES_DIR, f"virus_signatures_{timestamp}.json")
            
            # 转换特征为可序列化格式
            signatures_data = []
            for sig in self.scanner.signatures:
                sig_dict = {
                    "signature_id": sig.signature_id,
                    "name": sig.name,
                    "description": sig.description,
                    "file_names": sig.file_names,
                    "file_hashes": sig.file_hashes,
                    "file_sizes": sig.file_sizes,
                    "registry_paths": sig.registry_paths,
                    "process_names": sig.process_names,
                    "network_indicators": sig.network_indicators,
                    "file_paths": sig.file_paths,
                    "creation_date": sig.creation_date.isoformat(),
                    "is_active": sig.is_active,
                    "threat_level": sig.threat_level
                }
                signatures_data.append(sig_dict)
            
            # 写入JSON文件
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(signatures_data, f, ensure_ascii=False, indent=2)
            
            self.scanner.log(f"病毒特征已导出至: {file_path}", "SUCCESS")
            return file_path
        except Exception as e:
            self.scanner.log(f"导出病毒特征失败: {str(e)}", "ERROR")
            return ""
    
    def import_signatures(self, file_path: str, merge: bool = True) -> bool:
        """
        从JSON文件导入病毒特征
        
        Args:
            file_path: JSON文件路径
            merge: 是否合并到现有特征库，False则替换
            
        Returns:
            是否导入成功
        """
        try:
            if not os.path.exists(file_path):
                self.scanner.log(f"特征文件不存在: {file_path}", "ERROR")
                return False
            
            # 读取JSON文件
            with open(file_path, "r", encoding="utf-8") as f:
                signatures_data = json.load(f)
            
            # 标准化并验证特征数据
            valid_signatures = []
            for data in signatures_data:
                # 标准化特征数据
                standardized = self.standardize_signature(data)
                
                # 验证必要字段
                missing_fields = [f for f in self.required_fields if f not in standardized]
                if missing_fields:
                    self.scanner.log(f"特征数据不完整，缺少字段: {', '.join(missing_fields)}", "WARNING")
                    continue
                
                # 创建VirusSignature对象
                try:
                    signature = VirusSignature(
                        signature_id=standardized["signature_id"],
                        name=standardized["name"],
                        description=standardized["description"],
                        file_names=standardized["file_names"],
                        file_hashes=standardized["file_hashes"],
                        file_sizes=standardized["file_sizes"],
                        registry_paths=standardized["registry_paths"],
                        process_names=standardized["process_names"],
                        network_indicators=standardized["network_indicators"],
                        file_paths=standardized["file_paths"],
                        creation_date=datetime.datetime.fromisoformat(standardized["creation_date"]),
                        is_active=standardized["is_active"],
                        threat_level=standardized["threat_level"]
                    )
                    valid_signatures.append(signature)
                except Exception as e:
                    self.scanner.log(f"创建特征对象失败: {str(e)}", "WARNING")
                    continue
            
            # 应用导入的特征
            if not merge:
                self.scanner.signatures = []
            
            for sig in valid_signatures:
                self.scanner.add_signature(sig)
            
            self.scanner.log(f"成功导入 {len(valid_signatures)} 个病毒特征", "SUCCESS")
            return True
        except Exception as e:
            self.scanner.log(f"导入病毒特征失败: {str(e)}", "ERROR")
            return False
    
    def standardize_signature(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        标准化病毒特征数据，确保格式正确
        
        Args:
            data: 原始特征数据
            
        Returns:
            标准化后的特征数据
        """
        standardized = {}
        
        # 处理必要字段
        standardized["signature_id"] = data.get("signature_id", f"auto_gen_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
        standardized["name"] = data.get("name", "未命名特征")
        standardized["description"] = data.get("description", "无描述")
        
        # 确保列表类型字段
        list_fields = [
            "file_names", "file_hashes", "file_sizes", 
            "registry_paths", "process_names", 
            "network_indicators", "file_paths"
        ]
        for field in list_fields:
            value = data.get(field, [])
            if not isinstance(value, list):
                standardized[field] = [value] if value else []
            else:
                standardized[field] = value
        
        # 处理日期字段
        try:
            if "creation_date" in data:
                # 尝试解析多种日期格式
                date_formats = ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y/%m/%d"]
                for fmt in date_formats:
                    try:
                        dt = datetime.datetime.strptime(str(data["creation_date"]), fmt)
                        standardized["creation_date"] = dt.isoformat()
                        break
                    except ValueError:
                        continue
                else:
                    # 如果所有格式都失败，使用当前时间
                    standardized["creation_date"] = datetime.datetime.now().isoformat()
            else:
                standardized["creation_date"] = datetime.datetime.now().isoformat()
        except:
            standardized["creation_date"] = datetime.datetime.now().isoformat()
        
        # 处理布尔值字段
        standardized["is_active"] = bool(data.get("is_active", True))
        
        # 处理威胁级别（确保1-5之间的整数）
        try:
            threat_level = int(data.get("threat_level", 3))
            standardized["threat_level"] = max(1, min(5, threat_level))
        except:
            standardized["threat_level"] = 3
            
        return standardized
    # -------------------------- 病毒特征管理模块 --------------------------
class SignatureManager:
    """病毒特征管理工具，支持导入、导出和标准化（优化版）"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.required_fields = [
            "signature_id", "name", "description", "file_names",
            "file_hashes", "file_sizes", "registry_paths", "process_names",
            "network_indicators", "file_paths", "creation_date",
            "is_active", "threat_level"
        ]
        os.makedirs(SIGNATURES_DIR, exist_ok=True)
        # 支持的日期格式扩展
        self.date_formats = [
            "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",  # ISO格式
            "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",         # 带时间
            "%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y"             # 仅日期
        ]
    
    def export_signatures(self, file_path: Optional[str] = None) -> str:
        # 保持原有导出逻辑不变（略）
        ...
    
    def import_signatures(self, file_path: str, merge: bool = True) -> bool:
        """优化版导入逻辑：增强错误捕获和日志提示"""
        if not file_path:
            self.scanner.log("未提供特征文件路径", "ERROR")
            return False

        # 基础文件检查
        if not os.path.isfile(file_path):
            self.scanner.log(f"特征文件不存在或不是文件: {file_path}", "ERROR")
            return False
        
        try:
            # 读取文件（增加编码检测和权限处理）
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    try:
                        signatures_data = json.load(f)
                    except json.JSONDecodeError as e:
                        self.scanner.log(
                            f"JSON格式错误: 在第{e.lineno}行第{e.colno}列 - {e.msg}", 
                            "ERROR"
                        )
                        return False
            except PermissionError:
                self.scanner.log(f"无权限读取文件: {file_path}", "ERROR")
                return False
            except UnicodeDecodeError:
                # 尝试其他编码
                try:
                    with open(file_path, "r", encoding="gbk") as f:
                        signatures_data = json.load(f)
                except:
                    self.scanner.log(f"文件编码错误，无法解析: {file_path}", "ERROR")
                    return False
            except Exception as e:
                self.scanner.log(f"读取文件失败: {str(e)}", "ERROR")
                return False

            # 确保数据是列表格式
            if not isinstance(signatures_data, list):
                signatures_data = [signatures_data]
                self.scanner.log("特征文件为单个特征，自动转换为列表格式", "INFO")

            valid_signatures = []
            invalid_count = 0

            for idx, data in enumerate(signatures_data):
                if not isinstance(data, dict):
                    self.scanner.log(f"第{idx+1}个特征不是字典格式，跳过", "WARNING")
                    invalid_count += 1
                    continue

                # 标准化特征
                try:
                    standardized = self.standardize_signature(data)
                except Exception as e:
                    self.scanner.log(f"第{idx+1}个特征标准化失败: {str(e)}", "WARNING")
                    invalid_count += 1
                    continue

                # 检查必填字段
                missing_fields = [f for f in self.required_fields if f not in standardized]
                if missing_fields:
                    self.scanner.log(
                        f"第{idx+1}个特征缺少必填字段: {', '.join(missing_fields)}，跳过", 
                        "WARNING"
                    )
                    invalid_count += 1
                    continue

                # 验证并创建特征对象
                try:
                    # 严格验证日期格式
                    creation_date = datetime.datetime.fromisoformat(standardized["creation_date"])
                    
                    # 验证数值类型
                    if not isinstance(standardized["threat_level"], int):
                        raise ValueError("威胁级别必须是整数")
                    if not all(isinstance(s, int) for s in standardized["file_sizes"]):
                        raise ValueError("文件大小必须是整数列表")

                    signature = VirusSignature(
                        signature_id=standardized["signature_id"],
                        name=standardized["name"],
                        description=standardized["description"],
                        file_names=standardized["file_names"],
                        file_hashes=standardized["file_hashes"],
                        file_sizes=standardized["file_sizes"],
                        registry_paths=standardized["registry_paths"],
                        process_names=standardized["process_names"],
                        network_indicators=standardized["network_indicators"],
                        file_paths=standardized["file_paths"],
                        creation_date=creation_date,
                        is_active=standardized["is_active"],
                        threat_level=standardized["threat_level"]
                    )
                    valid_signatures.append(signature)
                except Exception as e:
                    self.scanner.log(
                        f"第{idx+1}个特征创建失败: {str(e)}，跳过", 
                        "WARNING"
                    )
                    invalid_count += 1
                    continue

            # 应用导入结果
            if not merge:
                self.scanner.signatures = []
                self.scanner.log("已清空现有特征库", "INFO")

            # 去重并添加
            added_count = 0
            existing_ids = {s.signature_id for s in self.scanner.signatures}
            for sig in valid_signatures:
                if sig.signature_id not in existing_ids:
                    self.scanner.add_signature(sig)
                    existing_ids.add(sig.signature_id)
                    added_count += 1

            self.scanner.log(
                f"特征导入完成 - 总数量: {len(signatures_data)}, "
                f"有效: {len(valid_signatures)}, "
                f"新增: {added_count}, "
                f"无效/重复: {invalid_count + (len(valid_signatures) - added_count)}",
                "SUCCESS"
            )
            return len(valid_signatures) > 0

        except Exception as e:
            self.scanner.log(f"导入过程发生未预期错误: {str(e)}", "ERROR")
            return False
    
    def standardize_signature(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """优化版标准化：增强类型转换和兼容性"""
        standardized = {}

        # 处理ID（确保唯一）
        base_id = data.get("signature_id", f"auto_gen_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
        standardized["signature_id"] = base_id.strip()

        # 处理字符串字段
        standardized["name"] = str(data.get("name", "未命名特征")).strip()
        standardized["description"] = str(data.get("description", "无描述")).strip()

        # 处理列表字段（严格转换为列表，确保元素类型正确）
        list_fields = {
            "file_names": str,    # 文件名应为字符串
            "file_hashes": str,   # 哈希应为字符串
            "file_sizes": int,    # 大小应为整数
            "registry_paths": str,
            "process_names": str,
            "network_indicators": str,
            "file_paths": str
        }
        for field, elem_type in list_fields.items():
            value = data.get(field, [])
            # 确保是列表
            if not isinstance(value, list):
                value = [value] if value is not None else []
            # 转换元素类型并过滤空值
            standardized_list = []
            for item in value:
                try:
                    # 特殊处理file_sizes的字符串转换（如"1024"转1024）
                    if field == "file_sizes" and isinstance(item, str):
                        standardized_item = int(item.strip())
                    else:
                        standardized_item = elem_type(item)
                    standardized_list.append(standardized_item)
                except:
                    continue  # 跳过转换失败的元素
            standardized[field] = standardized_list

        # 处理日期（增强兼容性）
        creation_date = data.get("creation_date")
        if creation_date:
            for fmt in self.date_formats:
                try:
                    dt = datetime.datetime.strptime(str(creation_date), fmt)
                    standardized["creation_date"] = dt.isoformat()
                    break
                except ValueError:
                    continue
            else:
                # 所有格式都失败时使用当前时间
                standardized["creation_date"] = datetime.datetime.now().isoformat()
                self.scanner.log(f"日期格式不支持: {creation_date}，已自动修正", "WARNING")
        else:
            standardized["creation_date"] = datetime.datetime.now().isoformat()

        # 处理布尔值（支持字符串"true"/"false"）
        is_active = data.get("is_active", True)
        if isinstance(is_active, str):
            is_active = is_active.lower() in ["true", "1", "yes"]
        standardized["is_active"] = bool(is_active)

        # 处理威胁级别（严格限制1-5）
        threat_level = data.get("threat_level", 3)
        try:
            threat_level = int(threat_level)
        except:
            threat_level = 3
        standardized["threat_level"] = max(1, min(5, threat_level))

        return standardized

# -------------------------- 核心扫描器类 --------------------------
class PirsrcScanner:
    """pirsrc_scan 核心扫描器"""
    
    def __init__(self):
        # 初始化组件
        self.file_identifier = FileTypeIdentifier()
        self.signature_verifier = SignatureVerifier()
        self.sandbox_analyzer = SandboxAnalyzer(self)
        self.intel_clients = {
            name: ThreatIntelClient(cfg) 
            for name, cfg in THREAT_INTEL_CONFIG.items()
        }
        self.result_exporter = ScanResultExporter(self)
        self.signature_manager = SignatureManager(self)
        
        # 数据存储
        self.signatures = DEFAULT_SIGNATURES.copy()
        self.scan_results = []
        self.logs = []
        self.cross_border_connections = []
        
        # 确保CSV报告文件存在
        self.border_report_path = os.path.join(REPORTS_DIR, "cross_border_connections.csv")
        if not os.path.exists(self.border_report_path):
            with open(self.border_report_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["时间", "进程ID", "进程名", "IP地址", "国家/地区", "服务位置", "文件位置"])
        
        # 误杀恢复记录
        self.quarantine_log = os.path.join(QUARANTINE_DIR, "quarantine_log.json")
        if not os.path.exists(self.quarantine_log):
            with open(self.quarantine_log, "w", encoding="utf-8") as f:
                json.dump([], f, ensure_ascii=False, indent=2)
    
    def log(self, message: str, level: str = "INFO") -> str:
        """记录日志"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] [{level}] {message}"
        self.logs.append(log_msg)
        # 控制台输出带颜色
        if Color.support_color():
            color_map = {
                "INFO": Color.WHITE,
                "WARNING": Color.YELLOW,
                "ERROR": Color.RED,
                "SUCCESS": Color.GREEN
            }
            color = color_map.get(level, Color.WHITE)
            print(f"{color}{log_msg}{Color.RESET}")
        else:
            print(log_msg)
        
        # 写入日志文件
        log_file = os.path.join(REPORTS_DIR, f"scan_log_{datetime.datetime.now().strftime('%Y%m%d')}.txt")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_msg + "\n")
            
        return log_msg
    
    def print_anomaly_process(self, proc: Dict, connections: List[Dict] = None):
        """打印异常进程信息"""
        print(f"\n{Color.RED}{Color.BOLD}发现异常进程:{Color.RESET}")
        print(f"PID: {proc['pid']}")
        print(f"进程名: {proc['name']}")
        print(f"路径: {proc['path']}")
        print(f"CPU占用: {proc['cpu_usage']}%")
        print(f"内存占用: {proc['memory_usage']}%")
        
        # Windows系统特有信息
        if IS_WINDOWS and proc['path'] and os.path.exists(proc['path']):
            sig_valid, sig_msg = self.signature_verifier.verify_file_signature(proc['path'])
            print(f"数字签名: {'有效' if sig_valid else '无效'} ({sig_msg})")
            
            # 文件属性
            try:
                stat_info = os.stat(proc['path'])
                print(f"文件大小: {stat_info.st_size} bytes")
                print(f"创建时间: {datetime.datetime.fromtimestamp(stat_info.st_ctime)}")
                print(f"修改时间: {datetime.datetime.fromtimestamp(stat_info.st_mtime)}")
            except:
                pass
        
        # Linux系统特有信息
        if IS_LINUX and proc['path'] and os.path.exists(proc['path']):
            try:
                stat_info = os.stat(proc['path'])
                print(f"文件权限: {oct(stat_info.st_mode & 0o777)}")
                print(f"所有者ID: {stat_info.st_uid}")
                print(f"组ID: {stat_info.st_gid}")
            except:
                pass
        
        # 网络连接信息
        if connections:
            proc_connections = [c for c in connections if c['pid'] == proc['pid']]
            if proc_connections:
                print(f"\n{Color.YELLOW}相关网络连接:{Color.RESET}")
                for conn in proc_connections:
                    print(f"远程IP: {conn['remote_ip']}:{conn['remote_port']}")
                    print(f"位置: {conn['country']}")
                    
                    # 威胁情报对比
                    for report in conn['ip_reports']:
                        if report['status'] == 'success':
                            if 'positives' in report:
                                print(f"{report['source']}检测: {report['positives']}/{report['total']} 引擎报毒")
                            elif 'judgments' in report and report['judgments']:
                                print(f"{report['source']}检测: {report['judgments'][0]['judgment']}")
        
        # 写入日志
        self.log(f"异常进程: {proc['name']} (PID: {proc['pid']}) - 路径: {proc['path']}", "WARNING")
    
    def add_signature(self, signature: VirusSignature) -> None:
        """添加自定义病毒特征"""
        # 检查是否已存在相同ID的特征
        existing = next((s for s in self.signatures if s.signature_id == signature.signature_id), None)
        if existing:
            # 更新现有特征
            self.signatures.remove(existing)
        self.signatures.append(signature)
        self.log(f"已添加/更新病毒特征: {signature.name} (ID: {signature.signature_id})")
    
    def save_signatures(self, file_path: str) -> bool:
        """保存病毒特征到文件"""
        return self.signature_manager.export_signatures(file_path)
    
    def load_signatures(self, file_path: str) -> bool:
        """从文件加载病毒特征"""
        return self.signature_manager.import_signatures(file_path)
    
    def calculate_file_hash(self, file_path: str) -> str:
        """计算文件SHA256哈希"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(4096):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            self.log(f"计算{file_path}哈希失败: {str(e)}", "ERROR")
            return ""
    
    def is_ip_overseas(self, ip: str) -> Tuple[bool, str]:
        """判断IP是否为跨境IP"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            if ip_addr.is_private:
                return False, "内网IP"
            for network in [ipaddress.ip_network(cidr) for cidr in CHINA_IP_RANGES]:
                if ip_addr in network:
                    return False, "中国"
            return True, "境外"
        except ValueError:
            return True, "未知"
    
    def get_running_processes(self) -> List[Dict]:
        """获取当前运行的进程，包含资源占用信息"""
        processes = []
        if not psutil:
            self.log("psutil库未安装，无法获取进程信息", "WARNING")
            return processes
            
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.as_dict()
                    # 判断是否为常见正常进程
                    is_common = proc_info['name'].lower() in [p.lower() for p in COMMON_LEGIT_PROCESSES]
                    
                    processes.append({
                        "name": proc_info['name'],
                        "pid": proc_info['pid'],
                        "path": proc_info['exe'] if proc_info['exe'] else "",
                        "cpu_usage": proc_info['cpu_percent'],
                        "memory_usage": proc_info['memory_percent'],
                        "is_common": is_common
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            self.log(f"获取进程列表失败: {str(e)}", "ERROR")
        return processes
    
    def check_high_resource_processes(self) -> List[Dict]:
        """检查高资源占用的进程"""
        high_resource = []
        processes = self.get_running_processes()
        
        for proc in processes:
            # 判断是否为高资源占用（CPU>20%或内存>10%）
            if proc["cpu_usage"] > 20 or proc["memory_usage"] > 10:
                # 如果不是常见进程，则标记为可疑
                if not proc["is_common"]:
                    proc["is_suspicious"] = True
                    high_resource.append(proc)
                    # 自动打印异常进程信息
                    self.print_anomaly_process(proc)
                else:
                    proc["is_suspicious"] = False
        
        return high_resource
    
    def check_network_connections(self) -> List[Dict]:
        """检查网络连接，检测跨境连接"""
        connections = []
        if not psutil:
            self.log("psutil库未安装，无法获取网络连接信息", "WARNING")
            return connections
            
        try:
            # 获取网络连接
            for conn in psutil.net_connections(kind='tcp'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    local_ip, local_port = conn.laddr
                    remote_ip, remote_port = conn.raddr
                    
                    # 只检查远程IP
                    is_overseas, country = self.is_ip_overseas(remote_ip)
                    
                    # 获取进程信息
                    proc_info = None
                    try:
                        if conn.pid:
                            proc = psutil.Process(conn.pid)
                            proc_name = proc.name()
                            proc_path = proc.exe() if proc.exe() else ""
                            is_common = proc_name.lower() in [p.lower() for p in COMMON_LEGIT_PROCESSES]
                            
                            proc_info = {
                                "name": proc_name,
                                "pid": conn.pid,
                                "path": proc_path,
                                "is_common": is_common
                            }
                            
                            # 如果是不常见进程且有跨境连接，标记为异常
                            if is_overseas and not is_common:
                                self.print_anomaly_process(proc_info, [{"pid": conn.pid, "remote_ip": remote_ip, 
                                                                    "remote_port": remote_port, "country": country,
                                                                    "ip_reports": []}])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    # 查询IP威胁情报
                    ip_reports = []
                    for client in self.intel_clients.values():
                        if client.enabled and client.api_key:
                            report = client.get_ip_report(remote_ip)
                            ip_reports.append(report)
                    
                    conn_info = {
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "is_overseas": is_overseas,
                        "country": country,
                        "pid": conn.pid,
                        "process_info": proc_info,
                        "ip_reports": ip_reports,
                        "timestamp": datetime.datetime.now()
                    }
                    
                    connections.append(conn_info)
                    
                    # 如果是跨境连接，添加到报告
                    if is_overseas:
                        self.cross_border_connections.append(conn_info)
                        proc_name = proc_info["name"] if proc_info else "未知进程"
                        self.log(f"检测到跨境连接: {remote_ip} (PID: {conn.pid}, 进程: {proc_name})", "WARNING")
                        
                        # 保存到CSV
                        with open(self.border_report_path, "a", newline="", encoding="utf-8") as f:
                            writer = csv.writer(f)
                            writer.writerow([
                                conn_info["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                                conn_info["pid"],
                                proc_name if proc_info else "未知",
                                conn_info["remote_ip"],
                                conn_info["country"],
                                proc_info["path"] if proc_info else "未知",
                                proc_info["path"] if proc_info else "未知"
                            ])
        except Exception as e:
            self.log(f"检查网络连接失败: {str(e)}", "ERROR")
        return connections
    
    def scan_file(self, file_path: str, deep_scan: bool = False) -> Dict:
        """扫描单个文件，确保错误结果也包含必要信息"""
        # 初始化基础结果字典
        result = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "status": "success",
            "error_message": "",
        }
        
        # 检查文件是否存在
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            result["status"] = "error"
            result["error_message"] = f"文件不存在: {file_path}"
            self.scan_results.append(result)
            # 确保单个文件扫描结果也导出到CSV
            self.result_exporter.export_to_csv([result])
            return result
        
        # 完善结果字典的其他字段
        try:
            result.update({
                "file_size": os.path.getsize(file_path),
                "file_type": self.file_identifier.get_file_type(file_path),
                "file_hash": self.calculate_file_hash(file_path),
                "is_malicious": False,
                "matched_signatures": [],
                "threat_intel_reports": [],
                "signature_verification": {"valid": False, "message": ""},
                "integrity_check": {"valid": False, "message": ""},
                "sandbox_analysis": None,
                "timestamp": datetime.datetime.now()
            })
            
            # 验证文件签名
            sig_valid, sig_msg = self.signature_verifier.verify_file_signature(file_path)
            result["signature_verification"] = {
                "valid": sig_valid,
                "message": sig_msg
            }
            
            # 检查文件完整性
            int_valid, int_msg = self.signature_verifier.check_file_integrity(file_path)
            result["integrity_check"] = {
                "valid": int_valid,
                "message": int_msg
            }
            
            # 检查文件是否匹配病毒特征
            for sig in self.signatures:
                if not sig.is_active:
                    continue
                    
                matches = []
                # 检查文件名
                if result["file_name"].lower() in [n.lower() for n in sig.file_names]:
                    matches.append(f"文件名匹配: {result['file_name']}")
                
                # 检查文件大小
                if result["file_size"] in sig.file_sizes:
                    matches.append(f"文件大小匹配: {result['file_size']} bytes")
                    
                # 检查文件哈希
                if result["file_hash"] and result["file_hash"] in sig.file_hashes:
                    matches.append(f"文件哈希匹配: {result['file_hash']}")
                    result["is_malicious"] = True
                    
                # 检查文件路径
                for path_pattern in sig.file_paths:
                    if re.match(path_pattern.replace("\\", "\\\\").replace("*", ".*"), file_path, re.IGNORECASE):
                        matches.append(f"文件路径匹配: {file_path}")
                        result["is_malicious"] = True
                    
                if matches:
                    result["matched_signatures"].append({
                        "signature_id": sig.signature_id,
                        "name": sig.name,
                        "description": sig.description,
                        "matches": matches,
                        "threat_level": sig.threat_level
                    })
                    result["is_malicious"] = True
            
            # 如果是恶意文件或深度扫描，进行沙盒分析
            if result["is_malicious"] or deep_scan:
                result["sandbox_analysis"] = self.sandbox_analyzer.run_sandbox_analysis(file_path)
                if result["sandbox_analysis"]["verdict"] == "malicious":
                    result["is_malicious"] = True
            
            # 查询威胁情报中心
            if result["file_hash"]:
                for client in self.intel_clients.values():
                    report = client.get_file_report(result["file_hash"])
                    result["threat_intel_reports"].append(report)
                    
                    # 如果任何情报中心标记为恶意，则标记为恶意
                    if report.get("status") == "success" and report.get("positives", 0) > 0:
                        result["is_malicious"] = True
            
            self.scan_results.append(result)
            status = "恶意" if result["is_malicious"] else "正常"
            self.log(f"文件扫描完成: {result['file_name']} - 状态: {status}")
            
            # 确保单个文件扫描结果也导出到CSV
            self.result_exporter.export_to_csv([result])
            return result
            
        except Exception as e:
            # 处理扫描过程中的异常
            result["status"] = "error"
            result["error_message"] = f"扫描过程中出错: {str(e)}"
            self.scan_results.append(result)
            # 异常情况也导出结果
            self.result_exporter.export_to_csv([result])
            self.log(f"文件扫描出错: {result['file_name']} - 错误: {str(e)}", "ERROR")
            return result

    def scan_directory(self, dir_path: str, deep_scan: bool = False) -> List[Dict]:
        """扫描目录中的所有文件"""
        if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
            error_msg = f"目录不存在或不是有效的目录: {dir_path}"
            self.log(error_msg, "ERROR")
            # 记录错误结果
            error_result = {
                "file_path": dir_path,
                "file_name": os.path.basename(dir_path),
                "status": "error",
                "error_message": error_msg,
                "timestamp": datetime.datetime.now()
            }
            self.scan_results.append(error_result)
            # 导出错误结果
            self.result_exporter.export_to_csv([error_result])
            return self.scan_results
            
        results = []
        self.log(f"开始扫描目录: {dir_path}")
        
        # 递归扫描所有文件
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # 跳过符号链接避免循环
                    if os.path.islink(file_path):
                        continue
                        
                    result = self.scan_file(file_path, deep_scan)
                    results.append(result)
                except Exception as e:
                    self.log(f"扫描文件{file_path}失败: {str(e)}", "ERROR")
                    # 记录单个文件扫描错误
                    error_result = {
                        "file_path": file_path,
                        "file_name": file,
                        "status": "error",
                        "error_message": str(e),
                        "timestamp": datetime.datetime.now()
                    }
                    results.append(error_result)
                    self.scan_results.append(error_result)
        
        self.log(f"目录扫描完成: {dir_path}，共扫描{len(results)}个文件")
        # 确保所有结果都导出到CSV
        csv_path = self.result_exporter.export_to_csv(results)
        self.log(f"扫描结果已保存至CSV: {csv_path}", "INFO")
        return results
    
    def extract_samples(self, quarantine: bool = True) -> List[str]:
        """提取可疑样本并保存到samples目录"""
        samples = []
        for result in self.scan_results:
            if result.get("is_malicious", False):
                try:
                    # 构建样本文件名: 哈希_原文件名
                    sample_name = f"{result.get('file_hash', '')[:8]}_{result.get('file_name', '')}"
                    sample_path = os.path.join(SAMPLES_DIR, sample_name)
                    
                    # 复制文件
                    shutil.copy2(result.get("file_path", ""), sample_path)
                    samples.append(sample_path)
                    self.log(f"已提取样本: {sample_path}")
                    
                    # 如果需要隔离，移动到隔离区
                    if quarantine and result.get("file_path", "") != sample_path:
                        self.quarantine_file(result.get("file_path", ""))
                except Exception as e:
                    self.log(f"提取样本{result.get('file_path', '')}失败: {str(e)}", "ERROR")
        
        # 打包样本
        if samples:
            zip_path = os.path.join(SAMPLES_DIR, f"samples_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
            try:
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for sample in samples:
                        zf.write(sample, os.path.basename(sample))
                self.log(f"已打包样本到: {zip_path}")
            except Exception as e:
                self.log(f"打包样本失败: {str(e)}", "ERROR")
        
        return samples
    
    def quarantine_file(self, file_path: str) -> Tuple[bool, str]:
        """隔离文件到隔离区"""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return False, "文件不存在"
            
        try:
            # 生成唯一文件名
            file_hash = self.calculate_file_hash(file_path)
            file_name = f"{file_hash[:8]}_{os.path.basename(file_path)}"
            quarantine_path = os.path.join(QUARANTINE_DIR, file_name)
            
            # 移动文件到隔离区
            shutil.move(file_path, quarantine_path)
            
            # 记录隔离信息
            with open(self.quarantine_log, "r", encoding="utf-8") as f:
                log_data = json.load(f)
            
            log_entry = {
                "original_path": file_path,
                "quarantine_path": quarantine_path,
                "timestamp": datetime.datetime.now().isoformat(),
                "file_hash": file_hash,
                "status": "quarantined"
            }
            
            log_data.append(log_entry)
            
            with open(self.quarantine_log, "w", encoding="utf-8") as f:
                json.dump(log_data, f, ensure_ascii=False, indent=2)
            
            self.log(f"文件已隔离: {file_path} -> {quarantine_path}")
            return True, quarantine_path
        except Exception as e:
            self.log(f"隔离文件{file_path}失败: {str(e)}", "ERROR")
            return False, str(e)
    
    def restore_file(self, quarantine_entry: Dict) -> Tuple[bool, str]:
        """从隔离区恢复文件"""
        try:
            quarantine_path = quarantine_entry.get("quarantine_path", "")
            original_path = quarantine_entry.get("original_path", "")
            
            if not os.path.exists(quarantine_path):
                return False, "隔离文件不存在"
            
            # 确保原始目录存在
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            # 如果原始路径已存在文件，添加后缀
            if os.path.exists(original_path):
                name, ext = os.path.splitext(original_path)
                original_path = f"{name}_restored{ext}"
            
            # 移动文件回原始位置
            shutil.move(quarantine_path, original_path)
            
            # 更新隔离日志
            with open(self.quarantine_log, "r", encoding="utf-8") as f:
                log_data = json.load(f)
            
            for entry in log_data:
                if entry.get("quarantine_path", "") == quarantine_path:
                    entry["status"] = "restored"
                    entry["restored_path"] = original_path
                    entry["restore_timestamp"] = datetime.datetime.now().isoformat()
                    break
            
            with open(self.quarantine_log, "w", encoding="utf-8") as f:
                json.dump(log_data, f, ensure_ascii=False, indent=2)
            
            self.log(f"文件已恢复: {quarantine_path} -> {original_path}")
            return True, original_path
        except Exception as e:
            self.log(f"恢复文件失败: {str(e)}", "ERROR")
            return False, str(e)
    
    def get_quarantined_files(self) -> List[Dict]:
        """获取所有隔离文件"""
        try:
            with open(self.quarantine_log, "r", encoding="utf-8") as f:
                log_data = json.load(f)
            return log_data
        except Exception as e:
            self.log(f"获取隔离文件列表失败: {str(e)}", "ERROR")
            return []
    
    def submit_samples_to_sandbox(self, intel_source: str = "all") -> List[Dict]:
        """将提取的样本提交到威胁情报中心沙盒"""
        results = []
        sample_files = glob.glob(os.path.join(SAMPLES_DIR, "*"))
        
        if not sample_files:
            self.log("没有可提交的样本文件")
            return results
            
        # 确定要提交的情报中心
        clients = []
        if intel_source == "all":
            clients = list(self.intel_clients.values())
        elif intel_source in self.intel_clients:
            clients = [self.intel_clients[intel_source]]
        
        for client in clients:
            self.log(f"开始向{client.name}提交样本...")
            for sample in sample_files:
                if os.path.isfile(sample) and not sample.endswith(".zip"):  # 不提交zip包
                    result = client.upload_file(sample)
                    result["sample"] = sample
                    results.append(result)
                    status = "成功" if result["status"] == "success" else "失败"
                    self.log(f"向{client.name}提交样本{os.path.basename(sample)}: {status}")
        
        return results
    
    def full_system_scan(self, deep_scan: bool = False) -> Dict:
        """全系统扫描"""
        start_time = datetime.datetime.now()
        self.log("开始全系统扫描...")
        
        # 确定要扫描的关键目录
        scan_dirs = []
        if IS_WINDOWS:
            scan_dirs = [
                "C:\\Program Files",
                "C:\\Program Files (x86)",
                "C:\\Users",
                "C:\\Windows\\Temp",
                os.environ.get("APPDATA", ""),
                os.environ.get("LOCALAPPDATA", "")
            ]
        elif IS_LINUX:
            scan_dirs = [
                "/usr/bin",
                "/usr/sbin",
                "/bin",
                "/sbin",
                "/home",
                "/tmp",
                "/var/tmp"
            ]
        elif IS_MACOS:
            scan_dirs = [
                "/Applications",
                "/usr/bin",
                "/Users",
                "/private/tmp",
                "~/Library/Application Support"
            ]
        
        # 过滤不存在的目录
        scan_dirs = [d for d in scan_dirs if d and os.path.exists(d) and os.path.isdir(d)]
        
        # 扫描目录
        dir_results = []
        for dir_path in scan_dirs:
            results = self.scan_directory(dir_path, deep_scan)
            dir_results.extend(results)
        
        # 检查网络连接
        network_results = self.check_network_connections()
        
        # 检查高资源占用进程
        high_resource_processes = self.check_high_resource_processes()
        
        # 检查可疑进程
        processes = self.get_running_processes()
        malicious_processes = []
        for proc in processes:
            for sig in self.signatures:
                if not sig.is_active:
                    continue
                if proc["name"].lower() in [p.lower() for p in sig.process_names]:
                    malicious_processes.append(proc)
                    self.log(f"检测到可疑进程: {proc['name']} (PID: {proc['pid']})", "WARNING")
                    # 打印异常进程详细信息
                    self.print_anomaly_process(proc, network_results)
        
        end_time = datetime.datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        summary = {
            "start_time": start_time,
            "end_time": end_time,
            "duration": duration,
            "total_files_scanned": len(dir_results),
            "malicious_files_found": len([r for r in dir_results if r.get("is_malicious", False)]),
            "malicious_processes_found": len(malicious_processes),
            "high_resource_processes": len(high_resource_processes),
            "cross_border_connections_found": len(self.cross_border_connections)
        }
        
        self.log(f"全系统扫描完成，耗时{duration:.2f}秒")
        self.log(f"扫描摘要: 共扫描{summary['total_files_scanned']}个文件，发现{summary['malicious_files_found']}个恶意文件，"
                f"{summary['malicious_processes_found']}个可疑进程，{summary['high_resource_processes']}个高资源占用进程，"
                f"{summary['cross_border_connections_found']}个跨境连接")
        
        # 生成扫描报告
        report_path = os.path.join(
            REPORTS_DIR, 
            f"full_scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                report_data = {
                    "summary": summary,
                    "malicious_files": [r for r in dir_results if r.get("is_malicious", False)],
                    "malicious_processes": malicious_processes,
                    "high_resource_processes": high_resource_processes,
                    "cross_border_connections": self.cross_border_connections
                }
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            self.log(f"全系统扫描报告已保存到: {report_path}")
        except Exception as e:
            self.log(f"保存扫描报告失败: {str(e)}", "ERROR")
        
        # 确保所有结果都导出到CSV
        csv_path = self.result_exporter.export_to_csv(dir_results)
        self.log(f"扫描结果已保存至CSV: {csv_path}", "INFO")
        
        return {
            "summary": summary,
            "file_results": dir_results,
            "network_results": network_results,
            "process_results": malicious_processes,
            "high_resource_processes": high_resource_processes,
            "report_path": report_path
        }

# -------------------------- 命令行界面类 --------------------------
class CliInterface:
    """命令行界面交互类"""
    
    def __init__(self):
        self.scanner = PirsrcScanner()
        self.current_tab = 0  # 0: 扫描, 1: 网络, 2: 样本, 3: 特征, 4: 配置
        self.tabs = ["扫描", "网络监控", "样本管理", "病毒特征", "配置"]
        self.running = True
        self.load_config()
        
        # 页面状态
        self.scan_results = []
        self.network_connections = []
        self.status_message = "就绪"
    
    def load_config(self):
        """加载配置"""
        config_path = os.path.join(BASE_DIR, "intel_config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    for name, cfg in config.items():
                        if name in THREAT_INTEL_CONFIG:
                            THREAT_INTEL_CONFIG[name]["enabled"] = cfg.get("enabled", True)
                            THREAT_INTEL_CONFIG[name]["api_key"] = cfg.get("api_key", "")
                            
                            # 更新扫描器中的客户端配置
                            if name in self.scanner.intel_clients:
                                self.scanner.intel_clients[name].config["enabled"] = cfg.get("enabled", True)
                                self.scanner.intel_clients[name].config["api_key"] = cfg.get("api_key", "")
                                self.scanner.intel_clients[name].enabled = cfg.get("enabled", True)
                                self.scanner.intel_clients[name].api_key = cfg.get("api_key", "")
            except Exception as e:
                self.scanner.log(f"加载配置失败: {str(e)}", "ERROR")
    
    def save_config(self):
        """保存配置"""
        config_path = os.path.join(BASE_DIR, "intel_config.json")
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                save_config = {
                    name: {
                        "enabled": cfg["enabled"],
                        "api_key": cfg["api_key"]
                    } for name, cfg in THREAT_INTEL_CONFIG.items()
                }
                json.dump(save_config, f, ensure_ascii=False, indent=2)
            self.status_message = "配置已保存"
        except Exception as e:
            self.status_message = f"保存配置失败: {str(e)}"
    
    def print_header(self):
        """打印头部信息"""
        print("\n" + "="*80)
        print(f"{Color.BOLD}{Color.CYAN}pirsrc_scan 6.2 - 木马扫描工具{Color.RESET}")
        print(f"{Color.BOLD}作者: p1r07{Color.RESET}")
        print("-"*80)
        
        # 打印标签
        tab_str = "  ".join([
            f"{Color.REVERSE} {tab} {Color.RESET}" if i == self.current_tab else f" {tab} " 
            for i, tab in enumerate(self.tabs)
        ])
        print(tab_str)
        print("-"*80)
    
    def print_footer(self):
        """打印底部信息和状态"""
        print("-"*80)
        print(f"{Color.BOLD}状态: {self.status_message}{Color.RESET}")
        print(f"{Color.YELLOW}提示: 使用n(下一个)和p(上一个)切换标签，q退出，h显示帮助{Color.RESET}")
        print("="*80 + "\n")

    def print_help(self):
        """打印帮助信息"""
        self.clear_screen()
        self.print_header()
        print(f"{Color.BOLD}使用帮助:{Color.RESET}\n")
        print("导航:")
        print("  p     : 上一个标签页")
        print("  n     : 下一个标签页")
        print("  q     : 退出程序")
        print("  h     : 显示帮助\n")
        
        print("扫描标签:")
        print("  1     : 快速扫描系统")
        print("  2     : 深度扫描系统")
        print("  3     : 扫描指定文件")
        print("  4     : 扫描指定目录\n")
        
        print("网络监控标签:")
        print("  1     : 刷新网络连接")
        print("  2     : 显示跨境连接报告")
        print("  3     : 分析异常连接\n")
        
        print("样本管理标签:")
        print("  1     : 提取可疑样本")
        print("  2     : 查看隔离文件")
        print("  3     : 恢复隔离文件")
        print("  4     : 提交样本到威胁情报中心\n")
        
        print("病毒特征标签:")
        print("  1     : 查看所有特征")
        print("  2     : 导入新特征")
        print("  3     : 导出特征库")
        print("  4     : 添加自定义特征\n")
        
        print("配置标签:")
        print("  1     : 启用/禁用威胁情报源")
        print("  2     : 设置API密钥")
        print("  3     : 保存配置\n")
        
        input(f"{Color.CYAN}按Enter键返回...{Color.RESET}")

    def clear_screen(self):
        """清屏"""
        if IS_WINDOWS:
            os.system('cls')
        else:
            os.system('clear')

    def handle_scan_tab(self, key):
        """处理扫描标签的输入"""
        if key == '1':
            self.status_message = "正在进行快速扫描..."
            self.clear_screen()
            self.print_header()
            result = self.scanner.full_system_scan(deep_scan=False)
            self.scan_results = result["file_results"]
            # 明确提示CSV保存路径
            self.status_message = f"快速扫描完成，发现{result['summary']['malicious_files_found']}个恶意文件，结果已保存至CSV"
        elif key == '2':
            self.status_message = "正在进行深度扫描..."
            self.clear_screen()
            self.print_header()
            result = self.scanner.full_system_scan(deep_scan=True)
            self.scan_results = result["file_results"]
            # 明确提示CSV保存路径
            self.status_message = f"深度扫描完成，发现{result['summary']['malicious_files_found']}个恶意文件，结果已保存至CSV"
        elif key == '3':
            self.clear_screen()
            self.print_header()
            file_path = input("请输入要扫描的文件路径: ")
            if file_path:
                self.status_message = f"正在扫描文件: {file_path}"
                result = self.scanner.scan_file(file_path)
                self.scan_results = [result]
                status = "恶意" if result["is_malicious"] else "正常"
                self.status_message = f"文件扫描完成: {status}，结果已保存至CSV"
        elif key == '4':
            self.clear_screen()
            self.print_header()
            dir_path = input("请输入要扫描的目录路径: ")
            if dir_path:
                self.status_message = f"正在扫描目录: {dir_path}"
                self.scan_results = self.scanner.scan_directory(dir_path)
                malicious = len([r for r in self.scan_results if r.get("is_malicious", False)])
                self.status_message = f"目录扫描完成，发现{malicious}个恶意文件，结果已保存至CSV"

    def handle_network_tab(self, key):
        """处理网络监控标签的输入"""
        if key == '1':
            self.status_message = "正在刷新网络连接..."
            self.network_connections = self.scanner.check_network_connections()
            self.status_message = f"发现{len(self.network_connections)}个网络连接，{len(self.scanner.cross_border_connections)}个跨境连接"
        elif key == '2':
            self.clear_screen()
            self.print_header()
            print(f"{Color.BOLD}跨境连接报告:{Color.RESET}\n")
            if self.scanner.cross_border_connections:
                for i, conn in enumerate(self.scanner.cross_border_connections[:10]):  # 只显示前10个
                    proc_name = conn['process_info']['name'] if conn['process_info'] else "未知"
                    print(f"{i+1}. IP: {conn['remote_ip']}, 进程: {proc_name}, 时间: {conn['timestamp'].strftime('%H:%M:%S')}")
                if len(self.scanner.cross_border_connections) > 10:
                    print(f"... 还有{len(self.scanner.cross_border_connections)-10}个连接未显示")
            else:
                print("未发现跨境连接")
            input(f"\n{Color.CYAN}按Enter键返回...{Color.RESET}")
        elif key == '3':
            if self.network_connections:
                self.clear_screen()
                self.print_header()
                print(f"{Color.BOLD}选择要分析的连接 (1-{len(self.network_connections)}):{Color.RESET}")
                for i, conn in enumerate(self.network_connections[:10]):
                    proc_name = conn['process_info']['name'] if conn['process_info'] else "未知"
                    print(f"{i+1}. {conn['remote_ip']}:{conn['remote_port']} - {proc_name}")
                try:
                    choice = int(input("请输入编号: ")) - 1
                    if 0 <= choice < len(self.network_connections):
                        conn = self.network_connections[choice]
                        self.clear_screen()
                        self.print_header()
                        print(f"{Color.BOLD}连接详情:{Color.RESET}")
                        print(f"远程IP: {conn['remote_ip']}:{conn['remote_port']}")
                        print(f"位置: {conn['country']}")
                        print(f"进程: {conn['process_info']['name'] if conn['process_info'] else '未知'} (PID: {conn['pid']})")
                        print(f"\n{Color.BOLD}威胁情报分析:{Color.RESET}")
                        for report in conn['ip_reports']:
                            if report['status'] == 'success':
                                if 'positives' in report:
                                    print(f"{report['source']}: {report['positives']}/{report['total']} 引擎报毒")
                                elif 'judgments' in report and report['judgments']:
                                    print(f"{report['source']}: {report['judgments'][0]['judgment']}")
                            else:
                                print(f"{report['source']}: {report['message']}")
                    else:
                        self.status_message = "无效的选择"
                except ValueError:
                    self.status_message = "请输入有效的数字"
                input(f"\n{Color.CYAN}按Enter键返回...{Color.RESET}")
            else:
                self.status_message = "没有网络连接数据，请先刷新"

    def handle_samples_tab(self, key):
        """处理样本管理标签的输入"""
        if key == '1':
            self.status_message = "正在提取可疑样本..."
            samples = self.scanner.extract_samples()
            self.status_message = f"已提取{len(samples)}个可疑样本"
        elif key == '2':
            quarantined = self.scanner.get_quarantined_files()
            self.clear_screen()
            self.print_header()
            print(f"{Color.BOLD}隔离文件列表:{Color.RESET}\n")
            if quarantined:
                for i, entry in enumerate(quarantined):
                    status = "已隔离" if entry["status"] == "quarantined" else "已恢复"
                    print(f"{i+1}. {os.path.basename(entry['original_path'])} - {status}")
                    print(f"   原始路径: {entry['original_path']}")
                    print(f"   隔离时间: {entry['timestamp'].split('T')[0]} {entry['timestamp'].split('T')[1].split('.')[0]}\n")
            else:
                print("没有隔离的文件")
            input(f"{Color.CYAN}按Enter键返回...{Color.RESET}")
        elif key == '3':
            quarantined = self.scanner.get_quarantined_files()
            active_quarantined = [e for e in quarantined if e.get("status") == "quarantined"]
            if active_quarantined:
                self.clear_screen()
                self.print_header()
                print(f"{Color.BOLD}选择要恢复的文件 (1-{len(active_quarantined)}):{Color.RESET}")
                for i, entry in enumerate(active_quarantined):
                    print(f"{i+1}. {os.path.basename(entry['original_path'])}")
                    print(f"   隔离时间: {entry['timestamp'].split('T')[0]} {entry['timestamp'].split('T')[1].split('.')[0]}\n")
                try:
                    choice = int(input("请输入编号: ")) - 1
                    if 0 <= choice < len(active_quarantined):
                        success, path = self.scanner.restore_file(active_quarantined[choice])
                        if success:
                            self.status_message = f"文件已恢复至: {path}"
                        else:
                            self.status_message = f"恢复失败: {path}"
                    else:
                        self.status_message = "无效的选择"
                except ValueError:
                    self.status_message = "请输入有效的数字"
            else:
                self.status_message = "没有可恢复的隔离文件"
        elif key == '4':
            self.clear_screen()
            self.print_header()
            print(f"{Color.BOLD}选择要提交的威胁情报中心:{Color.RESET}")
            print("1. 全部")
            for i, name in enumerate(self.scanner.intel_clients.keys(), 2):
                print(f"{i}. {name}")
            try:
                choice = int(input("请输入编号: "))
                sources = list(self.scanner.intel_clients.keys())
                if choice == 1:
                    results = self.scanner.submit_samples_to_sandbox("all")
                elif 2 <= choice <= len(sources) + 1:
                    results = self.scanner.submit_samples_to_sandbox(sources[choice-2])
                else:
                    self.status_message = "无效的选择"
                    return
                
                success = sum(1 for r in results if r["status"] == "success")
                self.status_message = f"样本提交完成，成功{success}/{len(results)}个"
            except ValueError:
                self.status_message = "请输入有效的数字"

    def handle_signatures_tab(self, key):
        """处理病毒特征标签的输入"""
        if key == '1':
            self.clear_screen()
            self.print_header()
            print(f"{Color.BOLD}病毒特征列表 ({len(self.scanner.signatures)}):{Color.RESET}\n")
            for sig in self.scanner.signatures:
                status = "启用" if sig.is_active else "禁用"
                print(f"{sig.signature_id} - {sig.name} ({status})")
                print(f"威胁级别: {'★' * sig.threat_level}{'☆' * (5 - sig.threat_level)}")
                print(f"描述: {sig.description[:100]}{'...' if len(sig.description) > 100 else ''}\n")
            input(f"{Color.CYAN}按Enter键返回...{Color.RESET}")
        elif key == '2':
            self.clear_screen()
            self.print_header()
            file_path = input("请输入特征文件路径: ")
            if file_path and os.path.exists(file_path):
                merge = input("是否合并到现有特征库? (y/n): ").lower() == 'y'
                success = self.scanner.load_signatures(file_path)
                self.status_message = "特征导入成功" if success else "特征导入失败"
            else:
                self.status_message = "文件不存在"
        elif key == '3':
            self.clear_screen()
            self.print_header()
            file_path = input("请输入保存路径 (留空使用默认路径): ")
            path = self.scanner.save_signatures(file_path if file_path else None)
            self.status_message = f"特征已导出至: {path}" if path else "特征导出失败"
        elif key == '4':
            self.clear_screen()
            self.print_header()
            print(f"{Color.BOLD}添加自定义病毒特征:{Color.RESET}\n")
            try:
                sig_id = input("特征ID: ")
                name = input("特征名称: ")
                desc = input("特征描述: ")
                file_names = input("关联文件名 (逗号分隔): ").split(',')
                file_names = [n.strip() for n in file_names if n.strip()]
                
                sig = VirusSignature(
                    signature_id=sig_id,
                    name=name,
                    description=desc,
                    file_names=file_names,
                    file_hashes=[],
                    file_sizes=[],
                    registry_paths=[],
                    process_names=[],
                    network_indicators=[],
                    file_paths=[],
                    creation_date=datetime.datetime.now()
                )
                
                self.scanner.add_signature(sig)
                self.status_message = f"已添加自定义特征: {name}"
            except Exception as e:
                self.status_message = f"添加特征失败: {str(e)}"

    def handle_config_tab(self, key):
        """处理配置标签的输入"""
        if key == '1':
            self.clear_screen()
            self.print_header()
            print(f"{Color.BOLD}威胁情报源开关:{Color.RESET}\n")
            for i, (name, cfg) in enumerate(THREAT_INTEL_CONFIG.items(), 1):
                status = "启用" if cfg["enabled"] else "禁用"
                color = Color.GREEN if cfg["enabled"] else Color.RED
                print(f"{i}. {name}: {color}{status}{Color.RESET}")
            
            try:
                choice = int(input("\n请输入要切换状态的编号: ")) - 1
                if 0 <= choice < len(THREAT_INTEL_CONFIG):
                    names = list(THREAT_INTEL_CONFIG.keys())
                    THREAT_INTEL_CONFIG[names[choice]]["enabled"] = not THREAT_INTEL_CONFIG[names[choice]]["enabled"]
                    # 更新扫描器配置
                    self.scanner.intel_clients[names[choice]].enabled = THREAT_INTEL_CONFIG[names[choice]]["enabled"]
                    self.status_message = f"{names[choice]}已{'启用' if THREAT_INTEL_CONFIG[names[choice]]['enabled'] else '禁用'}"
                else:
                    self.status_message = "无效的选择"
            except ValueError:
                self.status_message = "请输入有效的数字"
        elif key == '2':
            self.clear_screen()
            self.print_header()
            print(f"{Color.BOLD}设置API密钥:{Color.RESET}\n")
            for i, (name, cfg) in enumerate(THREAT_INTEL_CONFIG.items(), 1):
                key_display = cfg["api_key"][:4] + "..." if cfg["api_key"] else "未设置"
                print(f"{i}. {name}: {key_display}")
            
            try:
                choice = int(input("\n请输入要设置的编号: ")) - 1
                if 0 <= choice < len(THREAT_INTEL_CONFIG):
                    names = list(THREAT_INTEL_CONFIG.keys())
                    new_key = input(f"请输入{names[choice]}的API密钥: ")
                    THREAT_INTEL_CONFIG[names[choice]]["api_key"] = new_key
                    # 更新扫描器配置
                    self.scanner.intel_clients[names[choice]].api_key = new_key
                    self.status_message = f"{names[choice]}的API密钥已更新"
                else:
                    self.status_message = "无效的选择"
            except ValueError:
                self.status_message = "请输入有效的数字"
        elif key == '3':
            self.save_config()

    def render_current_tab(self):
        """渲染当前标签页内容"""
        # 确保Color类已正确定义且包含所需属性
        if not hasattr(Color, 'BOLD') or not hasattr(Color, 'RESET'):
            raise AttributeError("Color类缺少必要的属性定义")

        if self.current_tab == 0:  # 扫描标签
            print(f"{Color.BOLD}扫描选项:{Color.RESET}")
            print("1. 快速扫描系统 (推荐)")
            print("2. 深度扫描系统 (耗时较长)")
            print("3. 扫描指定文件")
            print("4. 扫描指定目录\n")
            
            # 安全检查scan_results属性
            if hasattr(self, 'scan_results') and isinstance(self.scan_results, list) and self.scan_results:
                print(f"{Color.BOLD}最近扫描结果 ({len(self.scan_results)}个文件):{Color.RESET}")
                # 过滤恶意文件，使用get方法避免KeyError
                malicious = [r for r in self.scan_results if isinstance(r, dict) and r.get("is_malicious", False)]
                
                if malicious:
                    # 确保RED颜色已定义
                    if hasattr(Color, 'RED'):
                        print(f"{Color.RED}发现{len(malicious)}个恶意文件:{Color.RESET}")
                    else:
                        print(f"发现{len(malicious)}个恶意文件:")
                    
                    # 只显示前5个结果
                    for r in malicious[:5]:
                        print(f"- {r.get('file_path', '未知路径')}")
                        signatures = r.get('matched_signatures', [])
                        # 处理签名信息
                        threat_names = []
                        for s in signatures[:2]:
                            if isinstance(s, dict):
                                threat_names.append(s.get('name', '未知威胁'))
                            else:
                                threat_names.append('无效威胁信息')
                        print(f"  威胁: {', '.join(threat_names)}")
                else:
                    # 确保GREEN颜色已定义
                    if hasattr(Color, 'GREEN'):
                        print(f"{Color.GREEN}未发现恶意文件{Color.RESET}")
                    else:
                        print("未发现恶意文件")
        
        elif self.current_tab == 1:  # 网络监控标签
            print(f"{Color.BOLD}网络监控选项:{Color.RESET}")
            print("1. 刷新网络连接")
            print("2. 显示跨境连接报告")
            print("3. 分析异常连接\n")
            
            # 安全检查network_connections属性
            if hasattr(self, 'network_connections') and isinstance(self.network_connections, list) and self.network_connections:
                print(f"{Color.BOLD}网络连接概览:{Color.RESET}")
                print(f"总连接数: {len(self.network_connections)}")
                
                # 计算跨境连接数，增加多重安全检查
                cross_border_count = 0# 计算跨境连接数，增加多重安全检查
            cross_border_count = 0
            for conn in self.network_connections:
                if isinstance(conn, dict) and conn.get("is_overseas", False):
                    cross_border_count += 1
            
            # 确保YELLOW颜色已定义
            if hasattr(Color, 'YELLOW'):
                print(f"{Color.YELLOW}跨境连接数: {cross_border_count}{Color.RESET}")
            else:
                print(f"跨境连接数: {cross_border_count}")
            
            # 显示前3个跨境连接
            if cross_border_count > 0:
                print(f"\n{Color.BOLD}主要跨境连接:{Color.RESET}")
                count = 0
                for conn in self.network_connections:
                    if isinstance(conn, dict) and conn.get("is_overseas", False) and count < 3:
                        proc_info = conn.get("process_info", {})
                        proc_name = proc_info.get("name", "未知进程") if isinstance(proc_info, dict) else "未知进程"
                        print(f"- IP: {conn.get('remote_ip', '未知IP')}:{conn.get('remote_port', '未知端口')}")
                        print(f"  进程: {proc_name} (PID: {conn.get('pid', '未知')})")
                        print(f"  位置: {conn.get('country', '未知')}\n")
                        count += 1

        elif self.current_tab == 2:  # 样本管理标签
            print(f"{Color.BOLD}样本管理选项:{Color.RESET}")
            print("1. 提取可疑样本 (保存到samples目录)")
            print("2. 查看隔离文件列表")
            print("3. 恢复选中的隔离文件")
            print("4. 提交样本到威胁情报中心")
            print("5. 显示样本目录结构\n")  # 新增选项
            
            # 显示样本统计信息
            samples_dir = SAMPLES_DIR
            if os.path.exists(samples_dir) and os.path.isdir(samples_dir):
                sample_files = [f for f in os.listdir(samples_dir) if os.path.isfile(os.path.join(samples_dir, f))]
                zip_files = [f for f in sample_files if f.endswith(".zip")]
                raw_samples = [f for f in sample_files if not f.endswith(".zip")]
                
                print(f"{Color.BOLD}样本统计:{Color.RESET}")
                print(f"样本总数: {len(sample_files)}")
                print(f"原始样本: {len(raw_samples)}")
                print(f"打包样本: {len(zip_files)}")
            else:
                print(f"{Color.YELLOW}样本目录不存在或未创建{Color.RESET}")
                
            # 显示最近隔离的文件
            quarantined = self.scanner.get_quarantined_files()
            if quarantined and isinstance(quarantined, list):
                recent_quarantined = [e for e in quarantined if isinstance(e, dict) and e.get("status") == "quarantined"]
                if recent_quarantined:
                    print(f"\n{Color.BOLD}最近隔离文件 ({len(recent_quarantined)}):{Color.RESET}")
                    for entry in recent_quarantined[:3]:  # 只显示最近3个
                        print(f"- {os.path.basename(entry.get('original_path', '未知文件'))}")
                        print(f"  隔离时间: {entry.get('timestamp', '未知时间').split('T')[0]}")

        elif self.current_tab == 3:  # 病毒特征标签
            print(f"{Color.BOLD}病毒特征管理:{Color.RESET}")
            print("1. 查看所有病毒特征")
            print("2. 从JSON文件导入特征")
            print("3. 导出特征库到JSON文件")
            print("4. 添加自定义病毒特征\n")
            
            # 显示特征库统计
            if hasattr(self.scanner, 'signatures') and isinstance(self.scanner.signatures, list):
                total = len(self.scanner.signatures)
                active = sum(1 for sig in self.scanner.signatures if getattr(sig, 'is_active', False))
                threat_levels = [getattr(sig, 'threat_level', 0) for sig in self.scanner.signatures if hasattr(sig, 'threat_level')]
                avg_level = sum(threat_levels) / len(threat_levels) if threat_levels else 0
                
                print(f"{Color.BOLD}特征库统计:{Color.RESET}")
                print(f"总特征数: {total}")
                print(f"激活特征数: {active}")
                print(f"平均威胁级别: {avg_level:.1f}/5")
                
                # 显示主要威胁类型
                if total > 0:
                    print(f"\n{Color.BOLD}主要威胁类型:{Color.RESET}")
                    for sig in self.scanner.signatures[:3]:  # 显示前3个
                        print(f"- {getattr(sig, 'name', '未知威胁')} (级别: {getattr(sig, 'threat_level', 0)})")

        elif self.current_tab == 4:  # 配置标签
            print(f"{Color.BOLD}系统配置:{Color.RESET}")
            print("1. 启用/禁用威胁情报源")
            print("2. 设置威胁情报API密钥")
            print("3. 保存当前配置")
            print("4. 显示目录结构\n")  # 新增选项
            
            # 显示当前配置状态
            print(f"{Color.BOLD}威胁情报源状态:{Color.RESET}")
            for name, cfg in THREAT_INTEL_CONFIG.items():
                status = "启用" if cfg.get("enabled", False) else "禁用"
                key_status = "已设置" if cfg.get("api_key", "") else "未设置"
                color = Color.GREEN if cfg.get("enabled", False) else Color.RED
                print(f"- {name}: {color}{status}{Color.RESET}，API密钥: {key_status}")
            
            # 显示目录配置
            print(f"\n{Color.BOLD}工作目录:{Color.RESET}")
            print(f"报告目录: {REPORTS_DIR}")
            print(f"样本目录: {SAMPLES_DIR}")
            print(f"隔离目录: {QUARANTINE_DIR}")

    def print_directory_tree(self, root_dir, max_depth=3, show_files=True, highlight_recent=False, recent_files=None):
        """
        打印目录树结构
        :param root_dir: 根目录
        :param max_depth: 最大显示深度
        :param show_files: 是否显示文件
        :param highlight_recent: 是否高亮显示最近文件
        :param recent_files: 最近文件列表（用于高亮）
        """
        if not os.path.exists(root_dir) or not os.path.isdir(root_dir):
            print(f"{Color.RED}目录不存在: {root_dir}{Color.RESET}")
            return
            
        # 确保recent_files是集合类型便于查找
        recent_set = set(recent_files) if recent_files and isinstance(recent_files, (list, set)) else set()
            
        print(f"\n{Color.BOLD}目录结构: {root_dir}{Color.RESET}")
        print(f"显示深度: {max_depth}，{'显示文件' if show_files else '仅显示目录'}")
        print("----------------------------------------")
        
        for root, dirs, files in os.walk(root_dir):
            # 计算当前深度
            depth = root[len(root_dir):].count(os.sep)
            if depth > max_depth:
                continue
                
            # 构建前缀
            prefix = "│   " * (depth - 1) + "├── " if depth > 0 else ""
            print(f"{prefix}{os.path.basename(root)}/")
            
            # 显示文件
            if show_files and depth < max_depth:
                # 对文件进行排序，最近的扫描结果排在前面
                file_paths = [os.path.join(root, f) for f in files]
                file_paths.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                
                for i, file_path in enumerate(file_paths[:5]):  # 每个目录最多显示5个文件
                    file = os.path.basename(file_path)
                    file_prefix = "│   " * depth + "├── "
                    
                    # 如果是最近的扫描结果文件，高亮显示
                    if highlight_recent and file in recent_set:
                        print(f"{file_prefix}{Color.GREEN}{file}{Color.RESET}")
                    else:
                        print(f"{file_prefix}{file}")
                    
                if len(files) > 5:
                    file_prefix = "│   " * depth + "└── "
                    print(f"{file_prefix}... 还有 {len(files) - 5} 个文件")

    def handle_scan_complete(self, scan_results):
        """处理扫描完成后的操作，包括显示结果和结果目录"""
        # 显示扫描结果摘要
        threats_found = len(scan_results.get('threats', []))
        if threats_found > 0:
            print(f"\n{Color.RED}{Color.BOLD}扫描完成! 发现 {threats_found} 个威胁{Color.RESET}")
        else:
            print(f"\n{Color.GREEN}{Color.BOLD}扫描完成! 未发现威胁{Color.RESET}")
        
        # 明确显示扫描结果存储位置
        print(f"{Color.CYAN}扫描结果存储位置: {REPORTS_DIR}{Color.RESET}")
        
        # 获取并显示最近的扫描报告文件
        report_files = []
        if os.path.exists(REPORTS_DIR) and os.path.isdir(REPORTS_DIR):
            report_files = [f for f in os.listdir(REPORTS_DIR) 
                          if os.path.isfile(os.path.join(REPORTS_DIR, f)) 
                          and f.startswith('scan_report_')]
        
        # 自动显示扫描结果目录
        print(f"\n{Color.BOLD}扫描结果目录内容:{Color.RESET}")
        self.print_directory_tree(
            REPORTS_DIR, 
            max_depth=2, 
            highlight_recent=True, 
            recent_files=report_files[:3]  # 高亮最近3个报告文件
        )
        
        # 提示用户可以查看详细报告
        if report_files:
            latest_report = max(report_files, key=lambda x: os.path.getmtime(os.path.join(REPORTS_DIR, x)))
            latest_report_path = os.path.join(REPORTS_DIR, latest_report)
            print(f"\n{Color.YELLOW}提示: 最新报告完整路径为 {latest_report_path}{Color.RESET}")
            print(f"{Color.YELLOW}可直接访问该路径查看详细扫描结果{Color.RESET}")
        
        input("\n按回车键返回主菜单...")

    def run(self):
        """运行命令行界面"""
        # 显示欢迎信息和火焰特效
        print(HACKER_ICON_ASCII)
        FlameEffect.print_flame()
        self.scanner.log("欢迎使用pirsrc_scan 6.2 - 高级木马扫描工具")
        self.scanner.log("融合了核心功能和扩展模块，支持自动导出CSV和病毒特征管理")
        
        while self.running:
            self.clear_screen()
            self.print_header()
            self.render_current_tab()
            self.print_footer()
            
            # 获取用户输入
            key = input("请输入命令: ").strip().lower()
            
            # 全局命令
            if key == 'q':
                self.running = False
                self.scanner.log("程序已退出")
            elif key == 'n':
                self.current_tab = (self.current_tab + 1) % len(self.tabs)
                self.status_message = f"已切换到{self.tabs[self.current_tab]}标签"
            elif key == 'p':
                self.current_tab = (self.current_tab - 1) % len(self.tabs)
                self.status_message = f"已切换到{self.tabs[self.current_tab]}标签"
            elif key == 'h':
                self.print_help()
            elif key == 'd':  # 全局目录查看命令
                self.print_directory_tree(os.getcwd())
                input("\n按回车键继续...")
            else:
                # 处理当前标签的命令
                if self.current_tab == 0:
                    # 扫描标签 - 假设1是开始扫描命令
                    if key == '1':
                        print(f"{Color.BOLD}开始执行系统扫描...{Color.RESET}")
                        # 执行扫描并获取结果
                        scan_results = self.scanner.perform_scan()
                        # 扫描完成后显示结果和目录
                        self.handle_scan_complete(scan_results)
                    else:
                        self.handle_scan_tab(key)
                elif self.current_tab == 1:
                    self.handle_network_tab(key)
                elif self.current_tab == 2:
                    # 样本管理标签处理目录命令
                    if key == '5':
                        self.print_directory_tree(SAMPLES_DIR)
                        input("\n按回车键继续...")
                    else:
                        self.handle_samples_tab(key)
                elif self.current_tab == 3:
                    self.handle_signatures_tab(key)
                elif self.current_tab == 4:
                    # 配置标签处理目录命令
                    if key == '4':
                        print(f"{Color.BOLD}1. 报告目录")
                        print(f"2. 样本目录")
                        print(f"3. 隔离目录")
                        print(f"4. 所有目录{Color.RESET}")
                        sub_key = input("请选择要查看的目录: ").strip()
                        if sub_key == '1':
                            self.print_directory_tree(REPORTS_DIR)
                        elif sub_key == '2':
                            self.print_directory_tree(SAMPLES_DIR)
                        elif sub_key == '3':
                            self.print_directory_tree(QUARANTINE_DIR)
                        elif sub_key == '4':
                            self.print_directory_tree(REPORTS_DIR)
                            self.print_directory_tree(SAMPLES_DIR)
                            self.print_directory_tree(QUARANTINE_DIR)
                        input("\n按回车键继续...")
                    else:
                        self.handle_config_tab(key)
                else:
                    self.status_message = "无效命令，请输入h查看帮助"

# -------------------------- 主程序入口 --------------------------
if __name__ == "__main__":
    try:
        # 检查运行权限
        if IS_WINDOWS:
            # Windows下尝试获取管理员权限
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    print("提示: 以管理员权限运行可获得更完整的扫描结果")
            except:
                pass
        else:
            # Linux/macOS下检查是否为root用户
            if os.geteuid() != 0:
                print("警告: 非root用户可能无法访问部分系统文件和进程信息")
        
        # 启动命令行界面
        cli = CliInterface()
        cli.run()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        print(f"程序运行出错: {str(e)}")
        # 记录错误日志
        error_log = os.path.join(REPORTS_DIR, f"error_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(error_log, "w", encoding="utf-8") as f:
            f.write(f"错误时间: {datetime.datetime.now()}\n")
            f.write(f"错误信息: {str(e)}\n")
            import traceback
            f.write(f"堆栈跟踪: {traceback.format_exc()}\n")
        print(f"错误详情已记录到: {error_log}")
    
