#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pirsrc_scan 6.1
# Author: p1r07
# 兼容Python 3.10，无特殊依赖，纯原生库实现

import os
import re
import sys
import json
import zipfile
import hashlib
import socket
import platform
import ipaddress
import subprocess
import threading
import time
import shutil
import csv
import base64
import zlib
import random
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Set, Callable
import tempfile
import glob
import psutil
import stat

# 确保中文显示正常
if platform.system() == "Windows":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        # 设置控制台编码
        os.system("chcp 65001 >nul 2>&1")
    except:
        pass

# 系统类型判断
SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX = SYSTEM == "Linux"
IS_MACOS = SYSTEM == "Darwin"

# 确保临时目录存在
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_DIR = os.path.join(BASE_DIR, "tmp")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")  # 隔离区
os.makedirs(TEMP_DIR, exist_ok=True)
os.makedirs(SAMPLES_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# 火焰主题颜色配置 (命令行可用)
class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"
    REVERSE = "\033[7m"

    @staticmethod
    def support_color():
        """判断终端是否支持颜色"""
        if not hasattr(sys.stdout, 'isatty'):
            return False
        if not sys.stdout.isatty():
            return False
        if platform.system() == 'Windows':
            return True
        return True

# 威胁情报中心API配置
THREAT_INTEL_CONFIG = {
    "virustotal": {
        "name": "VirusTotal",
        "api_url": "https://www.virustotal.com/vtapi/v2/file/report",
        "upload_url": "https://www.virustotal.com/vtapi/v2/file/scan",
        "api_key": "",  # 用户需要填写自己的API密钥
        "enabled": True
    },
    "threatbook": {
        "name": "微步在线",
        "api_url": "https://s.threatbook.cn/api/v3/file/report",
        "upload_url": "https://s.threatbook.cn/api/v3/file/upload",
        "api_key": "",  # 用户需要填写自己的API密钥
        "enabled": True
    },
    "qianxin": {
        "name": "奇安信",
        "api_url": "https://ti.qianxin.com/v2/file/report",
        "upload_url": "https://ti.qianxin.com/v2/file/upload",
        "api_key": "",  # 用户需要填写自己的API密钥
        "enabled": True
    },
    "nsfocus": {
        "name": "绿盟",
        "api_url": "https://ti.nsfocus.com/v1/file/report",
        "upload_url": "https://ti.nsfocus.com/v1/file/upload",
        "api_key": "",  # 用户需要填写自己的API密钥
        "enabled": True
    }
}

# 中国IP段（用于检测跨境连接）
CHINA_IP_RANGES = [
    "1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "1.0.32.0/19",
    "1.1.0.0/24", "1.1.2.0/23", "1.1.4.0/22", "1.1.8.0/21",
    "101.0.0.0/15", "103.0.0.0/16", "110.0.0.0/15", "112.0.0.0/14",
    "114.0.0.0/15", "116.0.0.0/14", "120.0.0.0/13", "124.0.0.0/14",
    "180.0.0.0/15", "182.0.0.0/15", "202.0.0.0/16", "203.0.0.0/16"
]

# 常见正常进程列表（用于进程合法性判断）
COMMON_LEGIT_PROCESSES = {
    # 系统进程
    "system", "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "services.exe", "explorer.exe", "kernel32.dll", "ntdll.dll",
    
    # 常见办公软件
    "winword.exe", "excel.exe", "powerpoint.exe", "outlook.exe",
    "wps.exe", "et.exe", "wpp.exe", "notepad.exe", "wordpad.exe",
    
    # 浏览器
    "chrome.exe", "firefox.exe", "iexplore.exe", "edge.exe", 
    "safari.exe", "opera.exe",
    
    # 常见工具
    "taskmgr.exe", "regedit.exe", "cmd.exe", "powershell.exe",
    "terminal.exe", "gnome-terminal", "konsole",
    
    # 游戏进程示例
    "leagueclient.exe", "valorant.exe", "overwatch.exe",
    "csgo.exe", "pubg.exe", "minecraft.exe"
}

# 黑客图标（ASCII艺术）
HACKER_ICON_ASCII = """
   .--.
  |o_o |
  |:_/ |
 //   \ \\
(|     | )
/'\_   _/`\\
\___)=(___/
"""

# 病毒特征类（标准化特征）
@dataclass
class VirusSignature:
    """标准化的病毒特征类"""
    signature_id: str  # 特征ID
    name: str  # 病毒名称
    description: str  # 描述
    file_names: List[str]  # 关联文件名
    file_hashes: List[str]  # 关联哈希值
    file_sizes: List[int]  # 关联文件大小
    registry_paths: List[str]  # 关联注册表路径
    process_names: List[str]  # 关联进程名
    network_indicators: List[str]  # 关联网络指标（IP/域名）
    file_paths: List[str]  # 关联文件路径
    creation_date: datetime  # 创建日期
    is_active: bool  # 是否启用
    threat_level: int  # 威胁级别 1-5

# 默认病毒特征库（包含2025木马和银狐恶意样本特征）
DEFAULT_SIGNATURES = [
    VirusSignature(
        signature_id="sig_2025trojan",
        name="2025木马",
        description="2025木马是一种具有自删除功能的恶意软件，通过压缩包传播，会创建计划任务实现持久化",
        file_names=["2025.exe", "2025.rar", "SbieDll.bin", "SbieDll.dll", "SbieSvc.exe", "temp.key"],
        file_hashes=[],  # 可根据实际样本添加
        file_sizes=[31787 * 1024, 11834 * 1024, 271 * 1024, 118 * 1024, 2 * 1024],
        registry_paths=[
            "HKLM\\System\\CurrentControlSet", 
            "HKLM\\SOFTWARE"
        ],
        process_names=["2025.exe", "SbieSvc.exe", "svchost.exe"],  # svchost.exe为注入目标
        network_indicators=[
            "ec2-18-166-220-75.ap-east-1.compute.amazonaws.com",
            "18.166.220.75",
            "www.fapiaoshuiwuk.cn"
        ],
        file_paths=["C:\\Program Files\\Internet Explorer\\"],
        creation_date=datetime(2025, 5, 22),
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
        creation_date=datetime(2025, 5, 22),
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
                create_time = datetime.fromtimestamp(stat_info.st_ctime)
                modify_time = datetime.fromtimestamp(stat_info.st_mtime)
            else:
                # Unix系统没有创建时间，使用inode更改时间
                create_time = datetime.fromtimestamp(stat_info.st_ctime)
                modify_time = datetime.fromtimestamp(stat_info.st_mtime)
            
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
            f"sandbox_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
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
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        log_file = os.path.join(REPORTS_DIR, f"scan_log_{datetime.now().strftime('%Y%m%d')}.txt")
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
                print(f"创建时间: {datetime.fromtimestamp(stat_info.st_ctime)}")
                print(f"修改时间: {datetime.fromtimestamp(stat_info.st_mtime)}")
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
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                # 转换为可序列化的字典
                sig_list = []
                for sig in self.signatures:
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
                    sig_list.append(sig_dict)
                json.dump(sig_list, f, ensure_ascii=False, indent=2)
            self.log(f"病毒特征已保存到: {file_path}")
            return True
        except Exception as e:
            self.log(f"保存病毒特征失败: {str(e)}", "ERROR")
            return False
    
    def load_signatures(self, file_path: str) -> bool:
        """从文件加载病毒特征"""
        try:
            if not os.path.exists(file_path):
                self.log(f"病毒特征文件不存在: {file_path}", "ERROR")
                return False
                
            with open(file_path, "r", encoding="utf-8") as f:
                sig_list = json.load(f)
                
            self.signatures = []
            for sig_dict in sig_list:
                try:
                    signature = VirusSignature(
                        signature_id=sig_dict["signature_id"],
                        name=sig_dict["name"],
                        description=sig_dict["description"],
                        file_names=sig_dict["file_names"],
                        file_hashes=sig_dict["file_hashes"],
                        file_sizes=sig_dict["file_sizes"],
                        registry_paths=sig_dict["registry_paths"],
                        process_names=sig_dict["process_names"],
                        network_indicators=sig_dict["network_indicators"],
                        file_paths=sig_dict.get("file_paths", []),
                        creation_date=datetime.fromisoformat(sig_dict["creation_date"]),
                        is_active=sig_dict["is_active"],
                        threat_level=sig_dict.get("threat_level", 3)
                    )
                    self.signatures.append(signature)
                except Exception as e:
                    self.log(f"解析病毒特征失败: {str(e)}", "ERROR")
            
            self.log(f"已从{file_path}加载{len(self.signatures)}个病毒特征")
            return True
        except Exception as e:
            self.log(f"加载病毒特征失败: {str(e)}", "ERROR")
            return False
    
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
                        "timestamp": datetime.now()
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
        """扫描单个文件"""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return {"status": "error", "message": f"文件不存在: {file_path}"}
            
        result = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "file_type": self.file_identifier.get_file_type(file_path),
            "file_hash": self.calculate_file_hash(file_path),
            "is_malicious": False,
            "matched_signatures": [],
            "threat_intel_reports": [],
            "signature_verification": {"valid": False, "message": ""},
            "integrity_check": {"valid": False, "message": ""},
            "sandbox_analysis": None,
            "timestamp": datetime.now()
        }
        
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
        return result
    
    def scan_directory(self, dir_path: str, deep_scan: bool = False) -> List[Dict]:
        """扫描目录中的所有文件"""
        if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
            self.log(f"目录不存在: {dir_path}", "ERROR")
            return []
            
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
        
        self.log(f"目录扫描完成: {dir_path}，共扫描{len(results)}个文件")
        return results
    
    def extract_samples(self, quarantine: bool = True) -> List[str]:
        """提取可疑样本并保存到samples目录"""
        samples = []
        for result in self.scan_results:
            if result["is_malicious"]:
                try:
                    # 构建样本文件名: 哈希_原文件名
                    sample_name = f"{result['file_hash'][:8]}_{result['file_name']}"
                    sample_path = os.path.join(SAMPLES_DIR, sample_name)
                    
                    # 复制文件
                    shutil.copy2(result["file_path"], sample_path)
                    samples.append(sample_path)
                    self.log(f"已提取样本: {sample_path}")
                    
                    # 如果需要隔离，移动到隔离区
                    if quarantine and result["file_path"] != sample_path:
                        self.quarantine_file(result["file_path"])
                except Exception as e:
                    self.log(f"提取样本{result['file_path']}失败: {str(e)}", "ERROR")
        
        # 打包样本
        if samples:
            zip_path = os.path.join(SAMPLES_DIR, f"samples_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
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
                "timestamp": datetime.now().isoformat(),
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
            quarantine_path = quarantine_entry["quarantine_path"]
            original_path = quarantine_entry["original_path"]
            
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
                if entry["quarantine_path"] == quarantine_path:
                    entry["status"] = "restored"
                    entry["restored_path"] = original_path
                    entry["restore_timestamp"] = datetime.now().isoformat()
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
        start_time = datetime.now()
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
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        summary = {
            "start_time": start_time,
            "end_time": end_time,
            "duration": duration,
            "total_files_scanned": len(dir_results),
            "malicious_files_found": len([r for r in dir_results if r["is_malicious"]]),
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
            f"full_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                report_data = {
                    "summary": summary,
                    "malicious_files": [r for r in dir_results if r["is_malicious"]],
                    "malicious_processes": malicious_processes,
                    "high_resource_processes": high_resource_processes,
                    "cross_border_connections": self.cross_border_connections
                }
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            self.log(f"全系统扫描报告已保存到: {report_path}")
        except Exception as e:
            self.log(f"保存扫描报告失败: {str(e)}", "ERROR")
        
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
        print(f"{Color.BOLD}{Color.CYAN}pirsrc_scan 6.1 - 木马扫描工具{Color.RESET}")
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
        """打印底部信息"""
        print("-"*80)
        print(f"{Color.YELLOW}状态: {self.status_message}{Color.RESET}")
        print(f"{Color.CYAN}按数字键选择操作，n切换到下一页，p切换到上一页，q返回，ESC退出{Color.RESET}")
        print("="*80 + "\n")
    
    def clear_screen(self):
        """清屏"""
        os.system('cls' if IS_WINDOWS else 'clear')
    
    def wait_for_key(self, message: str = "按任意键继续..."):
        """等待用户按键"""
        input(f"\n{message}")
    
    def print_menu(self, menu_items: List[str]):
        """打印菜单选项"""
        print(f"{Color.BOLD}{Color.MAGENTA}操作菜单:{Color.RESET}")
        for i, item in enumerate(menu_items, 1):
            print(f"{Color.GREEN}{i}. {item}{Color.RESET}")
        print()
    
    def show_scan_tab(self):
        """显示扫描标签页"""
        self.print_header()
        
        menu_items = [
            "选择文件扫描",
            "选择目录扫描",
            "全系统快速扫描",
            "全系统深度扫描",
            "查看扫描结果"
        ]
        
        self.print_menu(menu_items)
        
        # 显示扫描结果
        if self.scan_results:
            print(f"{Color.BOLD}{Color.MAGENTA}最近扫描结果:{Color.RESET}")
            for i, result in enumerate(self.scan_results[:10]):
                status_color = Color.RED if result["is_malicious"] else Color.GREEN
                status = "恶意" if result["is_malicious"] else "正常"
                print(f"{i+1}. {os.path.basename(result['file_path'])} - {status_color}{status}{Color.RESET}")
            if len(self.scan_results) > 10:
                print(f"... 还有 {len(self.scan_results) - 10} 个结果未显示")
        else:
            print(f"{Color.YELLOW}暂无扫描结果，请开始扫描{Color.RESET}")
        
        self.print_footer()
    
    def show_network_tab(self):
        """显示网络监控标签页"""
        self.print_header()
        
        menu_items = [
            "刷新网络连接",
            "查看跨境连接报告",
            "导出连接报告"
        ]
        
        self.print_menu(menu_items)
        
        # 显示网络连接
        if self.network_connections:
            print(f"{Color.BOLD}{Color.MAGENTA}网络连接列表:{Color.RESET}")
            for i, conn in enumerate(self.network_connections[:10]):
                status_color = Color.RED if conn["is_overseas"] else Color.WHITE
                status = "跨境" if conn["is_overseas"] else "国内"
                proc_name = conn["process_info"]["name"] if conn["process_info"] else "未知"
                
                print(f"{i+1}. {conn['remote_ip']}:{conn['remote_port']} - {proc_name} - {status_color}{status}{Color.RESET}")
            if len(self.network_connections) > 10:
                print(f"... 还有 {len(self.network_connections) - 10} 个连接未显示")
        else:
            print(f"{Color.YELLOW}暂无网络连接信息，请刷新{Color.RESET}")
        
        self.print_footer()
    
    def show_sample_tab(self):
        """显示样本管理标签页"""
        self.print_header()
        
        menu_items = [
            "提取恶意样本",
            "提交样本到沙盒",
            "查看隔离文件",
            "恢复隔离文件"
        ]
        
        self.print_menu(menu_items)
        
        # 显示样本列表
        sample_files = glob.glob(os.path.join(SAMPLES_DIR, "*"))
        sample_files = [f for f in sample_files if os.path.isfile(f)]
        
        if sample_files:
            print(f"{Color.BOLD}{Color.MAGENTA}样本列表:{Color.RESET}")
            for i, sample in enumerate(sample_files[:10]):
                print(f"{i+1}. {os.path.basename(sample)}")
            if len(sample_files) > 10:
                print(f"... 还有 {len(sample_files) - 10} 个样本未显示")
        else:
            print(f"{Color.YELLOW}暂无样本文件{Color.RESET}")
        
        # 显示隔离文件
        quarantined = self.scanner.get_quarantined_files()
        quarantined = [q for q in quarantined if q["status"] == "quarantined"]
        
        if quarantined:
            print(f"\n{Color.BOLD}{Color.MAGENTA}隔离文件:{Color.RESET}")
            for i, item in enumerate(quarantined[:10]):
                print(f"{i+1}. {os.path.basename(item['original_path'])}")
            if len(quarantined) > 10:
                print(f"... 还有 {len(quarantined) - 10} 个隔离文件未显示")
        
        self.print_footer()
    
    def show_signature_tab(self):
        """显示病毒特征标签页"""
        self.print_header()
        
        menu_items = [
            "查看特征列表",
            "添加新特征",
            "加载特征库",
            "保存特征库"
        ]
        
        self.print_menu(menu_items)
        
        # 显示特征
        if self.scanner.signatures:
            print(f"{Color.BOLD}{Color.MAGENTA}病毒特征列表:{Color.RESET}")
            for i, sig in enumerate(self.scanner.signatures[:10]):
                status = "启用" if sig.is_active else "禁用"
                status_color = Color.GREEN if sig.is_active else Color.YELLOW
                
                print(f"{i+1}. {sig.name} - 威胁等级: {sig.threat_level}/5 - {status_color}{status}{Color.RESET}")
            if len(self.scanner.signatures) > 10:
                print(f"... 还有 {len(self.scanner.signatures) - 10} 个特征未显示")
        else:
            print(f"{Color.YELLOW}暂无病毒特征{Color.RESET}")
        
        self.print_footer()
    
    def show_config_tab(self):
        """显示配置标签页"""
        self.print_header()
        
        menu_items = [
            "保存配置"
        ]
        
        self.print_menu(menu_items)
        
        # 显示配置项
        print(f"{Color.BOLD}{Color.MAGENTA}威胁情报中心配置:{Color.RESET}")
        names = list(THREAT_INTEL_CONFIG.keys())
        for i, (name, cfg) in enumerate(THREAT_INTEL_CONFIG.items()):
            # 启用状态
            enabled_str = "启用" if cfg["enabled"] else "禁用"
            enabled_color = Color.GREEN if cfg["enabled"] else Color.YELLOW
            
            print(f"{i+1}. {cfg['name']}: {enabled_color}[{enabled_str}]{Color.RESET}")
            
            # API密钥（部分隐藏）
            api_key = cfg["api_key"]
            if api_key:
                key_display = api_key[:4] + "*" * (len(api_key) - 4) if len(api_key) > 4 else api_key
            else:
                key_display = "未设置"
                
            print(f"   API密钥: {key_display}\n")
        
        print(f"{Color.CYAN}按数字键切换对应情报中心的启用状态{Color.RESET}")
        print(f"{Color.CYAN}输入 'set [编号] [API密钥]' 设置API密钥（例如: set 1 your_api_key）{Color.RESET}")
        
        self.print_footer()
    
    def show_help(self):
        """显示帮助信息"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}{Color.CYAN}pirsrc_scan 使用帮助{Color.RESET}")
        print("-"*80)
        print("导航:")
        print("  n 或 右箭头: 切换到下一个标签页")
        print("  p 或 左箭头: 切换到上一个标签页")
        print("  q: 返回上一级")
        print("  ESC: 退出程序")
        print("\n扫描标签页:")
        print("  1: 选择文件扫描")
        print("  2: 选择目录扫描")
        print("  3: 全系统快速扫描")
        print("  4: 全系统深度扫描")
        print("  5: 查看扫描结果")
        print("\n网络监控标签页:")
        print("  1: 刷新网络连接")
        print("  2: 查看跨境连接报告")
        print("  3: 导出连接报告")
        print("\n样本管理标签页:")
        print("  1: 提取恶意样本")
        print("  2: 提交样本到沙盒")
        print("  3: 查看隔离文件")
        print("  4: 恢复隔离文件")
        print("\n病毒特征标签页:")
        print("  1: 查看特征列表")
        print("  2: 添加新特征")
        print("  3: 加载特征库")
        print("  4: 保存特征库")
        print("\n配置标签页:")
        print("  1: 保存配置")
        print("  数字键: 切换对应情报中心的启用状态")
        print("  set [编号] [API密钥]: 设置API密钥")
        print("-"*80)
        self.wait_for_key()
    
    def run(self):
        """运行主界面循环"""
        # 显示欢迎界面
        self.clear_screen()
        print(HACKER_ICON_ASCII)
        print(f"{Color.RED}{Color.BOLD}pirsrc_scan 6.1 - 高级木马扫描工具{Color.RESET}")
        print(f"{Color.YELLOW}作者: p1r07{Color.RESET}\n")
        FlameEffect.print_flame()
        self.wait_for_key("按任意键开始...")
        
        while self.running:
            self.clear_screen()
            
            # 根据当前标签显示内容
            if self.current_tab == 0:
                self.show_scan_tab()
            elif self.current_tab == 1:
                self.show_network_tab()
            elif self.current_tab == 2:
                self.show_sample_tab()
            elif self.current_tab == 3:
                self.show_signature_tab()
            elif self.current_tab == 4:
                self.show_config_tab()
            
            # 处理用户输入
            self.handle_input()
    
    def handle_input(self):
        """处理用户输入"""
        try:
            user_input = input("请输入操作: ").strip().lower()
            
            if not user_input:
                return
                
            # 全局命令
            if user_input in ['q', 'quit']:
                self.running = False
                return
            elif user_input in ['h', 'help', '?']:
                self.show_help()
                return
            elif user_input in ['n', 'next']:
                self.current_tab = (self.current_tab + 1) % len(self.tabs)
                return
            elif user_input in ['p', 'prev', 'previous']:
                self.current_tab = (self.current_tab - 1) % len(self.tabs)
                return
            
            # 扫描标签页处理
            if self.current_tab == 0:
                if user_input == '1':
                    self.select_file_scan()
                elif user_input == '2':
                    self.select_dir_scan()
                elif user_input == '3':
                    self.start_full_scan(deep=False)
                elif user_input == '4':
                    self.start_full_scan(deep=True)
                elif user_input == '5':
                    self.view_scan_results()
            
            # 网络标签页处理
            elif self.current_tab == 1:
                if user_input == '1':
                    self.refresh_network_connections()
                elif user_input == '2':
                    self.view_border_report()
                elif user_input == '3':
                    self.export_border_report()
            
            # 样本标签页处理
            elif self.current_tab == 2:
                if user_input == '1':
                    self.extract_samples()
                elif user_input == '2':
                    self.submit_samples()
                elif user_input == '3':
                    self.view_quarantined_files()
                elif user_input == '4':
                    self.restore_quarantined_file()
            
            # 特征标签页处理
            elif self.current_tab == 3:
                if user_input == '1':
                    self.view_signatures()
                elif user_input == '2':
                    self.add_signature()
                elif user_input == '3':
                    self.load_signatures()
                elif user_input == '4':
                    self.save_signatures()
            
            # 配置标签页处理
            elif self.current_tab == 4:
                if user_input == '1':
                    self.save_config()
                # 设置API密钥命令
                elif user_input.startswith('set '):
                    parts = user_input.split()
                    if len(parts) >= 3:
                        try:
                            idx = int(parts[1]) - 1
                            names = list(THREAT_INTEL_CONFIG.keys())
                            if 0 <= idx < len(names):
                                name = names[idx]
                                api_key = ' '.join(parts[2:])
                                THREAT_INTEL_CONFIG[name]["api_key"] = api_key
                                self.scanner.intel_clients[name].api_key = api_key
                                self.status_message = f"{THREAT_INTEL_CONFIG[name]['name']} API密钥已更新"
                            else:
                                self.status_message = "无效的编号"
                        except ValueError:
                            self.status_message = "无效的编号格式"
                    else:
                        self.status_message = "命令格式错误，正确格式: set [编号] [API密钥]"
                # 数字键切换启用状态
                elif user_input.isdigit() and 1 <= int(user_input) <= len(THREAT_INTEL_CONFIG):
                    idx = int(user_input) - 1
                    names = list(THREAT_INTEL_CONFIG.keys())
                    name = names[idx]
                    THREAT_INTEL_CONFIG[name]["enabled"] = not THREAT_INTEL_CONFIG[name]["enabled"]
                    self.scanner.intel_clients[name].enabled = THREAT_INTEL_CONFIG[name]["enabled"]
                    self.status_message = f"{THREAT_INTEL_CONFIG[name]['name']}已{'启用' if THREAT_INTEL_CONFIG[name]['enabled'] else '禁用'}"
        
        except KeyboardInterrupt:
            self.running = False
        except Exception as e:
            self.status_message = f"操作失败: {str(e)}"
    
    def select_file_scan(self):
        """选择文件扫描"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}文件扫描{Color.RESET}")
        print("-"*80)
        
        file_path = input("请输入要扫描的文件路径: ").strip()
        
        if file_path and os.path.exists(file_path) and os.path.isfile(file_path):
            print(f"\n正在扫描文件: {file_path}...")
            
            # 执行扫描
            result = self.scanner.scan_file(file_path)
            self.scan_results.append(result)
            
            # 显示结果
            self.clear_screen()
            print("="*80)
            print(f"{Color.BOLD}扫描结果{Color.RESET}")
            print("-"*80)
            print(f"文件: {result['file_name']}")
            print(f"路径: {result['file_path']}")
            print(f"大小: {result['file_size']} bytes")
            print(f"类型: {result['file_type']}")
            print(f"哈希: {result['file_hash'][:16]}...")
            print(f"签名验证: {result['signature_verification']['message']}")
            print(f"完整性: {result['integrity_check']['message']}")
            
            status = "恶意文件" if result["is_malicious"] else "正常文件"
            status_color = Color.RED if result["is_malicious"] else Color.GREEN
            print(f"\n{status_color}{Color.BOLD}状态: {status}{Color.RESET}")
            
            if result["matched_signatures"]:
                print(f"\n{Color.YELLOW}匹配的特征:{Color.RESET}")
                for sig in result["matched_signatures"]:
                    print(f"- {sig['name']}: {sig['description']}")
                    print(f"  匹配项: {', '.join(sig['matches'])}")
            
            # 如果发现恶意文件，询问是否隔离
            if result["is_malicious"]:
                choice = input("\n是否将该文件隔离? (y/n): ").strip().lower()
                if choice == 'y':
                    success, msg = self.scanner.quarantine_file(file_path)
                    print(f"\n{msg}")
        
        else:
            print(f"{Color.RED}无效的文件路径: {file_path}{Color.RESET}")
        
        self.wait_for_key()
    
    def select_dir_scan(self):
        """选择目录扫描"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}目录扫描{Color.RESET}")
        print("-"*80)
        
        dir_path = input("请输入要扫描的目录路径: ").strip()
        
        if dir_path and os.path.exists(dir_path) and os.path.isdir(dir_path):
            print(f"\n正在扫描目录: {dir_path}...")
            
            # 执行扫描
            results = self.scanner.scan_directory(dir_path)
            self.scan_results.extend(results)
            
            malicious_count = len([r for r in results if r["is_malicious"]])
            print(f"\n目录扫描完成，共扫描{len(results)}个文件，发现{malicious_count}个恶意文件")
            
            if malicious_count > 0:
                choice = input("是否查看恶意文件列表? (y/n): ").strip().lower()
                if choice == 'y':
                    self.clear_screen()
                    print("="*80)
                    print(f"{Color.BOLD}恶意文件列表{Color.RESET}")
                    print("-"*80)
                    for r in [r for r in results if r["is_malicious"]]:
                        print(f"- {r['file_path']}")
                    
                    choice = input("\n是否隔离这些恶意文件? (y/n): ").strip().lower()
                    if choice == 'y':
                        self.scanner.extract_samples(quarantine=True)
        else:
            print(f"{Color.RED}无效的目录路径: {dir_path}{Color.RESET}")
        
        self.wait_for_key()
    
    def start_full_scan(self, deep: bool = False):
        """开始全系统扫描"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}{'全系统深度扫描' if deep else '全系统快速扫描'}{Color.RESET}")
        print("-"*80)
        
        choice = input(f"确认要进行{('深度' if deep else '快速')}全系统扫描吗? (y/n): ").strip().lower()
        if choice != 'y':
            print("已取消扫描")
            self.wait_for_key()
            return
        
        print(f"\n开始{('深度' if deep else '快速')}全系统扫描，请稍候...")
        print("这可能需要较长时间，请勿关闭程序...\n")
        
        # 执行扫描（在主线程执行以显示实时日志）
        result = self.scanner.full_system_scan(deep)
        self.scan_results.extend(result["file_results"])
        
        # 显示结果摘要
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}全系统扫描结果{Color.RESET}")
        print("-"*80)
        print(f"开始时间: {result['summary']['start_time']}")
        print(f"结束时间: {result['summary']['end_time']}")
        print(f"耗时: {result['summary']['duration']:.2f}秒")
        print(f"扫描文件总数: {result['summary']['total_files_scanned']}")
        print(f"{Color.RED}发现恶意文件: {result['summary']['malicious_files_found']}{Color.RESET}")
        print(f"{Color.RED}发现可疑进程: {result['summary']['malicious_processes_found']}{Color.RESET}")
        print(f"{Color.YELLOW}高资源占用进程: {result['summary']['high_resource_processes']}{Color.RESET}")
        print(f"{Color.YELLOW}跨境连接: {result['summary']['cross_border_connections_found']}{Color.RESET}")
        print(f"\n报告已保存到: {result['report_path']}")
        
        # 询问是否处理发现的恶意文件
        if result["summary"]["malicious_files_found"] > 0:
            choice = input("\n是否隔离发现的恶意文件? (y/n): ").strip().lower()
            if choice == 'y':
                self.scanner.extract_samples(quarantine=True)
        
        self.wait_for_key()
    
    def view_scan_results(self):
        """查看扫描结果"""
        if not self.scan_results:
            self.status_message = "暂无扫描结果"
            return
            
        current = 0
        while True:
            self.clear_screen()
            print("="*80)
            print(f"{Color.BOLD}扫描结果详情 ({current+1}/{len(self.scan_results)}){Color.RESET}")
            print("-"*80)
            
            result = self.scan_results[current]
            status = "恶意文件" if result["is_malicious"] else "正常文件"
            status_color = Color.RED if result["is_malicious"] else Color.GREEN
            
            print(f"文件: {result['file_name']}")
            print(f"路径: {result['file_path']}")
            print(f"大小: {result['file_size']} bytes")
            print(f"类型: {result['file_type']}")
            print(f"哈希: {result['file_hash'][:16]}...")
            print(f"签名验证: {result['signature_verification']['message']}")
            print(f"完整性: {result['integrity_check']['message']}")
            
            print(f"\n{status_color}{Color.BOLD}状态: {status}{Color.RESET}")
            
            if result["matched_signatures"]:
                print(f"\n{Color.YELLOW}匹配的特征:{Color.RESET}")
                for sig in result["matched_signatures"]:
                    print(f"- {sig['name']}: {sig['description']}")
                    print(f"  匹配项: {', '.join(sig['matches'])}")
            
            if result["sandbox_analysis"]:
                print(f"\n{Color.CYAN}沙盒分析结果: {result['sandbox_analysis']['verdict']}{Color.RESET}")
            
            print("\n" + "-"*80)
            print("操作:")
            print("  n: 下一个结果")
            print("  p: 上一个结果")
            print("  d: 删除当前结果")
            print("  s: 沙盒分析（仅恶意文件）")
            print("  q: 返回")
            
            user_input = input("\n请输入操作: ").strip().lower()
            if user_input == 'q':
                break
            elif user_input == 'n' and current < len(self.scan_results) - 1:
                current += 1
            elif user_input == 'p' and current > 0:
                current -= 1
            elif user_input == 'd':
                del self.scan_results[current]
                if current >= len(self.scan_results) and len(self.scan_results) > 0:
                    current = len(self.scan_results) - 1
                elif len(self.scan_results) == 0:
                    break
            elif user_input == 's' and result["is_malicious"]:
                self.clear_screen()
                print("正在进行沙盒分析...")
                analysis = self.scanner.sandbox_analyzer.run_sandbox_analysis(result["file_path"])
                result["sandbox_analysis"] = analysis
                
                self.clear_screen()
                print("="*80)
                print(f"{Color.BOLD}沙盒分析报告{Color.RESET}")
                print("-"*80)
                print(f"文件: {analysis['file_name']}")
                print(f"结果: {analysis['verdict']}")
                
                print(f"\n{Color.YELLOW}可疑行为:{Color.RESET}")
                for behavior in analysis["suspicious_behaviors"]:
                    print(f"- {behavior}")
                
                self.wait_for_key()
    
    def refresh_network_connections(self):
        """刷新网络连接"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}刷新网络连接{Color.RESET}")
        print("-"*80)
        print("正在获取网络连接信息...")
        
        self.network_connections = self.scanner.check_network_connections()
        print(f"已刷新，共发现{len(self.network_connections)}个网络连接")
        
        self.wait_for_key()
    
    def view_border_report(self):
        """查看跨境连接报告"""
        if not os.path.exists(self.scanner.border_report_path):
            self.status_message = "没有跨境连接报告"
            return
            
        # 读取报告
        connections = []
        try:
            with open(self.scanner.border_report_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)  # 跳过表头
                for row in reader:
                    connections.append(row)
        except Exception as e:
            self.status_message = f"读取报告失败: {str(e)}"
            return
        
        if not connections:
            self.status_message = "跨境连接报告为空"
            return
        
        offset = 0
        page_size = 15
        while True:
            self.clear_screen()
            print("="*80)
            print(f"{Color.BOLD}跨境连接报告{Color.RESET}")
            print("-"*80)
            
            # 表头
            print(f"{'时间':<20} {'PID':<6} {'进程名':<20} {'IP地址':<15} {'位置':<8}")
            print("-"*80)
            
            # 内容
            for conn in connections[offset:offset+page_size]:
                print(f"{conn[0][:19]:<20} {conn[1]:<6} {conn[2][:18]:<20} {conn[3]:<15} {conn[4]:<8}")
            
            print("\n" + "-"*80)
            print(f"显示 {offset+1}-{min(offset+page_size, len(connections))} 共 {len(connections)} 条记录")
            print("操作:")
            print("  n: 下一页")
            print("  p: 上一页")
            print("  q: 返回")
            
            user_input = input("\n请输入操作: ").strip().lower()
            if user_input == 'q':
                break
            elif user_input == 'n' and offset + page_size < len(connections):
                offset += page_size
            elif user_input == 'p' and offset >= page_size:
                offset -= page_size
    
    def export_border_report(self):
        """导出跨境连接报告"""
        if not os.path.exists(self.scanner.border_report_path):
            self.status_message = "没有跨境连接报告可导出"
            return
            
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}导出跨境连接报告{Color.RESET}")
        print("-"*80)
        
        save_path = input("请输入保存路径: ").strip()
        
        if save_path:
            try:
                shutil.copy2(self.scanner.border_report_path, save_path)
                print(f"报告已保存到: {save_path}")
            except Exception as e:
                print(f"{Color.RED}导出报告失败: {str(e)}{Color.RESET}")
        else:
            print(f"{Color.YELLOW}未输入保存路径{Color.RESET}")
        
        self.wait_for_key()
    
    def extract_samples(self):
        """提取样本"""
        if not self.scanner.scan_results:
            self.status_message = "请先进行扫描"
            return
            
        malicious_count = len([r for r in self.scanner.scan_results if r["is_malicious"]])
        if malicious_count == 0:
            self.status_message = "没有发现恶意文件可提取"
            return
            
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}提取恶意样本{Color.RESET}")
        print("-"*80)
        
        choice = input(f"将提取{malicious_count}个恶意样本，是否同时隔离原文件? (y/n): ").strip().lower()
        quarantine = choice == 'y'
        
        print("\n正在提取样本...")
        samples = self.scanner.extract_samples(quarantine)
        print(f"已提取{len(samples)}个样本到samples目录")
        
        self.wait_for_key()
    
    def submit_samples(self):
        """提交样本到沙盒"""
        sample_files = glob.glob(os.path.join(SAMPLES_DIR, "*"))
        if not sample_files or len(sample_files) == 0:
            self.status_message = "没有样本可提交"
            return
            
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}提交样本到沙盒{Color.RESET}")
        print("-"*80)
        
        print("请选择要提交的威胁情报中心:")
        print("1. 所有启用的情报中心")
        print("2. VirusTotal")
        print("3. 微步在线")
        print("4. 奇安信")
        print("5. 绿盟")
        
        user_input = input("\n请输入选择 (1-5): ").strip()
        source_map = {
            '1': "all",
            '2': "virustotal",
            '3': "threatbook",
            '4': "qianxin",
            '5': "nsfocus"
        }
        
        source = source_map.get(user_input, "all")
        if source:
            print("\n正在提交样本到沙盒...")
            results = self.scanner.submit_samples_to_sandbox(source)
            success_count = len([r for r in results if r["status"] == "success"])
            print(f"样本提交完成，成功{success_count}/{len(results)}个")
        else:
            print("无效的选择")
        
        self.wait_for_key()
    
    def view_quarantined_files(self):
        """查看隔离文件"""
        quarantined = self.scanner.get_quarantined_files()
        quarantined = [q for q in quarantined if q["status"] == "quarantined"]
        
        if not quarantined:
            self.status_message = "没有隔离文件"
            return
            
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}隔离文件列表{Color.RESET}")
        print("-"*80)
        
        for i, item in enumerate(quarantined):
            print(f"{i+1}. {os.path.basename(item['original_path'])}")
            print(f"   原始路径: {item['original_path']}")
            print(f"   隔离时间: {item['timestamp'][:19]}\n")
        
        print("操作:")
        print("  输入文件编号: 处理该文件")
        print("  q: 返回")
        
        user_input = input("\n请输入操作: ").strip()
        if user_input == 'q':
            return
            
        try:
            idx = int(user_input) - 1
            if 0 <= idx < len(quarantined):
                self.handle_quarantined_file(quarantined[idx])
            else:
                print("无效的编号")
                self.wait_for_key()
        except ValueError:
            print("无效的输入")
            self.wait_for_key()
    
    def handle_quarantined_file(self, item: Dict):
        """处理隔离文件"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}处理隔离文件{Color.RESET}")
        print("-"*80)
        
        print(f"文件: {os.path.basename(item['original_path'])}")
        print(f"原始路径: {item['original_path']}")
        print(f"隔离路径: {item['quarantine_path']}")
        print(f"隔离时间: {item['timestamp'][:19]}")
        
        print("\n操作:")
        print("1. 恢复文件")
    
        print("2. 彻底删除")
        print("3. 取消")
        
        user_input = input("\n请输入选择 (1-3): ").strip()
        
        if user_input == '1':
            # 恢复文件
            success, msg = self.scanner.restore_file(item)
            print(f"\n{msg}")
        elif user_input == '2':
            # 彻底删除
            if os.path.exists(item["quarantine_path"]):
                try:
                    os.remove(item["quarantine_path"])
                    
                    # 更新日志
                    with open(self.scanner.quarantine_log, "r", encoding="utf-8") as f:
                        log_data = json.load(f)
                    
                    for entry in log_data:
                        if entry["quarantine_path"] == item["quarantine_path"]:
                            entry["status"] = "deleted"
                            entry["delete_timestamp"] = datetime.now().isoformat()
                            break
                    
                    with open(self.scanner.quarantine_log, "w", encoding="utf-8") as f:
                        json.dump(log_data, f, ensure_ascii=False, indent=2)
                    
                    print(f"\n文件已彻底删除: {item['quarantine_path']}")
                except Exception as e:
                    print(f"\n{Color.RED}删除文件失败: {str(e)}{Color.RESET}")
        # 其他情况取消操作
        
        self.wait_for_key()
    
    def restore_quarantined_file(self):
        """恢复隔离文件"""
        self.view_quarantined_files()
    
    def view_signatures(self):
        """查看病毒特征"""
        if not self.scanner.signatures:
            self.status_message = "暂无病毒特征"
            return
            
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}病毒特征列表{Color.RESET}")
        print("-"*80)
        
        for i, sig in enumerate(self.scanner.signatures):
            status = "启用" if sig.is_active else "禁用"
            status_color = Color.GREEN if sig.is_active else Color.YELLOW
            
            print(f"{i+1}. {sig.name}")
            print(f"   威胁等级: {sig.threat_level}/5")
            print(f"   状态: {status_color}{status}{Color.RESET}")
            print(f"   描述: {sig.description[:60]}...")
            print(f"   关联文件名: {', '.join(sig.file_names[:3])}{'...' if len(sig.file_names) > 3 else ''}\n")
        
        print("操作:")
        print("  输入特征编号: 查看详情")
        print("  q: 返回")
        
        user_input = input("\n请输入操作: ").strip()
        if user_input == 'q':
            return
            
        try:
            idx = int(user_input) - 1
            if 0 <= idx < len(self.scanner.signatures):
                self.view_signature_detail(self.scanner.signatures[idx])
            else:
                print("无效的编号")
                self.wait_for_key()
        except ValueError:
            print("无效的输入")
            self.wait_for_key()
    
    def view_signature_detail(self, sig: VirusSignature):
        """查看特征详情"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}病毒特征详情: {sig.name}{Color.RESET}")
        print("-"*80)
        
        print(f"特征ID: {sig.signature_id}")
        print(f"威胁等级: {sig.threat_level}/5")
        print(f"状态: {'启用' if sig.is_active else '禁用'}")
        print(f"创建日期: {sig.creation_date}")
        print(f"\n描述: {sig.description}")
        
        print(f"\n{Color.YELLOW}关联文件名:{Color.RESET}")
        print(f"  {', '.join(sig.file_names)}")
        
        print(f"\n{Color.YELLOW}关联哈希值:{Color.RESET}")
        if sig.file_hashes:
            print(f"  {', '.join(sig.file_hashes)}")
        else:
            print("  无关联哈希值")
        
        print(f"\n{Color.YELLOW}关联文件大小:{Color.RESET}")
        if sig.file_sizes:
            print(f"  {', '.join(f'{s:,} bytes' for s in sig.file_sizes)}")
        else:
            print("  无关联文件大小")
        
        print(f"\n{Color.YELLOW}关联注册表路径:{Color.RESET}")
        if sig.registry_paths:
            print(f"  {', '.join(sig.registry_paths)}")
        else:
            print("  无关联注册表路径")
        
        print(f"\n{Color.YELLOW}关联进程名:{Color.RESET}")
        if sig.process_names:
            print(f"  {', '.join(sig.process_names)}")
        else:
            print("  无关联进程名")
        
        print(f"\n{Color.YELLOW}关联网络指标:{Color.RESET}")
        if sig.network_indicators:
            print(f"  {', '.join(sig.network_indicators)}")
        else:
            print("  无关联网络指标")
        
        print(f"\n{Color.YELLOW}关联文件路径:{Color.RESET}")
        if sig.file_paths:
            print(f"  {', '.join(sig.file_paths)}")
        else:
            print("  无关联文件路径")
        
        print("\n操作:")
        print("1. 启用/禁用特征")
        print("2. 编辑特征")
        print("3. 删除特征")
        print("4. 返回")
        
        user_input = input("\n请输入选择 (1-4): ").strip()
        
        if user_input == '1':
            # 切换启用/禁用状态
            sig.is_active = not sig.is_active
            self.status_message = f"特征已{'启用' if sig.is_active else '禁用'}"
        elif user_input == '2':
            # 编辑特征
            self.edit_signature(sig)
        elif user_input == '3':
            # 删除特征
            confirm = input("确定要删除该特征吗? (y/n): ").strip().lower()
            if confirm == 'y':
                self.scanner.signatures.remove(sig)
                self.status_message = "特征已删除"
        # 其他情况返回
        
        self.wait_for_key()
    
    def edit_signature(self, sig: VirusSignature):
        """编辑病毒特征"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}编辑病毒特征: {sig.name}{Color.RESET}")
        print("-"*80)
        print("提示: 直接回车保持当前值，输入新值进行修改\n")
        
        # 编辑名称
        current = sig.name
        new_val = input(f"名称 [{current}]: ").strip()
        if new_val:
            sig.name = new_val
        
        # 编辑描述
        current = sig.description
        print(f"\n当前描述: {current[:100]}{'...' if len(current) > 100 else ''}")
        new_val = input("新描述 (多行输入，空行结束):\n").strip()
        # 处理多行输入
        lines = [new_val]
        while True:
            line = input()
            if not line:
                break
            lines.append(line)
        new_val = '\n'.join(lines)
        if new_val:
            sig.description = new_val
        
        # 编辑关联文件名
        current = ', '.join(sig.file_names)
        new_val = input(f"\n关联文件名 [{current}]: ").strip()
        if new_val:
            sig.file_names = [n.strip() for n in new_val.split(',') if n.strip()]
        
        # 编辑关联哈希值
        current = ', '.join(sig.file_hashes)
        new_val = input(f"关联哈希值 [{current}]: ").strip()
        if new_val:
            sig.file_hashes = [h.strip() for h in new_val.split(',') if h.strip()]
        
        # 编辑关联文件大小
        current = ', '.join(str(s) for s in sig.file_sizes)
        new_val = input(f"关联文件大小 (bytes) [{current}]: ").strip()
        if new_val:
            try:
                sig.file_sizes = [int(s.strip()) for s in new_val.split(',') if s.strip()]
            except ValueError:
                print(f"{Color.RED}无效的文件大小，保持原值{Color.RESET}")
        
        # 编辑关联注册表路径
        current = ', '.join(sig.registry_paths)
        new_val = input(f"关联注册表路径 [{current}]: ").strip()
        if new_val:
            sig.registry_paths = [p.strip() for p in new_val.split(',') if p.strip()]
        
        # 编辑关联进程名
        current = ', '.join(sig.process_names)
        new_val = input(f"关联进程名 [{current}]: ").strip()
        if new_val:
            sig.process_names = [p.strip() for p in new_val.split(',') if p.strip()]
        
        # 编辑关联网络指标
        current = ', '.join(sig.network_indicators)
        new_val = input(f"关联网络指标 (IP/域名) [{current}]: ").strip()
        if new_val:
            sig.network_indicators = [n.strip() for n in new_val.split(',') if n.strip()]
        
        # 编辑关联文件路径
        current = ', '.join(sig.file_paths)
        new_val = input(f"关联文件路径 [{current}]: ").strip()
        if new_val:
            sig.file_paths = [p.strip() for p in new_val.split(',') if p.strip()]
        
        # 编辑威胁等级
        current = sig.threat_level
        new_val = input(f"威胁等级 (1-5) [{current}]: ").strip()
        if new_val:
            try:
                level = int(new_val)
                if 1 <= level <= 5:
                    sig.threat_level = level
                else:
                    print(f"{Color.RED}威胁等级必须在1-5之间，保持原值{Color.RESET}")
            except ValueError:
                print(f"{Color.RED}无效的威胁等级，保持原值{Color.RESET}")
        
        self.status_message = "特征已更新"
        self.wait_for_key()
    
    def add_signature(self):
        """添加新的病毒特征"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}添加新病毒特征{Color.RESET}")
        print("-"*80)
        
        try:
            # 生成唯一ID
            sig_id = f"sig_custom_{int(time.time())}"
            
            # 输入名称
            name = ""
            while not name:
                name = input("请输入特征名称: ").strip()
                if not name:
                    print("特征名称不能为空")
            
            # 输入描述
            print("\n请输入特征描述 (多行输入，空行结束):")
            lines = []
            while True:
                line = input()
                if not line and lines:  # 空行且已有内容则结束
                    break
                if line:
                    lines.append(line)
            description = '\n'.join(lines) if lines else "无描述"
            
            # 输入关联文件名
            file_names = input("\n请输入关联文件名 (逗号分隔): ").strip()
            file_names = [n.strip() for n in file_names.split(',')] if file_names else []
            
            # 输入关联哈希值
            file_hashes = input("请输入关联哈希值 (逗号分隔): ").strip()
            file_hashes = [h.strip() for h in file_hashes.split(',')] if file_hashes else []
            
            # 输入关联文件大小
            file_sizes = []
            sizes_input = input("请输入关联文件大小 (bytes，逗号分隔): ").strip()
            if sizes_input:
                try:
                    file_sizes = [int(s.strip()) for s in sizes_input.split(',') if s.strip()]
                except ValueError:
                    print(f"{Color.RED}无效的文件大小，将忽略此项{Color.RESET}")
            
            # 输入关联注册表路径
            registry_paths = input("请输入关联注册表路径 (逗号分隔): ").strip()
            registry_paths = [p.strip() for p in registry_paths.split(',')] if registry_paths else []
            
            # 输入关联进程名
            process_names = input("请输入关联进程名 (逗号分隔): ").strip()
            process_names = [p.strip() for p in process_names.split(',')] if process_names else []
            
            # 输入关联网络指标
            network_indicators = input("请输入关联网络指标 (IP/域名，逗号分隔): ").strip()
            network_indicators = [n.strip() for n in network_indicators.split(',')] if network_indicators else []
            
            # 输入关联文件路径
            file_paths = input("请输入关联文件路径 (逗号分隔): ").strip()
            file_paths = [p.strip() for p in file_paths.split(',')] if file_paths else []
            
            # 输入威胁等级
            threat_level = 3
            level_input = input("请输入威胁等级 (1-5，默认3): ").strip()
            if level_input:
                try:
                    level = int(level_input)
                    if 1 <= level <= 5:
                        threat_level = level
                    else:
                        print(f"{Color.RED}威胁等级必须在1-5之间，使用默认值3{Color.RESET}")
                except ValueError:
                    print(f"{Color.RED}无效的威胁等级，使用默认值3{Color.RESET}")
            
            # 创建新特征
            new_sig = VirusSignature(
                signature_id=sig_id,
                name=name,
                description=description,
                file_names=file_names,
                file_hashes=file_hashes,
                file_sizes=file_sizes,
                registry_paths=registry_paths,
                process_names=process_names,
                network_indicators=network_indicators,
                file_paths=file_paths,
                creation_date=datetime.now(),
                is_active=True,
                threat_level=threat_level
            )
            
            # 添加到特征库
            self.scanner.add_signature(new_sig)
            self.status_message = f"已添加新特征: {name}"
            
        except Exception as e:
            self.status_message = f"添加特征失败: {str(e)}"
        
        self.wait_for_key()
    
    def load_signatures(self):
        """加载特征库"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}加载病毒特征库{Color.RESET}")
        print("-"*80)
        
        file_path = input("请输入特征库文件路径: ").strip()
        
        if file_path and os.path.exists(file_path) and os.path.isfile(file_path):
            success = self.scanner.load_signatures(file_path)
            if success:
                self.status_message = f"已从{file_path}加载特征库"
            else:
                self.status_message = "加载特征库失败"
        else:
            print(f"{Color.RED}无效的文件路径: {file_path}{Color.RESET}")
            self.status_message = "加载特征库失败"
        
        self.wait_for_key()
    
    def save_signatures(self):
        """保存特征库"""
        self.clear_screen()
        print("="*80)
        print(f"{Color.BOLD}保存病毒特征库{Color.RESET}")
        print("-"*80)
        
        default_path = os.path.join(BASE_DIR, "signatures.json")
        file_path = input(f"请输入保存路径 (默认: {default_path}): ").strip()
        if not file_path:
            file_path = default_path
        
        success = self.scanner.save_signatures(file_path)
        if success:
            self.status_message = f"已保存特征库到{file_path}"
        else:
            self.status_message = "保存特征库失败"
        
        self.wait_for_key()

# -------------------------- 主程序入口 --------------------------
def main():
    """主程序入口"""
    # 检查权限
    if (IS_LINUX or IS_MACOS) and os.geteuid() != 0:
        print(f"{Color.YELLOW}警告: 建议使用root权限运行以获得完整功能{Color.RESET}")
        time.sleep(2)
    
    # 启动程序
    cli = CliInterface()
    try:
        cli.run()
    except Exception as e:
        print(f"{Color.RED}程序运行出错: {str(e)}{Color.RESET}")
        # 保存错误日志
        error_log = os.path.join(REPORTS_DIR, f"error_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(error_log, "w", encoding="utf-8") as f:
            f.write(f"错误时间: {datetime.now()}\n")
            f.write(f"错误信息: {str(e)}\n")
            import traceback
            f.write(traceback.format_exc())
        print(f"错误详情已保存到: {error_log}")
    
    print("\n感谢使用pirsrc_scan 6.1")

if __name__ == "__main__":
    main()
    
