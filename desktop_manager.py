"""Lightweight Windows process manager (Tkinter, standard library only)."""
import ctypes
import os
import sys
import subprocess
import threading
import time
import json
import base64
import hashlib
import uuid
import csv
import math
import statistics
import struct
import re
import shutil
import tempfile
import winreg
from collections import deque
import tkinter as tk
from ctypes import wintypes
from tkinter import filedialog, messagebox, ttk

if os.name != "nt":
    raise SystemExit("此程序仅支持 Windows")

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x00100000
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260
ERROR_BAD_LENGTH = 24
ERROR_NO_MORE_FILES = 18

# Muted, distinct hues; each entry has a soft row background and a readable accent.
PROGRAM_COLORS = {
    "雾蓝": ("#E7ECF5", "#516987"),
    "青绿": ("#DFEEEA", "#3F776B"),
    "苔绿": ("#E8EFDF", "#61734A"),
    "暖黄": ("#F2EBDD", "#887143"),
    "陶橙": ("#F2E5DC", "#93644B"),
    "豆沙": ("#F0E3E8", "#8B5E6F"),
    "灰紫": ("#EAE5F1", "#6F6087"),
    "钢青": ("#E2EBEF", "#4D6F7C"),
}

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32.IsUserAnAdmin.restype = wintypes.BOOL
shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.LocalFree.restype = ctypes.c_void_p
shell32.ShellExecuteW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                  wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int]
shell32.ShellExecuteW.restype = ctypes.c_void_p


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HANDLE),
                ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
shell32.ShellExecuteExW.restype = wintypes.BOOL
WM_CLOSE = 0x0010
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
SYNCHRONIZE = 0x00100000
SEE_MASK_NOCLOSEPROCESS = 0x00000040
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL
user32.EnumWindows.argtypes = [ctypes.c_void_p, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.PostMessageW.restype = wintypes.BOOL
user32.GetForegroundWindow.argtypes = []
user32.GetForegroundWindow.restype = wintypes.HWND
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.restype = ctypes.c_int


class ElevatedProcess:
    """Process-handle wrapper for PresentMon launched through the Windows UAC broker."""
    def __init__(self, handle):
        self.handle = handle
        self.returncode = None

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        if not self.handle:
            return None
        if kernel32.WaitForSingleObject(self.handle, 0) == WAIT_OBJECT_0:
            code = wintypes.DWORD()
            self.returncode = int(code.value) if kernel32.GetExitCodeProcess(self.handle, ctypes.byref(code)) else 1
            kernel32.CloseHandle(self.handle)
            self.handle = None
            return self.returncode
        return None

    def wait(self, timeout=None):
        if self.poll() is not None:
            return self.returncode
        milliseconds = 0xFFFFFFFF if timeout is None else max(0, int(timeout * 1000))
        result = kernel32.WaitForSingleObject(self.handle, milliseconds)
        if result == WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired("PresentMon", timeout)
        return self.poll()

    def terminate(self):
        if self.poll() is None and self.handle:
            kernel32.TerminateProcess(self.handle, 1)


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL


def logical_drives():
    """Return all mounted Windows drive letters, not just drives used by processes."""
    mask = kernel32.GetLogicalDrives()
    return ["%s:" % chr(ord("A") + index) for index in range(26) if mask & (1 << index)]


def system_memory_status():
    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(status)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return 0, 0
    return int(status.ullTotalPhys), int(status.ullAvailPhys)


def foreground_process_id():
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return 0
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return int(pid.value)


def foreground_window_info():
    """Read the live foreground HWND, owner PID, title, class, and executable path."""
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return {"hwnd": 0, "pid": 0, "title": "", "class_name": "", "path": ""}
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    title_buffer = ctypes.create_unicode_buffer(max(2, min(2048, user32.GetWindowTextLengthW(hwnd) + 1)))
    user32.GetWindowTextW(hwnd, title_buffer, len(title_buffer))
    class_buffer = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, class_buffer, len(class_buffer))
    path = ""
    if pid.value:
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
        if handle:
            try:
                path_buffer = ctypes.create_unicode_buffer(32768)
                path_size = wintypes.DWORD(len(path_buffer))
                if kernel32.QueryFullProcessImageNameW(handle, 0, path_buffer, ctypes.byref(path_size)):
                    path = path_buffer.value
            finally:
                kernel32.CloseHandle(handle)
    return {"hwnd": int(hwnd), "pid": int(pid.value), "title": title_buffer.value,
            "class_name": class_buffer.value, "path": path}


def visible_window_process_ids():
    """Return PIDs that currently own a visible top-level window."""
    result = set()
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def visit(hwnd, _lparam):
        if user32.IsWindowVisible(hwnd):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                result.add(int(pid.value))
        return True

    callback = callback_type(visit)
    user32.EnumWindows(callback, 0)
    return result


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * MAX_PATH)]


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME)]
kernel32.GetProcessTimes.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL
psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
user32.DestroyIcon.argtypes = [wintypes.HANDLE]


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


def snapshot_processes():
    snap = wintypes.HANDLE(-1).value
    last_error = 0
    for attempt in range(5):
        ctypes.set_last_error(0)
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap != wintypes.HANDLE(-1).value:
            break
        last_error = ctypes.get_last_error()
        if last_error != ERROR_BAD_LENGTH or attempt == 4:
            raise ctypes.WinError(last_error) if last_error else OSError("无法创建进程快照")
        time.sleep(0.05 * (attempt + 1))
    results = []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        ctypes.set_last_error(0)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        if not ok:
            last_error = ctypes.get_last_error()
            if last_error not in (0, ERROR_NO_MORE_FILES):
                raise ctypes.WinError(last_error)
        while ok:
            pid, name = int(entry.th32ProcessID), entry.szExeFile
            parent_pid = int(entry.th32ParentProcessID)
            path, memory, started_at, creation_time_ticks = "不可读取（可能需要管理员权限）", 0, "未知", None
            path_readable = memory_readable = False
            # Use least-privilege handles independently so denial of VM_READ does
            # not hide a process whose name and image path are still queryable.
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                buf = ctypes.create_unicode_buffer(32768)
                size = wintypes.DWORD(len(buf))
                if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                    path = buf.value
                    path_readable = True
                creation, exit_time, kernel_time, user_time = FILETIME(), FILETIME(), FILETIME(), FILETIME()
                if kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time),
                                           ctypes.byref(kernel_time), ctypes.byref(user_time)):
                    ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
                    creation_time_ticks = ticks
                    unix_time = ticks / 10000000.0 - 11644473600
                    started_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unix_time))
                kernel32.CloseHandle(handle)
            # Memory permissions vary independently from image-path permissions.
            for access in (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           PROCESS_QUERY_LIMITED_INFORMATION):
                memory_handle = kernel32.OpenProcess(access, False, pid)
                if not memory_handle:
                    continue
                counters = PROCESS_MEMORY_COUNTERS()
                counters.cb = ctypes.sizeof(counters)
                if psapi.GetProcessMemoryInfo(memory_handle, ctypes.byref(counters), counters.cb):
                    memory = int(counters.WorkingSetSize)
                    memory_readable = True
                kernel32.CloseHandle(memory_handle)
                if memory_readable:
                    break
            results.append({"pid": pid, "parent_pid": parent_pid, "name": name, "path": path, "memory": memory,
                            "path_readable": path_readable, "memory_readable": memory_readable,
                            "started_at": started_at, "creation_time_ticks": creation_time_ticks,
                            "publisher": "路径不可读" if not path_readable else "签名查询中…"})
            ctypes.set_last_error(0)
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
            if not ok:
                last_error = ctypes.get_last_error()
                if last_error not in (0, ERROR_NO_MORE_FILES):
                    raise ctypes.WinError(last_error)
    finally:
        kernel32.CloseHandle(snap)
    names = {item["pid"]: item["name"] for item in results}
    path_counts = {}
    for item in results:
        identity = item["path"].lower() if not item["path"].startswith("不可读取") else item["name"].lower()
        path_counts[identity] = path_counts.get(identity, 0) + 1
    for item in results:
        item["parent_name"] = names.get(item["parent_pid"], "已退出/系统进程")
        identity = item["path"].lower() if not item["path"].startswith("不可读取") else item["name"].lower()
        item["instance_count"] = path_counts[identity]
    return results


def fmt_bytes(value):
    return "%.1f MB" % (value / (1024.0 * 1024.0)) if value > 0 else "—"


def windows_command_args(command):
    """Parse a Windows command line with the same rules used by process creation."""
    if not command:
        return []
    count = ctypes.c_int()
    values = shell32.CommandLineToArgvW(str(command), ctypes.byref(count))
    if not values:
        return []
    try:
        return [values[index] for index in range(count.value)]
    finally:
        kernel32.LocalFree(ctypes.cast(values, ctypes.c_void_p))


class Manager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("轻管 · 后台程序管理器")
        self.geometry("1080x700")
        self.minsize(860, 560)
        self.configure(bg="#f4f6f9")
        self.is_admin = bool(shell32.IsUserAnAdmin())
        self.rows = {}
        self.last_process_scan_error = ""
        self._refresh_generation = 0
        self._refresh_in_progress = False
        self._selection_restore_identities = None
        self.icon_cache = {}
        self.signature_cache = {}
        self.rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")
        self.manifest_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "latest_export_manifest.json")
        self.startup_data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "startup_manager_data")
        self.startup_state_path = os.path.join(self.startup_data_dir, "disabled_startup.json")
        self.startup_backup_dir = os.path.join(self.startup_data_dir, "startup_backups")
        self.legacy_startup_state_path = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                                                      "QingGuan", "disabled_startup.json")
        self.startup_state_error = ""
        self.startup_records = self._load_startup_records()
        self.startup_rows = {}
        self.rules = self._load_rules()
        self.after_refresh = None
        self.monitor_lock = threading.RLock()
        self.monitor_stop = threading.Event()
        self.monitor_history = deque(maxlen=1800)  # ~30 minutes at one sample per second.
        self.monitor_events = deque(maxlen=200)
        self.monitor_metadata = {}
        self.frame_baselines = {}
        self.last_frame_event = {}
        self.process_start_by_pid = {}
        self.presentmon_process = None
        self.presentmon_errors = deque(maxlen=8)
        self.presentmon_restart_count = 0
        self.presentmon_retrying = False
        self.presentmon_elevation_attempted = False
        self.presentmon_elevation_in_progress = False
        self.presentmon_elevated_active = False
        self.presentmon_csv_path = ""
        self.monitor_status = "监测准备中"
        self.monitor_started_at = time.time()
        self._monitor_last_snapshot = {}
        self._restore_monitor_state_from_environment()
        self._style()
        self._build()
        self.refresh()
        self._start_monitoring()
        self.foreground_refresh_after = self.after(250, self._foreground_ui_tick)

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background="white", fieldbackground="white", foreground="#202938", rowheight=48, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background="#fafbfc", foreground="#788392", font=("Segoe UI", 9, "bold"), relief="flat", padding=(8, 9))
        style.map("Treeview", background=[("selected", "#eaf2ff")], foreground=[("selected", "#225eb4")])
        style.configure("Monitor.Treeview", background="white", fieldbackground="white", foreground="#334155",
                        rowheight=34, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Monitor.Treeview.Heading", background="#f7f9fc", foreground="#66758a",
                        font=("Segoe UI", 8, "bold"), relief="flat", padding=(8, 8))
        style.map("Monitor.Treeview", background=[("selected", "#eaf2ff")], foreground=[("selected", "#225eb4")])
        style.configure("TNotebook", background="#f4f6f9", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(15, 7), background="#edf0f5", foreground="#586476")
        style.map("TNotebook.Tab", background=[("selected", "white")], foreground=[("selected", "#2e66b0")])

    def _build(self):
        header = tk.Frame(self, bg="white", height=56, highlightbackground="#e6eaf0", highlightthickness=1)
        header.pack(fill="x")
        logo = tk.Canvas(header, width=34, height=34, bg="white", highlightthickness=0)
        logo.pack(side="left", padx=(18, 9), pady=10)
        logo.create_oval(1, 1, 33, 33, fill="#EAF1FB", outline="")
        logo.create_line(10, 12, 24, 12, fill="#557DBA", width=2)
        logo.create_line(10, 17, 21, 17, fill="#557DBA", width=2)
        logo.create_line(10, 22, 18, 22, fill="#557DBA", width=2)
        logo.create_oval(22, 19, 27, 24, fill="#6FA58C", outline="")
        self._title_icon = tk.PhotoImage(width=16, height=16)
        self._title_icon.put("#EAF1FB", to=(0, 0, 16, 16))
        for y in (4, 7, 10):
            self._title_icon.put("#557DBA", to=(3, y, 10, y + 1))
        self._title_icon.put("#6FA58C", to=(11, 9, 14, 12))
        self.iconphoto(True, self._title_icon)
        tk.Label(header, text="轻管 · 后台程序管理器", bg="white", fg="#202938", font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(header, text="本机实时进程", bg="white", fg="#8590a0", font=("Segoe UI", 9)).pack(side="right", padx=18)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(8, 10))
        body = tk.Frame(self.notebook, bg="#f4f6f9", padx=18, pady=14)
        self.notebook.add(body, text="进程管理")
        monitor_page = tk.Frame(self.notebook, bg="#f4f6f9", padx=18, pady=14)
        self.notebook.add(monitor_page, text="实时监测")
        self._build_monitor_page(monitor_page)
        self.startup_page = tk.Frame(self.notebook, bg="#f4f6f9", padx=18, pady=14)
        self.notebook.add(self.startup_page, text="开机启动")
        self._build_startup_page(self.startup_page)
        titlebar = tk.Frame(body, bg="#f4f6f9")
        titlebar.pack(fill="x")
        left = tk.Frame(titlebar, bg="#f4f6f9")
        left.pack(side="left", fill="x", expand=True)
        tk.Label(left, text="后台程序", bg="#f4f6f9", fg="#202938", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(left, text="列出所有运行进程（包括隐藏后台任务）；无可见窗口不代表多余或未在工作", bg="#f4f6f9", fg="#8792a1", font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))
        self.scan_summary_var = tk.StringVar(value="等待首次扫描")
        tk.Label(left, textvariable=self.scan_summary_var, bg="#f4f6f9", fg="#48658c",
                 font=("Segoe UI", 8), wraplength=900, justify="left").pack(anchor="w", pady=(3, 0))
        toolbar = tk.Frame(body, bg="#f4f6f9")
        toolbar.pack(fill="x", pady=(10, 0))
        self.refresh_btn = ttk.Button(toolbar, text="刷新", command=self.refresh)
        self.refresh_btn.pack(side="right", padx=(8, 0), pady=2)
        ttk.Button(toolbar, text="结束选中进程", command=self.end_selected).pack(side="right", pady=2)
        ttk.Button(toolbar, text="导出报告", command=self.export_report).pack(side="right", padx=(0, 8), pady=2)
        self.list_menu_button = ttk.Menubutton(toolbar, text="清单操作")
        self.list_menu = tk.Menu(self.list_menu_button, tearoff=False)
        self.list_menu.add_command(label="导出分析清单", command=self.export_ai_template)
        self.list_menu.add_command(label="导入关闭清单", command=self.import_close_plan)
        self.list_menu_button.configure(menu=self.list_menu)
        self.list_menu_button.pack(side="right", padx=(0, 8), pady=2)
        ttk.Button(toolbar, text="重复分析", command=self.analyze_duplicates).pack(side="right", padx=(0, 8), pady=2)
        self.more_menu_button = ttk.Menubutton(toolbar, text="更多操作")
        self.more_menu = tk.Menu(self.more_menu_button, tearoff=False)
        self.more_menu.add_command(label="颜色标识", command=self.choose_program_color)
        if not self.is_admin:
            self.more_menu.add_command(label="管理员模式", command=self.restart_as_admin)
        self.more_menu_button.configure(menu=self.more_menu)
        self.more_menu_button.pack(side="right", padx=(0, 8), pady=2)
        cards = tk.Frame(body, bg="#f4f6f9")
        cards.pack(fill="x", pady=12)
        self.total_var, self.memory_var, self.time_var = tk.StringVar(value="—"), tk.StringVar(value="—"), tk.StringVar(value="启动中")
        self._card(cards, "运行中进程", self.total_var, 0)
        self._card(cards, "列表工作集合计", self.memory_var, 1)
        self._card(cards, "最后刷新", self.time_var, 2)
        controls = tk.Frame(body, bg="#f4f6f9")
        controls.pack(fill="x", pady=(0, 10))
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self.render())
        ttk.Entry(controls, textvariable=self.search).pack(side="left", fill="x", expand=True, ipady=6)
        self.drive_filter = tk.StringVar(value="所有磁盘")
        self.drive_box = ttk.Combobox(controls, textvariable=self.drive_filter, state="readonly", width=13,
                                      values=["所有磁盘"])
        self.drive_box.pack(side="left", padx=(8, 0), ipady=3)
        self.drive_box.bind("<<ComboboxSelected>>", lambda _e: self.render())
        self.status_filter = tk.StringVar(value="所有状态")
        self.status_box = ttk.Combobox(controls, textvariable=self.status_filter, state="readonly", width=14,
                                       values=["所有状态", "读取受限", "有可见窗口", "无可见窗口", "白名单", "黑名单标记"])
        self.status_box.pack(side="left", padx=(8, 0), ipady=3)
        self.status_box.bind("<<ComboboxSelected>>", lambda _e: self.render())
        self.memory_sort = tk.StringVar(value="内存：从高到低")
        self.sort_box = ttk.Combobox(controls, textvariable=self.memory_sort, state="readonly", width=16,
                                     values=["内存：从高到低", "内存：从低到高"])
        self.sort_box.pack(side="left", padx=(8, 0), ipady=3)
        self.sort_box.bind("<<ComboboxSelected>>", lambda _e: self.render())
        tablebox = tk.Frame(body, bg="white", highlightbackground="#e4e8ee", highlightthickness=1)
        tablebox.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tablebox, columns=("parent", "window", "instances", "publisher", "status", "memory", "pid", "started"), show="tree headings", selectmode="extended")
        for col, label in [("#0", "程序 / 文件路径"), ("parent", "父进程 / PID"), ("window", "窗口"), ("instances", "同路径进程数"), ("publisher", "发布者 / 签名"), ("status", "状态"), ("memory", "内存"), ("pid", "PID"), ("started", "启动时间")]:
            self.tree.heading(col, text=label, anchor="w")
        self.tree.column("#0", width=220, minwidth=180)
        self.tree.column("parent", width=110, minwidth=95)
        self.tree.column("window", width=80, minwidth=75)
        self.tree.column("instances", width=85, minwidth=80, anchor="center")
        self.tree.column("publisher", width=145, minwidth=115)
        self.tree.column("status", width=95, minwidth=80)
        self.tree.column("memory", width=70, anchor="e")
        self.tree.column("pid", width=50, anchor="e")
        self.tree.column("started", width=110, minwidth=100)
        for color_name, (background, foreground) in PROGRAM_COLORS.items():
            self.tree.tag_configure("program_color_" + color_name, background=background, foreground=foreground)
        scroll = ttk.Scrollbar(tablebox, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda _e: self.show_details())
        self.tree.bind("<Button-3>", self.context_menu)
        self.tree.bind("<<TreeviewSelect>>", self._process_selection_changed, add="+")
        tk.Label(body, text="“无可见窗口”仅表示没有检测到可见顶层窗口；托盘程序、后台服务和由系统宿主显示界面的程序仍可能在工作。结束进程可能丢失未保存数据。", bg="#f4f6f9", fg="#8d97a4", font=("Segoe UI", 8)).pack(anchor="w", pady=(9, 0))
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _card(self, parent, label, var, col):
        card = tk.Frame(parent, bg="white", highlightbackground="#e5e9ef", highlightthickness=1, padx=13, pady=10)
        card.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 9, 0))
        parent.grid_columnconfigure(col, weight=1)
        tk.Label(card, text=label, bg="white", fg="#8993a0", font=("Segoe UI", 8)).pack(anchor="w")
        tk.Label(card, textvariable=var, bg="white", fg="#202938", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(3, 0))

    def _load_startup_records(self):
        for path in (self.startup_state_path, self.legacy_startup_state_path):
            try:
                with open(path, "r", encoding="utf-8") as stream:
                    data = json.load(stream)
                if not isinstance(data, dict):
                    self.startup_state_error = "停用备份文件格式无效：%s" % path
                    return {}
                invalid = [key for key, value in data.items() if not isinstance(value, dict)]
                if invalid:
                    self.startup_state_error = "停用备份中有 %d 条格式无效记录：%s" % (len(invalid), path)
                return {key: value for key, value in data.items() if isinstance(value, dict)}
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                self.startup_state_error = "读取停用备份失败（%s）：%s" % (path, exc)
                return {}
        return {}

    def _save_startup_records(self):
        os.makedirs(os.path.dirname(self.startup_state_path), exist_ok=True)
        temporary = self.startup_state_path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(self.startup_records, stream, ensure_ascii=False, indent=2)
        os.replace(temporary, self.startup_state_path)

    def _build_startup_page(self, parent):
        tk.Label(parent, text="开机启动项", bg="#f4f6f9", fg="#202938",
                 font=("Segoe UI", 18, "bold")).pack(anchor="w")
        tk.Label(parent, text="停用只影响下次登录或开机，不会关闭当前运行中的程序。可随时恢复。",
                 bg="#f4f6f9", fg="#778393", font=("Segoe UI", 9)).pack(anchor="w", pady=(3, 10))
        tk.Label(parent, text="同目标分组表示多个启动入口指向相同目标，不代表多余；注册表/启动文件夹的最终启用状态可能需要到 Windows 设置中核对。",
                 bg="#f4f6f9", fg="#8d6b35", font=("Segoe UI", 8), wraplength=1050, justify="left").pack(anchor="w", pady=(0, 8))
        bar = tk.Frame(parent, bg="#f4f6f9")
        bar.pack(fill="x", pady=(0, 9))
        self.startup_search = tk.StringVar()
        self.startup_match_path = ""
        self.startup_search_programmatic = False
        self.startup_search.trace_add("write", self._startup_search_changed)
        ttk.Entry(bar, textvariable=self.startup_search).pack(side="left", fill="x", expand=True, ipady=5)
        ttk.Button(bar, text="刷新", command=self.refresh_startup_items).pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="停用所选开机启动", command=self.disable_startup_item).pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="恢复所选", command=self.restore_startup_item).pack(side="left", padx=(8, 0))
        self.startup_admin_button = None
        if not self.is_admin:
            self.startup_admin_button = ttk.Button(bar, text="管理员模式", command=self.restart_as_admin)
            self.startup_admin_button.pack(side="left", padx=(8, 0))
        self.startup_error_button = ttk.Button(bar, text="扫描问题（0）", command=self.show_startup_scan_errors)
        self.startup_error_button.pack(side="left", padx=(8, 0))
        frame = tk.Frame(parent, bg="white", highlightbackground="#e4e8ee", highlightthickness=1)
        frame.pack(fill="both", expand=True)
        columns = ("state", "source", "name", "target", "publisher", "command")
        self.startup_tree = ttk.Treeview(frame, columns=columns, show="tree headings", selectmode="browse")
        self.startup_tree.heading("#0", text="目标程序 / 同目标入口", anchor="w")
        for column, label in [("state", "状态"), ("source", "启动位置"), ("name", "启动项"),
                              ("target", "解析出的目标"), ("publisher", "签名/发布者"), ("command", "启动命令 / 参数")]:
            self.startup_tree.heading(column, text=label, anchor="w")
        self.startup_tree.column("#0", width=210, minwidth=160)
        self.startup_tree.column("state", width=100, minwidth=90, stretch=False)
        self.startup_tree.column("source", width=180, minwidth=145, stretch=False)
        self.startup_tree.column("name", width=175, minwidth=130, stretch=False)
        self.startup_tree.column("target", width=230, minwidth=170)
        self.startup_tree.column("publisher", width=165, minwidth=120)
        self.startup_tree.column("command", width=400, minwidth=220)
        yscroll = ttk.Scrollbar(frame, orient="vertical", command=self.startup_tree.yview)
        xscroll = ttk.Scrollbar(frame, orient="horizontal", command=self.startup_tree.xview)
        self.startup_tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        xscroll.pack(side="bottom", fill="x")
        self.startup_tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        tk.Label(parent, text="扫描 Run/RunOnce、启动文件夹、登录/开机计划任务和自动启动服务。计划任务按整项停用，服务只改下次启动类型。应用内专用自启动机制仍可能不在列表里。",
                 bg="#f4f6f9", fg="#8d97a4", font=("Segoe UI", 8)).pack(anchor="w", pady=(8, 0))
        self.startup_status_var = tk.StringVar(value="等待扫描")
        tk.Label(parent, textvariable=self.startup_status_var, bg="#f4f6f9", fg="#687587",
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(3, 0))
        self.startup_errors = []
        self.startup_items = []
        self.startup_rows = {}
        self.after(150, self.refresh_startup_items)

    def _startup_key(self, source, identity):
        return hashlib.sha256((source + "|" + identity).encode("utf-8", "replace")).hexdigest()

    def _powershell_json(self, script, timeout=20):
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            raw = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                          stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.decode("utf-8", "replace").strip() if exc.stderr else str(exc)
            raise RuntimeError(detail)
        value = json.loads(raw.decode("utf-8-sig").strip() or "null")
        return value

    def _powershell_with_payload(self, payload, body, timeout=20):
        encoded_payload = base64.b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("ascii")
        wrapped = "$ErrorActionPreference='Stop'; try { $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))|ConvertFrom-Json; %s } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }" % (encoded_payload, body)
        encoded_script = base64.b64encode(wrapped.encode("utf-16le")).decode("ascii")
        try:
            return subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
                                           stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.decode("utf-8", "replace").strip() if exc.stderr else str(exc)
            raise RuntimeError(detail)

    def _resolve_startup_command(self, command, extra_args=""):
        full_command = (str(command or "") + (" " + str(extra_args) if extra_args else "")).strip()
        expanded_command = os.path.expandvars(str(command or ""))
        if extra_args:
            parse_command = subprocess.list2cmdline([expanded_command]) + " " + os.path.expandvars(str(extra_args))
        else:
            parse_command = expanded_command
        args = windows_command_args(parse_command)
        raw_target = args[0] if args else str(command or "").strip().strip('"')
        target = os.path.expandvars(raw_target).strip().strip('"')
        if target and not str(command or "").strip().startswith('"'):
            # Resolve common unquoted service paths containing spaces by checking real .exe prefixes.
            for match in re.finditer(r"(?i)\.exe(?=\s|$)", expanded_command):
                possible = expanded_command[:match.end()].strip().strip('"')
                if os.path.isfile(possible):
                    target = possible
                    break
        if target.lower().startswith("\\systemroot\\"):
            target = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), target[len("\\SystemRoot\\"):])
        if target.startswith("\\??\\"):
            target = target[4:]
        if target and not os.path.isabs(target):
            target = shutil.which(target) or target
        if target and os.path.isabs(target):
            target = os.path.normpath(target)
        basename = os.path.basename(target).casefold()
        wrapper_names = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                         "rundll32.exe", "regsvr32.exe", "mshta.exe", "dllhost.exe", "svchost.exe"}
        payload_resolved = False
        if basename in wrapper_names and args:
            candidates = []
            if basename in ("cmd.exe", "powershell.exe", "pwsh.exe"):
                for index, arg in enumerate(args[1:], 1):
                    if arg.casefold() in ("/c", "/k", "-file", "-f", "-command") and index + 1 < len(args):
                        candidates.append(args[index + 1])
            elif basename in ("wscript.exe", "cscript.exe", "mshta.exe"):
                candidates.extend(args[1:2])
            elif basename == "rundll32.exe":
                candidates.extend(args[1:2])
            elif basename == "regsvr32.exe":
                candidates.extend(arg for arg in args[1:] if arg.lower().endswith(".dll"))
            for candidate in candidates:
                candidate = os.path.expandvars(candidate.split(",", 1)[0].strip('"'))
                if os.path.isfile(candidate):
                    target = os.path.normpath(candidate)
                    payload_resolved = True
                    break
        normalized = os.path.normcase(target).casefold() if target else ""
        # When a wrapper's payload is not a file path, keep its full command separate.
        group_key = normalized if basename not in wrapper_names or payload_resolved else (normalized + "|" + full_command.casefold())
        return target or "无法解析", full_command, group_key, basename in wrapper_names

    def _resolve_shortcuts(self, items):
        shortcuts = [item for item in items if item.get("kind") == "folder" and item.get("path", "").lower().endswith(".lnk")]
        if not shortcuts:
            return
        payload = [{"id": item["id"], "path": item["path"]} for item in shortcuts]
        body = ("$shell=New-Object -ComObject WScript.Shell; $r=@(foreach($x in $p){try{$s=$shell.CreateShortcut($x.path);"
                "[pscustomobject]@{Id=$x.id;Target=$s.TargetPath;Arguments=$s.Arguments;WorkingDirectory=$s.WorkingDirectory}}catch{"
                "[pscustomobject]@{Id=$x.id;Target='';Arguments='';WorkingDirectory=''}}});"
                "ConvertTo-Json -InputObject $r -Depth 4 -Compress")
        try:
            raw = self._powershell_with_payload(payload, body, timeout=15)
            result = json.loads(raw.decode("utf-8-sig").strip() or "[]")
            if isinstance(result, dict):
                result = [result]
            by_id = {entry.get("Id"): entry for entry in result if isinstance(entry, dict)}
            for item in shortcuts:
                resolved = by_id.get(item["id"], {})
                target, command, group_key, wrapper = self._resolve_startup_command(
                    resolved.get("Target", ""), resolved.get("Arguments", ""))
                item["target"] = target
                item["command"] = command or item["path"]
                item["group_key"] = group_key or item["id"]
                item["wrapper"] = wrapper
        except Exception as exc:
            self.startup_errors.append("快捷方式目标解析失败：%s" % exc)
            for item in shortcuts:
                item["target"] = "快捷方式目标无法解析"
                item["group_key"] = item["id"]

    def _enrich_startup_targets(self, items):
        windows_dir = os.path.normcase(os.path.abspath(os.environ.get("WINDIR", r"C:\Windows")))
        signature_rows = []
        for item in items:
            if item.get("kind") == "folder" and item.get("path", "").lower().endswith(".url"):
                try:
                    with open(item["path"], "r", encoding="utf-8-sig", errors="replace") as stream:
                        url = next((line.split("=", 1)[1].strip() for line in stream if line.strip().upper().startswith("URL=")), "")
                except OSError:
                    url = ""
                item["target"] = url or "URL 未读取"
                item["group_key"] = url.casefold() or item["id"]
                item["publisher"] = "网址快捷方式"
                item["protected"] = False
                continue
            if item.get("kind") == "folder" and not item.get("target"):
                item["target"] = item["path"]
                item["command"] = item["path"]
                item["group_key"] = os.path.normcase(os.path.abspath(item["path"])).casefold()
                item["wrapper"] = False
            elif item.get("kind") in ("registry", "task", "service") and not item.get("target"):
                item["target"], item["command"], item["group_key"], item["wrapper"] = self._resolve_startup_command(
                    item.get("command", ""), item.get("arguments", ""))
            target = item.get("target", "")
            target_parts = [part.strip() for part in target.split(" | ") if part.strip()]
            normalized_parts = [os.path.normcase(os.path.abspath(part)) for part in target_parts if os.path.isabs(part)]
            normalized = normalized_parts[0] if len(normalized_parts) == 1 else ""
            in_windows = any(path == windows_dir or path.startswith(windows_dir + os.sep) for path in normalized_parts)
            is_microsoft_task = item.get("kind") == "task" and str(item.get("task_path", "")).casefold().startswith("\\microsoft\\windows\\")
            unknown_service = item.get("kind") == "service" and not normalized_parts
            item["system_target"] = in_windows
            item["protected"] = (item.get("kind") == "service" and (in_windows or unknown_service)) or is_microsoft_task
            item["protection_reason"] = "服务目标无法识别，因此禁止修改" if unknown_service else (
                "Microsoft Windows 计划任务受保护" if is_microsoft_task else ("目标位于 Windows 系统目录" if in_windows else ""))
            item["publisher"] = "Windows 目录目标（需谨慎）" if in_windows else (
                "服务目标无法识别（保护）" if unknown_service else ("Microsoft Windows 系统任务（保护）" if is_microsoft_task else "正在核验…"))
            for path in normalized_parts:
                if os.path.isfile(path):
                    signature_rows.append({"path": path, "publisher": ""})
        signatures = {}
        for start in range(0, len(signature_rows), 80):
            chunk = signature_rows[start:start + 80]
            self._enrich_publishers(chunk)
            signatures.update({row["path"].casefold(): row.get("publisher", "无法确认") for row in chunk})
        for item in items:
            if item.get("protected"):
                continue
            target_parts = [part.strip() for part in item.get("target", "").split(" | ") if part.strip()]
            item["publisher"] = "；".join(dict.fromkeys(signatures.get(part.casefold(), "无法确认目标签名")
                                                          for part in target_parts)) or "无法确认目标"

    def _read_registry_startup(self):
        entries = []
        roots = [("当前用户", winreg.HKEY_CURRENT_USER), ("所有用户", winreg.HKEY_LOCAL_MACHINE)]
        startup_keys = [(r"Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
                        (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
                        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "策略 Run")]
        native_arch = os.environ.get("PROCESSOR_ARCHITEW6432", os.environ.get("PROCESSOR_ARCHITECTURE", ""))
        is_64bit_windows = sys.maxsize > 2**32 or "64" in native_arch.upper() or "ARM64" in native_arch.upper()
        views = [("64 位", getattr(winreg, "KEY_WOW64_64KEY", 0)), ("32 位", getattr(winreg, "KEY_WOW64_32KEY", 0))] if is_64bit_windows else [("32 位", 0)]
        for hive_label, root in roots:
            for run_key, run_label in startup_keys:
                key_views = [("共享", 0)] if "\\policies\\" in run_key.casefold() else views
                for view_label, view_flag in key_views:
                    try:
                        key = winreg.OpenKey(root, run_key, 0, winreg.KEY_READ | view_flag)
                    except FileNotFoundError:
                        continue
                    except OSError as exc:
                        self.startup_errors.append("读取 %s %s %s 失败：%s" % (hive_label, run_label, view_label, exc))
                        continue
                    try:
                        index = 0
                        while True:
                            try:
                                name, value, value_type = winreg.EnumValue(key, index)
                            except OSError as exc:
                                if getattr(exc, "winerror", None) not in (259, None):
                                    self.startup_errors.append("枚举 %s %s 失败：%s" % (hive_label, run_label, exc))
                                break
                            index += 1
                            identity = "%s|%s|%s|%s" % (hive_label, view_label, run_key, name)
                            entry_id = self._startup_key("registry", identity)
                            command = str(value)
                            entries.append({"id": entry_id, "kind": "registry", "source": "%s %s（%s）" % (hive_label, run_label, view_label),
                                            "name": str(name), "command": command, "hive": hive_label,
                                            "view": view_label, "key": run_key, "value_type": int(value_type),
                                            "value": value, "run_label": run_label})
                    finally:
                        winreg.CloseKey(key)
        return entries

    def _read_folder_startup(self):
        entries = []
        folders = [("当前用户启动文件夹", os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")),
                   ("所有用户启动文件夹", os.path.join(os.environ.get("PROGRAMDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))]
        for label, folder in folders:
            if not os.path.isdir(folder):
                continue
            try:
                children = os.listdir(folder)
            except OSError as exc:
                self.startup_errors.append("读取启动文件夹失败 %s：%s" % (folder, exc))
                continue
            for name in children:
                path = os.path.join(folder, name)
                if not os.path.isfile(path) or os.path.splitext(name)[1].casefold() not in (
                        ".lnk", ".url", ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta"):
                    continue
                entry_id = self._startup_key("folder", os.path.normcase(os.path.abspath(path)))
                entries.append({"id": entry_id, "kind": "folder", "source": label, "name": name, "command": path, "path": path})
        return entries

    def _read_scheduled_tasks(self):
        script = r"""
$ErrorActionPreference='Stop'
$rows=@(foreach($t in Get-ScheduledTask){
  $tr=@($t.Triggers | ForEach-Object {$_.CimClass.CimClassName})
  if(@($tr | Where-Object {$_ -match 'Boot|Logon'}).Count -gt 0){
    $ac=@($t.Actions | ForEach-Object {[pscustomobject]@{ActionType=$_.CimClass.CimClassName;Execute=$_.Execute;Arguments=$_.Arguments;WorkingDirectory=$_.WorkingDirectory;ClassId=$_.ClassId;Data=$_.Data}})
    [pscustomobject]@{TaskPath=$t.TaskPath;TaskName=$t.TaskName;Enabled=([string]$t.State -ne 'Disabled');State=[string]$t.State;Triggers=$tr;Actions=$ac}
  }
})
ConvertTo-Json -InputObject $rows -Depth 6 -Compress
"""
        try:
            result = self._powershell_json(script, timeout=35)
        except Exception as exc:
            self.startup_errors.append("读取计划任务失败：%s" % exc)
            return []
        if isinstance(result, dict):
            result = [result]
        entries = []
        for task in result or []:
            task_path = str(task.get("TaskPath", "\\"))
            task_name = str(task.get("TaskName", ""))
            task_id = self._startup_key("task", task_path + task_name)
            actions = task.get("Actions") or []
            if isinstance(actions, dict):
                actions = [actions]
            commands, targets, group_keys = [], [], []
            for action in actions:
                command, args = str(action.get("Execute", "") or ""), str(action.get("Arguments", "") or "")
                class_id = str(action.get("ClassId", "") or "")
                action_type = str(action.get("ActionType", "") or "")
                if not command and class_id:
                    label = "COM 处理器 %s" % class_id
                    commands.append(label + (" · " + str(action.get("Data")) if action.get("Data") else ""))
                    targets.append(label)
                    group_keys.append("com:" + class_id.casefold())
                    continue
                working = os.path.expandvars(str(action.get("WorkingDirectory", "") or ""))
                resolved_command = command
                if working and command and not os.path.isabs(os.path.expandvars(command)):
                    resolved_command = os.path.join(working, command)
                target, full_command, group_key, _wrapper = self._resolve_startup_command(resolved_command, args)
                if working:
                    full_command += " [工作目录：%s]" % working
                if action_type:
                    full_command += " [动作类型：%s]" % action_type
                commands.append(full_command)
                targets.append(target)
                group_keys.append(group_key)
            triggers = task.get("Triggers") or []
            if isinstance(triggers, str):
                triggers = [triggers]
            startup_triggers = [trigger for trigger in triggers if "Boot" in trigger or "Logon" in trigger]
            other_triggers = [trigger for trigger in triggers if trigger not in startup_triggers]
            trigger_labels = ["开机" if "Boot" in trigger else "登录" if "Logon" in trigger else trigger for trigger in startup_triggers]
            entries.append({"id": task_id, "kind": "task", "source": "计划任务 · " + ", ".join(trigger_labels),
                            "name": task_name, "command": " | ".join(commands), "target": " | ".join(targets) or "无可执行动作",
                            "group_key": "|".join(sorted(set(group_keys))) or task_id, "task_path": task_path,
                            "task_name": task_name, "enabled": bool(task.get("Enabled")),
                            "triggers": triggers, "other_triggers": other_triggers,
                            "action_blocked_reason": ("此计划任务还包含其他触发器；为避免连带停用定时任务，本版本不提供此项停用。" if other_triggers else ""),
                            "disabled": not bool(task.get("Enabled")), "publisher": "计划任务目标待核验"})
        return entries

    def _read_auto_services(self):
        script = r"""
$ErrorActionPreference='Stop'
$rows=@(foreach($s in Get-CimInstance Win32_Service -Filter "StartMode='Auto'"){
  $target=$s.PathName
  if($s.PathName -match '(?i)svchost\.exe'){
    try{$dll=(Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$s.Name+'\Parameters') -Name ServiceDll -ErrorAction Stop).ServiceDll;if($dll){$target=$dll}}catch{}
  }
  [pscustomobject]@{Name=$s.Name;DisplayName=$s.DisplayName;State=$s.State;StartMode=$s.StartMode;Delayed=[bool]$s.DelayedAutoStart;PathName=$s.PathName;TargetPath=$target;StartName=$s.StartName}
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
"""
        try:
            result = self._powershell_json(script, timeout=35)
        except Exception as exc:
            self.startup_errors.append("读取自动启动服务失败：%s" % exc)
            return []
        if isinstance(result, dict):
            result = [result]
        entries = []
        for service in result or []:
            name = str(service.get("Name", ""))
            path_name = str(service.get("PathName", ""))
            target_command = str(service.get("TargetPath") or path_name)
            target, command, group_key, _wrapper = self._resolve_startup_command(target_command)
            entry_id = self._startup_key("service", name.casefold())
            entries.append({"id": entry_id, "kind": "service", "source": "Windows 服务 · 自动启动" + ("（延迟）" if service.get("Delayed") else ""),
                            "name": str(service.get("DisplayName") or name), "service_name": name,
                            "command": path_name, "target": target,
                            "group_key": ("service:" + name.casefold()) if os.path.basename(target).casefold() == "svchost.exe" else group_key,
                            "start_mode": str(service.get("StartMode", "Auto")), "delayed": bool(service.get("Delayed")),
                            "service_state": str(service.get("State", "未知")), "service_account": str(service.get("StartName", "")),
                            "publisher": "服务目标待核验"})
        return entries

    def _startup_items(self):
        items = []
        self.startup_errors = []
        if self.startup_state_error:
            self.startup_errors.append(self.startup_state_error)
        try:
            items.extend(self._read_registry_startup())
        except Exception as exc:
            self.startup_errors.append("读取注册表启动项失败：%s" % exc)
        try:
            folder_items = self._read_folder_startup()
            items.extend(folder_items)
            self._resolve_shortcuts(folder_items)
        except Exception as exc:
            self.startup_errors.append("读取启动文件夹失败：%s" % exc)
        try:
            items.extend(self._read_scheduled_tasks())
        except Exception as exc:
            self.startup_errors.append("读取计划任务失败：%s" % exc)
        try:
            items.extend(self._read_auto_services())
        except Exception as exc:
            self.startup_errors.append("读取自动启动服务失败：%s" % exc)
        try:
            self._enrich_startup_targets(items)
        except Exception as exc:
            self.startup_errors.append("解析启动目标或签名失败：%s" % exc)
        active_ids = {item["id"] for item in items}
        for entry_id, record in self.startup_records.items():
            if entry_id in active_ids:
                for item in items:
                    if item["id"] == entry_id and item.get("kind") == "task" and item.get("disabled"):
                        item["has_backup"] = True
                continue
            if entry_id not in active_ids:
                items.append({"id": entry_id, "kind": record.get("kind"), "source": record.get("source", "已停用启动项"),
                              "name": record.get("name", "未知项目"), "command": record.get("command", record.get("original_path", "")),
                              "target": record.get("target", record.get("original_path", "未知目标")),
                              "group_key": record.get("group_key", record.get("target", entry_id)),
                              "publisher": record.get("publisher", "已停用备份"), "disabled": True, "has_backup": True,
                              "kind": record.get("kind")})
        return items

    def refresh_startup_items(self):
        self.startup_status_var.set("正在扫描常见启动来源…")
        self.startup_error_button.configure(text="扫描中…", state="disabled")
        self.startup_scan_generation = getattr(self, "startup_scan_generation", 0) + 1
        generation = self.startup_scan_generation
        def work():
            items = self._startup_items()
            errors = list(self.startup_errors)
            self.after(0, lambda: self._apply_startup_scan(generation, items, errors))
        threading.Thread(target=work, daemon=True).start()

    def _apply_startup_scan(self, generation, items, errors):
        if generation != self.startup_scan_generation:
            return
        self.startup_items = items
        self.startup_errors = errors
        self.startup_error_button.configure(text="扫描问题（%d）" % len(errors), state="normal")
        self.startup_status_var.set("扫描到 %d 条启动入口%s" % (len(items), "；%d 个来源读取失败/受限" % len(errors) if errors else ""))
        self.render_startup_items()
        if self.startup_match_path and not self.startup_rows:
            self.startup_status_var.set("没有找到与所选进程完整路径匹配的启动入口；它可能由计划任务、服务或程序内部启动器间接拉起。")

    def show_startup_scan_errors(self):
        if self.startup_errors:
            messagebox.showwarning("扫描问题", "以下位置没有完整读取，列表可能缺项：\n\n" + "\n".join("• " + error for error in self.startup_errors))
        else:
            messagebox.showinfo("扫描结果", "本次列出的支持来源均已读取。Windows 应用内自启动或其他专用机制仍可能不在扫描范围内。")

    def _startup_search_changed(self, *_args):
        if not self.startup_search_programmatic:
            self.startup_match_path = ""
        self.render_startup_items()

    def render_startup_items(self):
        if not hasattr(self, "startup_tree"):
            return
        self.startup_tree.delete(*self.startup_tree.get_children())
        self.startup_rows = {}
        query = self.startup_search.get().strip().casefold()
        groups = {}
        for item in self.startup_items:
            if self.startup_match_path:
                wanted = os.path.normcase(os.path.normpath(self.startup_match_path)).casefold()
                target = item.get("target", "")
                target_paths = [part.strip() for part in target.split(" | ") if part.strip()]
                normalized_targets = {os.path.normcase(os.path.normpath(part)).casefold()
                                      for part in target_paths if os.path.isabs(part)}
                unresolved = target in ("无法解析", "快捷方式目标无法解析", "无可执行动作", "URL 未读取", "无法确认")
                normalized_command = os.path.normcase(item.get("command", "")).casefold()
                if wanted not in normalized_targets and not (unresolved and wanted in normalized_command):
                    continue
            text = " ".join((item.get("name", ""), item.get("source", ""), item.get("target", ""),
                             item.get("publisher", ""), item.get("command", ""))).casefold()
            if query and query not in text:
                continue
            group_key = item.get("group_key") or item.get("id")
            groups.setdefault(group_key, []).append(item)
        for group_index, (group_key, members) in enumerate(sorted(groups.items(), key=lambda pair: str(pair[0]).casefold())):
            group_id = "startup_group_%d_%s" % (group_index, hashlib.sha1(str(group_key).encode("utf-8", "replace")).hexdigest()[:10])
            target = members[0].get("target", "未知目标")
            shown_target = self._startup_tree_text(target)
            self.startup_tree.insert("", "end", iid=group_id,
                                     text="%s（%d 个同目标入口；不代表多余）" % (shown_target, len(members)),
                                     values=("分组", "", "", shown_target, "", ""), open=len(members) == 1)
            for item in sorted(members, key=lambda entry: (entry.get("source", ""), entry.get("name", ""))):
                if item.get("disabled") and item.get("has_backup"):
                    state = "已停用（本工具）"
                elif item.get("kind") == "task" and item.get("disabled"):
                    state = "Windows 已停用"
                elif item.get("protected"):
                    state = "目标不明·保护" if item.get("protection_reason", "").startswith("服务目标无法识别") else "系统保护"
                elif item.get("system_target"):
                    state = "Windows目标·谨慎"
                elif item.get("action_blocked_reason"):
                    state = "含其他触发器·保护"
                elif item.get("kind") == "task" and item.get("other_triggers"):
                    state = "开机触发*"
                elif item.get("kind") in ("registry", "folder"):
                    state = "入口存在·状态待核"
                elif item.get("kind") == "service":
                    state = "自动启动·用途待核"
                else:
                    state = "开机触发"
                command = item.get("command", "")
                if item.get("kind") == "service":
                    command += " · 当前状态：%s · 服务账号：%s" % (item.get("service_state", "未知"), item.get("service_account", ""))
                if item.get("kind") == "task" and item.get("other_triggers"):
                    command += " · 还含其他触发器：" + ", ".join(item["other_triggers"])
                values = (state, item.get("source", ""), item.get("name", ""),
                          item.get("target", "未知目标"), item.get("publisher", "未知"), command)
                safe_values = tuple(self._startup_tree_text(value) for value in values)
                self.startup_tree.insert(group_id, "end", iid=item["id"],
                                         text=self._startup_tree_text(item.get("name", "")),
                                         values=safe_values)
                self.startup_rows[item["id"]] = item

    @staticmethod
    def _startup_tree_text(value):
        """Avoid Tcl 8.6.8 parsing quoted Windows paths as malformed list data."""
        text = str(value or "")
        return "› " + text if text.startswith('"') else text

    def disable_startup_item(self):
        selection = self.startup_tree.selection()
        if not selection:
            messagebox.showinfo("选择启动项", "请展开目标程序分组，再选择具体的启动入口。")
            return
        item = self.startup_rows.get(selection[0])
        if not item:
            messagebox.showinfo("选择具体入口", "请展开目标程序分组，再选择具体的启动入口。")
            return
        if item.get("disabled") or item.get("kind") == "task" and not item.get("enabled"):
            messagebox.showinfo("无法停用", "该项目已经停用，或当前列表状态已变化。请刷新后重试。")
            return
        if item.get("protected"):
            messagebox.showwarning("启动项受保护", "%s\n\n%s" % (item.get("protection_reason", "系统启动项受保护，管理器不会停用它。"), item.get("target", "")))
            return
        if item.get("action_blocked_reason"):
            messagebox.showwarning("为避免影响其他任务", item["action_blocked_reason"])
            return
        if item.get("kind") not in ("registry", "folder", "task", "service"):
            messagebox.showwarning("暂不支持", "这个启动来源当前不能修改。")
            return
        warning = "停用后只影响下次登录或开机，不会结束当前运行中的程序。"
        if item.get("kind") == "task":
            warning += "\n\n这会停用整个计划任务；此项只包含开机/登录触发器，恢复后可重新启用。"
        elif item.get("kind") == "service":
            warning += "\n\n这会把服务启动类型改为‘手动’，不会停止当前服务；应用仍可按需启动它。依赖关系或服务触发器可能仍会启动它，依赖它的应用或硬件功能也可能受影响。"
        if item.get("run_label") == "RunOnce":
            warning += "\n\n这是一次性启动项，通常用于安装或更新流程。停用可能中断下一次登录时待完成的操作。"
        if item.get("system_target") and not item.get("protected"):
            warning += "\n\n目标位于 Windows 目录。虽然入口可恢复，但停用可能影响输入法、登录组件或系统功能，请确认用途。"
        target_parts = [part.strip() for part in item.get("target", "").split(" | ") if part.strip()]
        if item.get("target") in ("无法解析", "快捷方式目标无法解析", "无可执行动作") or (
                item.get("kind") != "folder" and target_parts and not any(os.path.isabs(part) for part in target_parts)):
            warning += "\n\n程序无法准确识别目标，只能看到原始入口和命令。若你不能确认它对应哪个软件，请取消操作并先核对命令；名字陌生或签名未知本身不代表它可以停用。"
        prompt = "停用所选入口？\n\n来源：%s\n名称：%s\n目标：%s\n命令：%s\n\n%s" % (
            item.get("source", ""), item.get("name", ""), item.get("target", "未知目标"), item.get("command", ""), warning)
        if not messagebox.askyesno("停用开机启动", prompt):
            return
        record = dict(item)
        backup_path = None
        backup_registered = False
        try:
            if item["kind"] == "registry":
                root = winreg.HKEY_CURRENT_USER if item["hive"] == "当前用户" else winreg.HKEY_LOCAL_MACHINE
                view_flag = (getattr(winreg, "KEY_WOW64_64KEY", 0) if item["view"] == "64 位" else
                             getattr(winreg, "KEY_WOW64_32KEY", 0) if item["view"] == "32 位" else 0)
                access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | view_flag
                with winreg.OpenKey(root, item["key"], 0, access) as key:
                    value, value_type = winreg.QueryValueEx(key, item["name"])
                    if str(value) != item["command"] or int(value_type) != item["value_type"]:
                        raise RuntimeError("启动项内容已变化；为避免改错，请刷新列表后重新选择。")
                    record["value"] = value
                    record["disabled"] = True
                    self.startup_records[item["id"]] = record
                    try:
                        self._save_startup_records()
                    except Exception:
                        self.startup_records.pop(item["id"], None)
                        raise
                    try:
                        winreg.DeleteValue(key, item["name"])
                    except Exception:
                        self.startup_records.pop(item["id"], None)
                        self._save_startup_records()
                        raise
            elif item["kind"] == "folder":
                os.makedirs(self.startup_backup_dir, exist_ok=True)
                backup_path = os.path.join(self.startup_backup_dir, uuid.uuid4().hex + os.path.splitext(item["path"])[1].lower())
                shutil.copy2(item["path"], backup_path)
                with open(item["path"], "rb") as original, open(backup_path, "rb") as backup:
                    if hashlib.sha256(original.read()).digest() != hashlib.sha256(backup.read()).digest():
                        os.remove(backup_path)
                        raise RuntimeError("快捷方式备份校验失败，原启动项没有更改。")
                record["backup_path"] = backup_path
                record["original_path"] = item["path"]
                record["disabled"] = True
                self.startup_records[item["id"]] = record
                self._save_startup_records()
                backup_registered = True
                try:
                    os.remove(item["path"])
                except Exception:
                    self.startup_records.pop(item["id"], None)
                    self._save_startup_records()
                    backup_registered = False
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                    raise
            elif item["kind"] == "task":
                record["disabled"] = True
                record["has_backup"] = True
                self.startup_records[item["id"]] = record
                try:
                    self._save_startup_records()
                except Exception:
                    self.startup_records.pop(item["id"], None)
                    raise
                payload = {"TaskPath": item["task_path"], "TaskName": item["task_name"]}
                body = ("$t=Get-ScheduledTask -TaskPath $p.TaskPath -TaskName $p.TaskName -ErrorAction Stop; "
                        "if([string]$t.State -eq 'Disabled'){throw '任务已被其他操作停用，请刷新。'}; "
                        "Disable-ScheduledTask -TaskPath $p.TaskPath -TaskName $p.TaskName -ErrorAction Stop | Out-Null")
                try:
                    self._powershell_with_payload(payload, body, timeout=25)
                except Exception:
                    self.startup_records.pop(item["id"], None)
                    self._save_startup_records()
                    raise
            elif item["kind"] == "service":
                record["disabled"] = True
                record["has_backup"] = True
                self.startup_records[item["id"]] = record
                try:
                    self._save_startup_records()
                except Exception:
                    self.startup_records.pop(item["id"], None)
                    raise
                payload = {"Name": item["service_name"]}
                body = ("$s=Get-CimInstance Win32_Service | Where-Object {$_.Name -eq $p.Name}; "
                        "if(-not $s -or $s.StartMode -ne 'Auto'){throw '服务启动类型已变化，请刷新。'}; "
                        "& sc.exe config $p.Name 'start=' 'demand' | Out-Null; "
                        "if($LASTEXITCODE -ne 0){throw ('sc.exe 配置失败，代码 '+$LASTEXITCODE)}")
                try:
                    self._powershell_with_payload(payload, body, timeout=25)
                except Exception:
                    self.startup_records.pop(item["id"], None)
                    self._save_startup_records()
                    raise
            else:
                raise RuntimeError("不支持此类启动项。")
            self.refresh_startup_items()
            messagebox.showinfo("已停用", "已停用此开机启动项。当前正在运行的程序不会被关闭。")
        except PermissionError:
            messagebox.showerror("权限不足", "无法修改这个启动项。请使用‘管理员模式’重新打开管理器后再试。")
        except Exception as exc:
            if backup_path and not backup_registered and os.path.exists(backup_path):
                try:
                    os.remove(backup_path)
                except OSError:
                    pass
            self.startup_records.pop(item["id"], None) if item["kind"] == "folder" and not backup_registered else None
            error_text = str(exc)
            if item.get("kind") in ("task", "service") and not self.is_admin:
                error_text += "\n\n此项通常需要管理员权限，请点击页面上的‘管理员模式’后再试。"
            messagebox.showerror("停用失败", error_text)
            self.refresh_startup_items()

    def restore_startup_item(self):
        selection = self.startup_tree.selection()
        if not selection:
            messagebox.showinfo("选择启动项", "请先选择一个已停用的项目。")
            return
        entry_id = selection[0]
        if entry_id not in self.startup_rows:
            messagebox.showinfo("选择具体入口", "请展开目标程序分组，再选择具体的已停用入口。")
            return
        record = self.startup_records.get(entry_id)
        if not record:
            messagebox.showinfo("无法恢复", "没有找到该项目的停用备份。")
            return
        if not messagebox.askyesno("恢复开机启动", "恢复这个项目的开机启动？\n\n%s\n%s" % (record.get("name", "未知项目"), record.get("command", record.get("original_path", "")))):
            return
        try:
            if record.get("kind") == "registry":
                root = winreg.HKEY_CURRENT_USER if record["hive"] == "当前用户" else winreg.HKEY_LOCAL_MACHINE
                view_flag = (getattr(winreg, "KEY_WOW64_64KEY", 0) if record["view"] == "64 位" else
                             getattr(winreg, "KEY_WOW64_32KEY", 0) if record["view"] == "32 位" else 0)
                access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | view_flag
                with winreg.OpenKey(root, record["key"], 0, access) as key:
                    try:
                        winreg.QueryValueEx(key, record["name"])
                    except FileNotFoundError:
                        pass
                    else:
                        raise RuntimeError("同名启动项已经存在。为避免覆盖它，未执行恢复。")
                    winreg.SetValueEx(key, record["name"], 0, record["value_type"], record["value"])
            elif record.get("kind") == "folder":
                destination = record["original_path"]
                if os.path.exists(destination):
                    raise RuntimeError("原启动文件位置已有同名文件。为避免覆盖，未执行恢复。")
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                temporary = destination + ".qg-restore-" + uuid.uuid4().hex
                try:
                    shutil.copy2(record["backup_path"], temporary)
                    with open(temporary, "rb") as restored, open(record["backup_path"], "rb") as backup:
                        if hashlib.sha256(restored.read()).digest() != hashlib.sha256(backup.read()).digest():
                            raise RuntimeError("恢复后的文件校验失败。")
                    os.rename(temporary, destination)
                finally:
                    if os.path.exists(temporary):
                        os.remove(temporary)
            elif record.get("kind") == "task":
                payload = {"TaskPath": record["task_path"], "TaskName": record["task_name"]}
                body = "Enable-ScheduledTask -TaskPath $p.TaskPath -TaskName $p.TaskName -ErrorAction Stop | Out-Null"
                self._powershell_with_payload(payload, body, timeout=25)
            elif record.get("kind") == "service":
                prior_mode = str(record.get("start_mode", "Auto")).casefold()
                mode = "delayed-auto" if record.get("delayed") else ("auto" if prior_mode == "auto" else "demand")
                payload = {"Name": record["service_name"], "StartMode": mode}
                body = ("& sc.exe config $p.Name 'start=' $p.StartMode | Out-Null; "
                        "if($LASTEXITCODE -ne 0){throw ('sc.exe 配置失败，代码 '+$LASTEXITCODE)}")
                self._powershell_with_payload(payload, body, timeout=25)
            else:
                raise RuntimeError("不支持恢复此类启动项。")
            backup_path = record.get("backup_path")
            del self.startup_records[entry_id]
            try:
                self._save_startup_records()
            except Exception:
                self.startup_records[entry_id] = record
                raise
            if backup_path and os.path.exists(backup_path):
                os.remove(backup_path)
            self.refresh_startup_items()
            messagebox.showinfo("已恢复", "已恢复开机启动设置。")
        except PermissionError:
            messagebox.showerror("权限不足", "无法恢复这个启动项。请使用‘管理员模式’重新打开管理器后再试。")
        except Exception as exc:
            messagebox.showerror("恢复失败", str(exc))

    def show_selected_startup_item(self):
        process = self.selected()
        if not process:
            return
        path = process.get("path", "")
        if not path or path.startswith("不可读取"):
            messagebox.showinfo("路径不可读", "当前进程路径不可读，无法精确匹配启动项。请先用管理员模式刷新进程列表。")
            return
        self.startup_match_path = path
        self.startup_search_programmatic = True
        self.startup_search.set(os.path.basename(path))
        self.startup_search_programmatic = False
        self.notebook.select(self.startup_page)
        self.refresh_startup_items()

    def refresh(self):
        if self.after_refresh:
            self.after_cancel(self.after_refresh)
            self.after_refresh = None
        self._refresh_generation += 1
        generation = self._refresh_generation
        self._refresh_in_progress = True
        self.time_var.set("扫描中…")
        self.scan_summary_var.set("正在读取 Windows 进程快照…")
        self.refresh_btn.configure(state="disabled")
        def work():
            try:
                data = snapshot_processes()
                self._enrich_publishers(data)
                self.after(0, lambda: self._apply(data, generation))
            except Exception as exc:
                self.after(0, lambda error=str(exc): self._refresh_failed(error, generation))
        threading.Thread(target=work, daemon=True).start()

    def _refresh_failed(self, error, generation=None):
        if generation is not None and generation != self._refresh_generation:
            return
        self._refresh_in_progress = False
        self.refresh_btn.configure(state="normal")
        self.time_var.set("扫描失败，保留上次列表")
        self.last_process_scan_error = error
        self.scan_summary_var.set("扫描失败，当前显示上次成功列表；错误：%s" % error)
        self._schedule_auto_refresh()

    def _apply(self, data, generation=None, selection_identities=None):
        if generation is not None and generation != self._refresh_generation:
            return
        self._refresh_in_progress = False
        if self.after_refresh:
            self.after_cancel(self.after_refresh)
            self.after_refresh = None
        if selection_identities is None:
            self._selection_restore_identities = {
                int(iid): self.rows.get(int(iid), {}).get("creation_time_ticks")
                for iid in self.tree.selection()
                if iid.isdigit() and self.rows.get(int(iid), {}).get("creation_time_ticks") is not None
            }
        else:
            self._selection_restore_identities = dict(selection_identities)
        visible_pids = visible_window_process_ids()
        for item in data:
            item["window_state"] = "有可见窗口" if item["pid"] in visible_pids else "无可见窗口"
        self.rows = {x["pid"]: x for x in data}
        path_limited = sum(not x.get("path_readable", not x["path"].startswith("不可读取")) for x in data)
        memory_limited = sum(not x.get("memory_readable", x["memory"] > 0) for x in data)
        self.last_process_scan_error = ""
        summary = "扫描成功：%d 个进程；路径受限 %d 个，内存读取受限 %d 个。名称来自系统进程快照。" % (
            len(data), path_limited, memory_limited)
        vgame_rows = [x for x in data if "vgame" in x["name"].casefold() or "vgame" in x["path"].casefold()]
        if vgame_rows:
            matches = "、".join("%s (PID %s)" % (x["name"], x["pid"]) for x in vgame_rows[:5])
            summary += " 检测到 VGAME 相关项：" + matches
        else:
            summary += " 本次快照未发现名称/路径含 VGAME 的项；如任务管理器仍显示，请按其实际 exe 名和 PID核对。"
        self.scan_summary_var.set(summary)
        self.total_var.set(str(len(data)))
        self.memory_var.set(fmt_bytes(sum(x["memory"] for x in data)))
        self.time_var.set(time.strftime("%H:%M:%S"))
        import ntpath
        observed_drives = {ntpath.splitdrive(x["path"])[0].upper() for x in data
                           if ntpath.splitdrive(x["path"])[0]}
        drives = sorted(set(logical_drives()) | observed_drives)
        choices = ["所有磁盘"] + drives
        current = self.drive_filter.get()
        self.drive_box.configure(values=choices)
        if current not in choices:
            self.drive_filter.set("所有磁盘")
        self.refresh_btn.configure(state="normal")
        self.render()
        self._schedule_auto_refresh()

    def _process_selection_changed(self, _event=None):
        if self.tree.selection():
            if self.after_refresh:
                self.after_cancel(self.after_refresh)
                self.after_refresh = None
            # Do not let a scan already in flight rebuild the list mid-selection.
            if self._refresh_in_progress:
                self._refresh_generation += 1
                self._refresh_in_progress = False
                self.refresh_btn.configure(state="normal")
            self.scan_summary_var.set(
                "已选中 %d 个进程，自动刷新已暂停以保留多选；点‘刷新’可手动更新。" %
                len(self.tree.selection()))
        elif not self._refresh_in_progress and not self.after_refresh:
            self.after_refresh = self.after(1000, self.refresh)

    def _schedule_auto_refresh(self):
        if self.after_refresh:
            self.after_cancel(self.after_refresh)
            self.after_refresh = None
        if self.tree.selection():
            self.scan_summary_var.set(
                "已选中 %d 个进程，自动刷新已暂停以保留多选；点‘刷新’可手动更新。" %
                len(self.tree.selection()))
            return
        self.after_refresh = self.after(5000, self.refresh)

    def _build_monitor_page(self, parent):
        heading = tk.Frame(parent, bg="#f4f6f9")
        heading.pack(fill="x", pady=(0, 2))
        tk.Label(heading, text="自动卡顿与资源监测", bg="#f4f6f9", fg="#202938",
                 font=("Segoe UI", 18, "bold")).pack(side="left", anchor="w")
        self.monitor_status_var = tk.StringVar(value="正在启动自动监测…")
        self.monitor_status_label = tk.Label(heading, textvariable=self.monitor_status_var,
                 bg="#eaf2ff", fg="#426a9c", font=("Segoe UI", 8, "bold"),
                 padx=10, pady=5, anchor="e", justify="right", wraplength=420)
        self.monitor_status_label.pack(side="right", padx=(10, 0))
        tk.Label(parent, text="自动记录帧时间异常，并对照当时的内存变化。相关变化是线索，不代表已确认卡顿原因。",
                 bg="#f4f6f9", fg="#778393", font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 10))
        cards = tk.Frame(parent, bg="#f4f6f9")
        cards.pack(fill="x", pady=(0, 10))
        self.monitor_app_var = tk.StringVar(value="等待前台程序")
        self.monitor_window_detail_var = tk.StringVar(value="正在读取前台窗口信息…")
        self.monitor_ram_var = tk.StringVar(value="—")
        self.monitor_events_var = tk.StringVar(value="0")
        app_card = tk.Frame(cards, bg="white", highlightbackground="#dce6f3", highlightthickness=1,
                            padx=14, pady=10)
        app_card.grid(row=0, column=0, sticky="nsew")
        cards.grid_columnconfigure(0, weight=2, uniform="monitor_cards")
        cards.grid_columnconfigure(1, weight=1, uniform="monitor_cards")
        cards.grid_columnconfigure(2, weight=1, uniform="monitor_cards")
        tk.Label(app_card, text="当前前台所属程序", bg="white", fg="#778393",
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(app_card, textvariable=self.monitor_app_var, bg="white", fg="#24364b",
                 font=("Segoe UI", 15, "bold"), anchor="w", justify="left",
                 wraplength=440, height=2).pack(fill="x", anchor="w", pady=(4, 0))
        self._card(cards, "系统已用内存 / 总量", self.monitor_ram_var, 1)
        self._card(cards, "自动帧时间标记", self.monitor_events_var, 2)
        identity_panel = tk.Frame(parent, bg="white", highlightbackground="#e5e9ef", highlightthickness=1,
                                  padx=12, pady=8)
        identity_panel.pack(fill="x", pady=(0, 10))
        tk.Label(identity_panel, text="实际采样对象", bg="white", fg="#5578a2",
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.monitor_detail_label = tk.Label(identity_panel, textvariable=self.monitor_window_detail_var,
                 bg="white", fg="#536174", font=("Segoe UI", 9), anchor="w", justify="left", wraplength=1100)
        self.monitor_detail_label.pack(fill="x", anchor="w", pady=(3, 0))
        parent.bind("<Configure>", lambda event: self.monitor_detail_label.configure(
            wraplength=max(360, event.width - 80)))

        chart_section = tk.Frame(parent, bg="#f4f6f9")
        chart_section.pack(fill="both", expand=True, pady=(0, 9))
        tk.Label(chart_section, text="资源趋势", bg="#f4f6f9", fg="#344256",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        chart_frame = tk.Frame(chart_section, bg="white", highlightbackground="#e4e8ee", highlightthickness=1)
        chart_frame.pack(fill="both", expand=True)
        self.monitor_chart = tk.Canvas(chart_frame, height=170, bg="white", highlightthickness=0)
        self.monitor_chart.pack(fill="both", expand=True, padx=10, pady=8)
        self.monitor_chart.bind("<Configure>", lambda _event: self._draw_monitor_chart())

        event_section = tk.Frame(parent, bg="#f4f6f9")
        event_section.pack(fill="both", expand=True)
        event_heading = tk.Frame(event_section, bg="#f4f6f9")
        event_heading.pack(fill="x", pady=(0, 5))
        tk.Label(event_heading, text="自动标记事件", bg="#f4f6f9", fg="#344256",
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(event_heading, text="双击查看 PID、识别依据和内存变化", bg="#f4f6f9", fg="#8792a1",
                 font=("Segoe UI", 8)).pack(side="right")
        event_frame = tk.Frame(event_section, bg="white", highlightbackground="#e4e8ee", highlightthickness=1)
        event_frame.pack(fill="both", expand=True)
        columns = ("time", "app", "pid", "frame", "baseline", "memory")
        self.monitor_event_tree = ttk.Treeview(event_frame, columns=columns, show="headings", height=6,
                                               style="Monitor.Treeview")
        for col, title in [("time", "自动标记时间"), ("app", "所属程序 / 进程链"), ("pid", "实际采样 PID"),
                           ("frame", "帧间隔"), ("baseline", "近期基线"), ("memory", "同期内存增长较多的进程")]:
            self.monitor_event_tree.heading(col, text=title, anchor="w")
        self.monitor_event_tree.column("time", width=145, minwidth=130, stretch=False)
        self.monitor_event_tree.column("app", width=200, minwidth=145, stretch=False)
        self.monitor_event_tree.column("pid", width=80, minwidth=70, anchor="e", stretch=False)
        self.monitor_event_tree.column("frame", width=88, minwidth=75, anchor="e", stretch=False)
        self.monitor_event_tree.column("baseline", width=88, minwidth=75, anchor="e", stretch=False)
        self.monitor_event_tree.column("memory", width=330, minwidth=240, stretch=True)
        yscroll = ttk.Scrollbar(event_frame, orient="vertical", command=self.monitor_event_tree.yview)
        xscroll = ttk.Scrollbar(event_frame, orient="horizontal", command=self.monitor_event_tree.xview)
        self.monitor_event_tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        xscroll.pack(side="bottom", fill="x")
        self.monitor_event_tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        self.monitor_event_tree.bind("<Double-1>", self.show_monitor_event)
        tk.Label(parent, text="内存每秒采样一次，保留最近约 30 分钟；所属程序识别不足时会明确显示未确认。",
                 bg="#f4f6f9", fg="#8792a1", font=("Segoe UI", 8)).pack(anchor="w", pady=(7, 0))

    def _start_monitoring(self):
        self.monitor_status = "内存自动采样中；帧时间采集正在启动"
        pm_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "PresentMon-2.6.0-x64.exe")
        self.presentmon_path = pm_path
        if not os.path.isfile(pm_path):
            self.monitor_status = "内存采样中；未找到 PresentMon 帧时间组件"
        else:
            self._launch_presentmon()
        self.monitor_status_var.set(self.monitor_status)
        threading.Thread(target=self._memory_monitor_loop, daemon=True).start()

    def _launch_presentmon(self):
        """Start one uniquely named frame-capture session and its readers."""
        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            proc = subprocess.Popen(
                [self.presentmon_path, "--output_stdout", "--no_console_stats", "--date_time", "--v1_metrics",
                 "--stop_existing_session", "--session_name", "QingGuan_%s" % os.getpid()],
                cwd=os.path.dirname(self.presentmon_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                creationflags=creationflags)
            self.presentmon_process = proc
            threading.Thread(target=self._read_presentmon_csv, args=(proc,), daemon=True).start()
            self.presentmon_error_thread = threading.Thread(target=self._read_presentmon_errors, args=(proc,), daemon=True)
            self.presentmon_error_thread.start()
            return True
        except OSError as exc:
            self.monitor_status = "内存采样中；帧时间采集启动失败：%s" % exc
            return False

    def _read_presentmon_errors(self, proc):
        if not proc or not proc.stderr:
            return
        for line in proc.stderr:
            line = line.strip()
            if line:
                with self.monitor_lock:
                    self.presentmon_errors.append(line[:300])

    def _read_presentmon_csv(self, proc, output_path=None):
        if not proc:
            return
        headers = None

        def consume(values):
            nonlocal headers
            if not values:
                return
            if headers is None:
                normalized = [value.strip().lower() for value in values]
                if "processid" in normalized and any(name in normalized for name in ("msbetweenpresents", "msbetweendisplaychange", "frametime")):
                    headers = normalized
                    self.monitor_status = "内存与游戏帧时间自动监测中"
                    self.after(0, self._refresh_monitor_ui)
                return
            if len(values) != len(headers):
                return
            row = {headers[index]: value.strip() for index, value in enumerate(values)}
            try:
                pid = int(row.get("processid", "0"))
                if not pid or pid != foreground_process_id():
                    return
                frame_field = next((key for key in ("msbetweendisplaychange", "msbetweenpresents", "frametime")
                                    if key in row and row[key]), None)
                if not frame_field:
                    return
                frame_ms = float(row[frame_field])
                if not math.isfinite(frame_ms) or frame_ms <= 0 or frame_ms > 2000:
                    return
            except (ValueError, TypeError):
                return
            with self.monitor_lock:
                started_ticks = self.process_start_by_pid.get(pid)
            # PID alone is not stable: Windows may reuse it after a process exits.
            if started_ticks is not None:
                self._observe_frame_time(pid, started_ticks, row.get("application", "前台图形程序"), frame_ms)

        if output_path:
            offset, pending = 0, ""
            while not self.monitor_stop.is_set():
                try:
                    with open(output_path, "r", encoding="utf-8-sig", errors="replace", newline="") as stream:
                        stream.seek(offset)
                        chunk = stream.read()
                        offset = stream.tell()
                except (OSError, UnicodeError):
                    chunk = ""
                if chunk:
                    pending += chunk
                    complete = pending.splitlines(keepends=True)
                    pending = ""
                    for line in complete:
                        if line.endswith(("\n", "\r")):
                            try:
                                consume(next(csv.reader([line])))
                            except (csv.Error, StopIteration):
                                pass
                        else:
                            pending = line
                if proc.poll() is not None and not chunk:
                    break
                self.monitor_stop.wait(0.15)
        elif proc.stdout:
            for values in csv.reader(proc.stdout):
                if self.monitor_stop.is_set():
                    break
                consume(values)
        if not self.monitor_stop.is_set() and proc.poll() is not None and self.presentmon_process is proc:
            with self.monitor_lock:
                detail = self.presentmon_errors[-1] if self.presentmon_errors else "采集程序已退出"
            self.monitor_status = "内存采样中；帧时间采集不可用：%s" % detail
            self.after(0, self._refresh_monitor_ui)

    def _process_group_details(self, pid, fallback_name=""):
        """Identify a game conservatively and expose the evidence used."""
        with self.monitor_lock:
            metadata = dict(self.monitor_metadata)
        by_pid = {identity[0]: item for identity, item in metadata.items()}
        current = by_pid.get(int(pid))
        if not current:
            name = fallback_name or "前台图形程序"
            return "未确认：%s" % name, name, [name], "当前进程快照中没有该 PID，无法核对进程链"

        process_name = current.get("name") or fallback_name or "未知进程"
        chain = [process_name]
        seen = {int(pid)}
        parent_pid = current.get("parent_pid")
        system_boundaries = {"explorer.exe", "services.exe", "svchost.exe", "wininit.exe",
                             "winlogon.exe", "userinit.exe", "csrss.exe", "smss.exe",
                             "dwm.exe", "system"}
        while parent_pid and parent_pid not in seen and parent_pid in by_pid and len(chain) < 6:
            parent = by_pid[parent_pid]
            parent_name = parent.get("name") or ""
            if parent_name.casefold() in system_boundaries:
                break
            seen.add(parent_pid)
            chain.append(parent_name)
            parent_pid = parent.get("parent_pid")
        ordered = list(reversed(chain))
        by_name = {item.get("name", "").casefold(): item for item in chain}
        game_exe = by_name.get("league of legends.exe")
        launcher_exes = {"leagueclient.exe", "leagueclientux.exe", "leagueclientuxrender.exe"}
        launcher_match = next((by_name[name] for name in launcher_exes if name in by_name), None)
        group_label = "未确认：%s" % process_name
        basis = "进程名未匹配已知游戏；父进程链仅供参考"
        if game_exe:
            game_path = game_exe.get("path", "")
            signature = self.signature_cache.get(game_path.casefold(), ("Unknown", ""))
            signature_valid = signature[0] == "Valid" and "riot" in signature[1].casefold()
            path_matches = "league of legends" in game_path.casefold()
            if signature_valid and path_matches:
                group_label = "英雄联盟"
                basis = "游戏进程名、安装路径及 Riot 有效签名匹配"
            else:
                group_label = "疑似英雄联盟"
                missing = []
                if not path_matches:
                    missing.append("路径未匹配")
                if not signature_valid:
                    missing.append("Riot 数字签名未验证")
                basis = "游戏进程名匹配；" + "、".join(missing)
        elif launcher_match:
            group_label = "疑似英雄联盟客户端"
            basis = "父进程链包含 %s；未确认游戏进程" % launcher_match.get("name")
        return group_label, process_name, ordered, basis

    def _observe_frame_time(self, pid, started_ticks, app_name, frame_ms):
        now = time.time()
        identity = (int(pid), int(started_ticks))
        group_label, process_name, process_chain, recognition_basis = self._process_group_details(pid, app_name)
        with self.monitor_lock:
            samples = self.frame_baselines.setdefault(identity, deque(maxlen=120))
            baseline = statistics.median(samples) if len(samples) >= 30 else None
            samples.append(frame_ms)
            if baseline is None or frame_ms < max(baseline * 2.2, baseline + 12.0):
                return
            event = next((item for item in reversed(self.monitor_events)
                          if (item["pid"], item.get("creation_time_ticks")) == identity
                          and now - item["timestamp"] <= 3.0), None)
            if event:
                event["spike_count"] += 1
                event["peak_frame_ms"] = max(event["peak_frame_ms"], frame_ms)
            else:
                event = {"event_id": str(uuid.uuid4()), "timestamp": now, "time_text": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                         "app": group_label, "process_name": process_name, "process_chain": process_chain,
                         "recognition_basis": recognition_basis,
                         "pid": pid, "creation_time_ticks": started_ticks,
                         "frame_ms": frame_ms,
                         "peak_frame_ms": frame_ms, "baseline_ms": baseline, "spike_count": 1,
                         "memory_changes": [], "correlation_ready": False}
                self.monitor_events.append(event)
                self.after(11000, lambda event_id=event["event_id"]: self._complete_event_correlation(event_id))
            self.last_frame_event[identity] = now
        self.after(0, self._refresh_monitor_ui)

    def _memory_monitor_loop(self):
        next_sample = time.monotonic()
        while not self.monitor_stop.is_set():
            try:
                processes = snapshot_processes()
                total, available = system_memory_status()
                timestamp = time.time()
                records = []
                metadata = {}
                for proc in processes:
                    ticks = proc.get("creation_time_ticks") or 0
                    if not proc.get("pid") or not ticks or proc.get("memory", 0) <= 0:
                        continue
                    key = (int(proc["pid"]), int(ticks))
                    records.append(struct.pack("<IQQ", key[0], key[1], int(proc["memory"])))
                    metadata[key] = {"name": proc["name"], "path": proc["path"],
                                     "parent_pid": proc.get("parent_pid", 0),
                                     "parent_name": proc.get("parent_name", ""),
                                     "window_state": proc.get("window_state", "未知")}
                packed = b"".join(records)
                with self.monitor_lock:
                    self.monitor_metadata.update(metadata)
                    self.process_start_by_pid = {pid: ticks for pid, ticks in metadata}
                    active_identities = set(metadata)
                    self.frame_baselines = {identity: samples for identity, samples in self.frame_baselines.items()
                                            if identity in active_identities}
                    self.monitor_history.append((timestamp, total, available, packed))
                    self._monitor_last_snapshot = {"timestamp": timestamp, "total": total, "available": available}
                self.after(0, self._refresh_monitor_ui)
            except Exception as exc:
                self.monitor_status = "内存自动采样异常：%s" % exc
                self.after(0, self._refresh_monitor_ui)
            proc = self.presentmon_process
            if proc and proc.poll() is not None:
                error_reader = getattr(self, "presentmon_error_thread", None)
                if error_reader and error_reader.is_alive():
                    error_reader.join(timeout=0.25)
                    if error_reader.is_alive():
                        self.monitor_stop.wait(0.05)
                        continue
                errors = "\n".join(self.presentmon_errors).casefold()
                needs_etw_access = "access denied" in errors or "performance log users" in errors
                if needs_etw_access:
                    if not self.presentmon_elevation_attempted and not self.presentmon_elevation_in_progress:
                        self.presentmon_elevation_attempted = True
                        self.presentmon_elevation_in_progress = True
                        with self.monitor_lock:
                            self.presentmon_errors.clear()
                        self.presentmon_process = None
                        self.monitor_status = "帧时间采集需要系统确认，正在请求一次权限；内存监测继续运行"
                        self.after(0, self._refresh_monitor_ui)
                        threading.Thread(target=self._start_presentmon_elevated, daemon=True).start()
                        next_sample += 1.0
                        self.monitor_stop.wait(max(0.05, next_sample - time.monotonic()))
                        continue
                    detail = "系统未授予帧时间采集权限"
                elif self.presentmon_errors:
                    detail = self.presentmon_errors[-1]
                else:
                    detail = "采集程序退出码 %s" % proc.returncode
                can_retry = (not needs_etw_access and not self.presentmon_elevated_active
                             and self.presentmon_restart_count < 1
                             and not self.presentmon_retrying and os.path.isfile(self.presentmon_path))
                if can_retry:
                    self.presentmon_retrying = True
                    self.presentmon_restart_count += 1
                    self.monitor_status = "内存采样中；帧时间采集意外中断，正在自动恢复（仅重试一次）"
                    self.after(0, self._refresh_monitor_ui)
                    threading.Thread(target=self._retry_presentmon_once, daemon=True).start()
                else:
                    self.monitor_status = "内存采样中；帧时间采集不可用：%s" % detail
                    self.after(0, self._refresh_monitor_ui)
            next_sample += 1.0
            self.monitor_stop.wait(max(0.05, next_sample - time.monotonic()))

    def _retry_presentmon_once(self):
        """Retry a crashed sampler once; permission errors are never retried or elevated silently."""
        try:
            if self.monitor_stop.wait(1.0):
                return
            with self.monitor_lock:
                self.presentmon_errors.clear()
            if self._launch_presentmon():
                self.monitor_status = "内存采样中；帧时间采集已自动重启，正在确认数据"
            else:
                self.monitor_status = "内存采样中；帧时间采集自动恢复失败"
            self.after(0, self._refresh_monitor_ui)
        finally:
            self.presentmon_retrying = False

    def _start_presentmon_elevated(self):
        """Request UAC for the sampler only; the manager stays unelevated."""
        state_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "QingGuan", "monitor")
        output_path = os.path.join(state_dir, "frames-%s-%s.csv" % (os.getpid(), uuid.uuid4().hex))
        try:
            os.makedirs(state_dir, exist_ok=True)
            args = ["--output_file", output_path, "--no_console_stats", "--date_time", "--v1_metrics",
                    "--stop_existing_session", "--session_name", "QingGuan_%s" % os.getpid()]
            info = SHELLEXECUTEINFOW()
            info.cbSize = ctypes.sizeof(info)
            info.fMask = SEE_MASK_NOCLOSEPROCESS
            info.lpVerb = "runas"
            info.lpFile = self.presentmon_path
            info.lpParameters = subprocess.list2cmdline(args)
            info.lpDirectory = os.path.dirname(self.presentmon_path)
            info.nShow = 0
            ctypes.set_last_error(0)
            if not shell32.ShellExecuteExW(ctypes.byref(info)):
                error = ctypes.get_last_error()
                if os.path.exists(output_path):
                    os.remove(output_path)
                if error == 1223:
                    self.monitor_status = "帧时间未启用；内存监测继续运行。重新打开轻管后可再次请求权限。"
                else:
                    self.monitor_status = "帧时间采集未能启动；内存监测继续运行。"
                self._schedule_monitor_ui_refresh()
                return
            if not info.hProcess:
                self.monitor_status = "帧时间采集没有取得可管理的进程句柄；内存监测继续运行。"
                try:
                    if os.path.exists(output_path):
                        os.remove(output_path)
                except OSError:
                    pass
                self._schedule_monitor_ui_refresh()
                return
            proc = ElevatedProcess(info.hProcess)
            if self.monitor_stop.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except Exception:
                    pass
                try:
                    if os.path.exists(output_path):
                        os.remove(output_path)
                except OSError:
                    pass
                return
            self.presentmon_csv_path = output_path
            self.presentmon_process = proc
            self.presentmon_elevated_active = True
            if self.monitor_stop.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except Exception:
                    pass
                try:
                    if os.path.exists(output_path):
                        os.remove(output_path)
                except OSError:
                    pass
                return
            threading.Thread(target=self._read_presentmon_csv, args=(proc, output_path), daemon=True).start()
            self.monitor_status = "内存监测继续运行；帧时间采集器正在准备。"
            self._schedule_monitor_ui_refresh()
        except Exception as exc:
            self.monitor_status = "帧时间采集未能启动；内存监测继续运行（%s）" % str(exc)[:160]
            self._schedule_monitor_ui_refresh()
            try:
                if os.path.exists(output_path):
                    os.remove(output_path)
            except OSError:
                pass
        finally:
            self.presentmon_elevation_in_progress = False

    def _schedule_monitor_ui_refresh(self):
        if self.monitor_stop.is_set():
            return
        try:
            self.after(0, self._refresh_monitor_ui)
        except tk.TclError:
            pass

    def _save_monitor_state_for_restart(self):
        """Save a bounded JSON checkpoint so an explicit elevated relaunch keeps this session's data."""
        with self.monitor_lock:
            payload = {
                "version": 1,
                "saved_at": time.time(),
                "history": [[ts, total, available, base64.b64encode(packed).decode("ascii")]
                            for ts, total, available, packed in self.monitor_history],
                "events": list(self.monitor_events),
                "metadata": [[pid, ticks, item.get("name", ""), item.get("path", "")]
                             for (pid, ticks), item in self.monitor_metadata.items()],
                "baselines": [[pid, ticks, list(samples)]
                              for (pid, ticks), samples in self.frame_baselines.items()],
            }
        local_app_data = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        state_dir = os.path.join(local_app_data, "QingGuan")
        os.makedirs(state_dir, exist_ok=True)
        # Remove abandoned checkpoints left by a canceled or failed elevated relaunch.
        for filename in os.listdir(state_dir):
            if not (filename.startswith("monitor-session-") and filename.endswith(".json")):
                continue
            stale_path = os.path.join(state_dir, filename)
            try:
                if time.time() - os.path.getmtime(stale_path) > 600:
                    os.remove(stale_path)
            except OSError:
                pass
        fd, path = tempfile.mkstemp(prefix="monitor-session-", suffix=".json", dir=state_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, ensure_ascii=False, separators=(",", ":"))
            return path
        except Exception:
            try:
                os.remove(path)
            except OSError:
                pass
            raise

    def _restore_monitor_state_from_environment(self):
        state_path = os.environ.pop("QINGGUAN_MONITOR_STATE", "")
        if not state_path:
            return
        try:
            if os.path.getsize(state_path) > 32 * 1024 * 1024:
                return
            with open(state_path, "r", encoding="utf-8") as stream:
                payload = json.load(stream)
            if payload.get("version") != 1 or time.time() - float(payload.get("saved_at", 0)) > 600:
                return
            self.monitor_history.extend((float(ts), int(total), int(available), base64.b64decode(packed))
                                        for ts, total, available, packed in payload.get("history", []))
            self.monitor_events.extend(payload.get("events", []))
            self.monitor_metadata.update({(int(pid), int(ticks)): {"name": name, "path": path}
                                          for pid, ticks, name, path in payload.get("metadata", [])})
            self.frame_baselines.update({(int(pid), int(ticks)): deque(samples, maxlen=120)
                                         for pid, ticks, samples in payload.get("baselines", [])})
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            self.monitor_status = "监测记录恢复失败；已重新开始采集"
        finally:
            try:
                os.remove(state_path)
            except OSError:
                pass

    def _complete_event_correlation(self, event_id):
        with self.monitor_lock:
            event = next((item for item in self.monitor_events if item["event_id"] == event_id), None)
            history = list(self.monitor_history)
        if not event or not history:
            return
        target_before = event["timestamp"] - 10.0
        target_after = event["timestamp"] + 10.0
        before = min(history, key=lambda item: abs(item[0] - target_before))
        after = min(history, key=lambda item: abs(item[0] - target_after))
        if after[0] < target_after - 1.5:
            self.after(2000, lambda: self._complete_event_correlation(event_id))
            return

        def decode(snapshot):
            packed = snapshot[3]
            values = {}
            size = struct.calcsize("<IQQ")
            for offset in range(0, len(packed) - size + 1, size):
                pid, ticks, memory = struct.unpack_from("<IQQ", packed, offset)
                values[(pid, ticks)] = memory
            return values

        start_values, end_values = decode(before), decode(after)
        changes = []
        for key, end_memory in end_values.items():
            start_memory = start_values.get(key)
            if start_memory is None:
                continue
            delta = end_memory - start_memory
            if delta > 0:
                metadata = self.monitor_metadata.get(key, {})
                changes.append({"pid": key[0], "name": metadata.get("name", "未知进程"),
                                "path": metadata.get("path", ""), "delta_bytes": delta,
                                "memory_bytes": end_memory})
        changes.sort(key=lambda item: item["delta_bytes"], reverse=True)
        with self.monitor_lock:
            event = next((item for item in self.monitor_events if item["event_id"] == event_id), None)
            if event:
                event["memory_changes"] = changes[:10]
                event["correlation_ready"] = True
        self.after(0, self._refresh_monitor_ui)

    def _refresh_monitor_ui(self):
        if not hasattr(self, "monitor_status_var"):
            return
        player_status = self._player_monitor_status(self.monitor_status)
        self.monitor_status_var.set(player_status)
        if any(word in player_status for word in ("不可用", "失败", "问题")):
            self.monitor_status_label.configure(bg="#fff0ed", fg="#a24f42")
        else:
            self.monitor_status_label.configure(bg="#eaf2ff", fg="#426a9c")
        self._update_foreground_display()
        with self.monitor_lock:
            history = list(self.monitor_history)
            events = list(self.monitor_events)
        if history:
            _stamp, total, available, _packed = history[-1]
            self.monitor_ram_var.set("%s / %s" % (fmt_bytes(total - available), fmt_bytes(total)))
        self.monitor_events_var.set(str(len(events)))
        for item in self.monitor_event_tree.get_children(""):
            self.monitor_event_tree.delete(item)
        for event in reversed(events):
            suspects = event.get("memory_changes", [])
            summary = "; ".join("%s +%s" % (row["name"], fmt_bytes(row["delta_bytes"])) for row in suspects[:3])
            if not event.get("correlation_ready"):
                summary = "分析卡顿前后内存变化中…"
            self.monitor_event_tree.insert("", "end", iid=event["event_id"],
                values=(event["time_text"], event["app"], event["pid"], "%.1f ms" % event["peak_frame_ms"],
                        "%.1f ms" % event["baseline_ms"], summary))
        self._draw_monitor_chart(history, events)

    def _update_foreground_display(self):
        if not hasattr(self, "monitor_app_var"):
            return
        foreground_info = foreground_window_info()
        foreground = foreground_info["pid"]
        if foreground == os.getpid():
            foreground_label = "轻管（当前正在查看监测页）"
        elif foreground and foreground_info["path"]:
            actual_name = os.path.basename(foreground_info["path"])
            foreground_label, _process_name, _chain, _basis = self._process_group_details(foreground, actual_name)
        elif foreground:
            foreground_label = "PID %s · 进程名/路径读取受限" % foreground
        else:
            foreground_label = "暂时没有可读取的前台窗口"
        self.monitor_app_var.set(foreground_label)
        if foreground_info["hwnd"]:
            title = foreground_info["title"] or "（无窗口标题）"
            class_name = foreground_info["class_name"] or "（未知窗口类）"
            if foreground and foreground_info["path"]:
                actual_name = os.path.basename(foreground_info["path"])
                _group, _name, chain, basis = self._process_group_details(foreground, actual_name)
                relationship = "识别依据：%s\n父进程链：%s" % (basis, " → ".join(chain))
                self.monitor_window_detail_var.set(
                    "实际窗口进程：%s · PID %s\n%s\n窗口：%s" %
                    (actual_name, foreground, relationship, title))
            else:
                self.monitor_window_detail_var.set(
                    "窗口标题：%s    窗口类：%s    HWND：0x%X" %
                    (title, class_name, foreground_info["hwnd"]))
        else:
            self.monitor_window_detail_var.set("Windows 当前未返回前台窗口句柄。")

    def _foreground_ui_tick(self):
        if self.monitor_stop.is_set():
            return
        self._update_foreground_display()
        self.foreground_refresh_after = self.after(500, self._foreground_ui_tick)

    @staticmethod
    def _player_monitor_status(status):
        """Translate collector diagnostics into short player-facing status text."""
        lowered = status.casefold()
        if "access denied" in lowered or "performance log users" in lowered or "权限不足" in status:
            return "帧时间暂不可用；内存监测仍在运行。"
        if "正在请求一次权限" in status:
            return "Windows 正在请求一次确认；内存监测继续运行。"
        if "帧时间未启用" in status:
            return "帧时间未启用；内存监测继续运行。重新打开轻管后可再次尝试。"
        if "自动重启" in status or "正在自动恢复" in status:
            return "帧时间采集短暂中断，轻管正在自动恢复；内存监测仍在运行。"
        if "自动恢复失败" in status or "帧时间采集不可用" in status:
            return "内存监测正常；帧时间暂不可用。你仍可查看进程和内存变化。"
        if "未找到 presentmon" in lowered:
            return "内存监测正常；帧时间组件缺失，需修复安装后才能采集。"
        if "帧时间采集启动失败" in status:
            return "内存监测正常；帧时间采集没有启动，请查看修复提示。"
        if status == "内存与游戏帧时间自动监测中":
            return "监测正常：内存与当前前台程序帧时间正在采集。"
        if "正在启动" in status or "正在确认数据" in status:
            return "正在准备监测；内存采集已启动，帧时间采集确认中。"
        if "帧时间采集器正在准备" in status:
            return status
        if "内存自动采样异常" in status:
            return "内存监测遇到问题；帧时间采集状态可能受影响。"
        return status

    def _draw_monitor_chart(self, history=None, events=None):
        if not hasattr(self, "monitor_chart"):
            return
        if history is None:
            with self.monitor_lock:
                history = list(self.monitor_history)
                events = list(self.monitor_events)
        canvas = self.monitor_chart
        canvas.delete("all")
        width, height = max(canvas.winfo_width(), 300), max(canvas.winfo_height(), 150)
        left, right, top, bottom = 52, width - 18, 18, height - 28
        if len(history) < 2:
            canvas.create_text(width / 2, height / 2, text="正在收集内存曲线…", fill="#8792a1", font=("Segoe UI", 10))
            return
        history = history[-1800:]
        start, end = history[0][0], history[-1][0]
        total = max((item[1] for item in history), default=0)
        used_values = [max(0, item[1] - item[2]) for item in history]
        ceiling = max(total, max(used_values), 1)
        for fraction in (0, .25, .5, .75, 1):
            y = bottom - (bottom - top) * fraction
            canvas.create_line(left, y, right, y, fill="#edf0f4")
            canvas.create_text(left - 8, y, text="%d%%" % int(fraction * 100), anchor="e", fill="#8792a1", font=("Segoe UI", 8))
        points = []
        span = max(end - start, 1.0)
        for item, used in zip(history, used_values):
            x = left + (right - left) * (item[0] - start) / span
            y = bottom - (bottom - top) * min(1.0, used / ceiling)
            points.extend((x, y))
        if len(points) >= 4:
            canvas.create_line(*points, fill="#5b84bf", width=2, smooth=False)
        for event in events or []:
            if start <= event["timestamp"] <= end:
                x = left + (right - left) * (event["timestamp"] - start) / span
                canvas.create_line(x, top, x, bottom, fill="#c97676", dash=(3, 3))
        canvas.create_text(left, height - 9, text=time.strftime("%H:%M:%S", time.localtime(start)), anchor="w", fill="#8792a1", font=("Segoe UI", 8))
        canvas.create_text(right, height - 9, text=time.strftime("%H:%M:%S", time.localtime(end)), anchor="e", fill="#8792a1", font=("Segoe UI", 8))
        canvas.create_line(width - 165, 10, width - 147, 10, fill="#5b84bf", width=2)
        canvas.create_text(width - 142, 10, text="系统已用内存", anchor="w", fill="#687587", font=("Segoe UI", 8))
        canvas.create_line(width - 55, 10, width - 40, 10, fill="#c97676", dash=(3, 3))
        canvas.create_text(width - 35, 10, text="帧时间标记", anchor="w", fill="#687587", font=("Segoe UI", 8))

    def show_monitor_event(self, _event=None):
        selection = self.monitor_event_tree.selection()
        if not selection:
            return
        with self.monitor_lock:
            item = next((row.copy() for row in self.monitor_events if row["event_id"] == selection[0]), None)
        if not item:
            return
        changes = item.get("memory_changes", [])
        detail = ["自动标记：%s" % item["time_text"],
                  "所属程序 / 进程链：%s" % item.get("app", "未知"),
                  "识别依据：%s" % item.get("recognition_basis", "旧记录无识别依据字段"),
                  "父进程链：%s" % " → ".join(item.get("process_chain", [])),
                  "实际帧时间采样进程：%s（PID %s）" % (item.get("process_name", item.get("app", "未知")), item["pid"]),
                  "峰值帧间隔：%.2f ms；近期基线：%.2f ms；连续尖峰数：%s" % (item["peak_frame_ms"], item["baseline_ms"], item["spike_count"]),
                  "", "卡顿点前后约 20 秒内内存增长较多的进程："]
        detail.extend("• %s（PID %s）：增加 %s，当前 %s\n  %s" % (row["name"], row["pid"], fmt_bytes(row["delta_bytes"]), fmt_bytes(row["memory_bytes"]), row["path"]) for row in changes)
        if not changes:
            detail.append("暂未发现明显的正向工作集增长，或前后样本不完整。")
        detail.extend(["", "时间相关不等于因果。工作集包含可能共享的页面；帧时间采集还会受游戏图形 API、系统权限和硬件影响。"])
        messagebox.showinfo("自动卡顿事件", "\n".join(detail))

    def _icon(self, path):
        if path in self.icon_cache:
            return self.icon_cache[path]
        try:
            from PIL import Image, ImageTk
            class SHFILEINFO(ctypes.Structure):
                _fields_ = [("hIcon", wintypes.HANDLE), ("iIcon", ctypes.c_int), ("dwAttributes", wintypes.DWORD), ("szDisplayName", wintypes.WCHAR * 260), ("szTypeName", wintypes.WCHAR * 80)]
            shell32.SHGetFileInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(SHFILEINFO), wintypes.UINT, wintypes.UINT]
            shell32.SHGetFileInfoW.restype = ctypes.c_void_p
            info = SHFILEINFO()
            if not shell32.SHGetFileInfoW(path, 0, ctypes.byref(info), ctypes.sizeof(info), 0x100 | 0x4) or not info.hIcon:
                return ""
            gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
            gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]; gdi32.CreateCompatibleDC.restype = wintypes.HDC
            gdi32.CreateDIBSection.argtypes = [wintypes.HDC, ctypes.c_void_p, wintypes.UINT, ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.DWORD]
            gdi32.CreateDIBSection.restype = wintypes.HBITMAP
            gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]; gdi32.SelectObject.restype = wintypes.HGDIOBJ
            gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]; gdi32.DeleteDC.argtypes = [wintypes.HDC]
            user32.GetDC.argtypes = [wintypes.HWND]; user32.GetDC.restype = wintypes.HDC
            user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
            user32.DrawIconEx.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.HANDLE, ctypes.c_int, ctypes.c_int, wintypes.UINT, wintypes.HBRUSH, wintypes.UINT]
            class Header(ctypes.Structure):
                _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD), ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG), ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]
            class Info(ctypes.Structure):
                _fields_ = [("header", Header), ("colors", wintypes.DWORD * 3)]
            bmi = Info(); bmi.header.biSize = ctypes.sizeof(Header); bmi.header.biWidth = 32; bmi.header.biHeight = -32; bmi.header.biPlanes = 1; bmi.header.biBitCount = 32
            screen = user32.GetDC(None); dc = gdi32.CreateCompatibleDC(screen); bits = ctypes.c_void_p()
            bitmap = gdi32.CreateDIBSection(dc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0); old = gdi32.SelectObject(dc, bitmap)
            user32.DrawIconEx(dc, 0, 0, info.hIcon, 32, 32, 0, None, 3)
            photo = ImageTk.PhotoImage(Image.frombytes("RGBA", (32, 32), ctypes.string_at(bits, 4096), "raw", "BGRA").resize((24, 24)))
            gdi32.SelectObject(dc, old); gdi32.DeleteObject(bitmap); gdi32.DeleteDC(dc); user32.ReleaseDC(None, screen); user32.DestroyIcon(info.hIcon)
            self.icon_cache[path] = photo
            return photo
        except Exception:
            return ""

    def _enrich_publishers(self, data):
        paths = list(dict.fromkeys(p["path"] for p in data if p["path"].lower() not in self.signature_cache and not p["path"].startswith("不可读取")))[:80]
        if paths:
            encoded = base64.b64encode(json.dumps(paths).encode("utf-8")).decode("ascii")
            script = "$paths=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))|ConvertFrom-Json;foreach($p in $paths){try{$s=Get-AuthenticodeSignature -LiteralPath $p;$n=$s.SignerCertificate.Subject;if(!$n){$n=if($s.Status -eq 'Valid'){'签名有效'}else{'未签名/无效签名'}};[pscustomobject]@{Path=$p;Status=[string]$s.Status;Publisher=$n}}catch{[pscustomobject]@{Path=$p;Status='Unknown';Publisher='无法验证'}}}" % encoded
            try:
                raw = subprocess.check_output(["powershell.exe", "-NoProfile", "-Command", script], stderr=subprocess.DEVNULL, timeout=20)
                result = json.loads(raw.decode("utf-8-sig"))
                if isinstance(result, dict): result = [result]
                for item in result:
                    if isinstance(item, dict): self.signature_cache[item.get("Path", "").lower()] = (item.get("Status", "Unknown"), item.get("Publisher", "无法验证"))
            except Exception:
                for path in paths: self.signature_cache[path.lower()] = ("Unknown", "无法验证签名")
        for p in data:
            signature = self.signature_cache.get(p["path"].lower())
            if signature:
                state, publisher = signature
                p["publisher"] = ("已验证 · " if state == "Valid" else "未验证 · ") + publisher

    def _load_rules(self):
        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                value = json.load(f)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_rules(self):
        temp = self.rules_path + ".tmp"
        with open(temp, "w", encoding="utf-8") as f: json.dump(self.rules, f, ensure_ascii=False, indent=2)
        os.replace(temp, self.rules_path)

    def set_rule(self, state):
        p = self.selected()
        if not p: return
        key = p["path"].lower()
        if state is None:
            record = self.rules.get(key, {})
            record.pop("state", None)
            if record.get("color") is None:
                self.rules.pop(key, None)
        else:
            record = self.rules.setdefault(key, {"name": p["name"], "path": p["path"]})
            record.update({"state": state, "name": p["name"], "path": p["path"]})
        self._save_rules(); self.render()

    def set_program_color(self, color_name):
        p = self.selected()
        if not p:
            return
        key = p["path"].lower()
        if not key or key.startswith("不可读取"):
            messagebox.showinfo("无法设置颜色", "这个进程的文件路径不可读，暂时无法把颜色稳定关联到程序。")
            return
        rule = self.rules.setdefault(key, {"name": p["name"], "path": p["path"]})
        if color_name is None:
            rule.pop("color", None)
            if "state" not in rule:
                self.rules.pop(key, None)
        else:
            rule["color"] = color_name
        self._save_rules()
        self.render()

    def choose_program_color(self):
        p = self.selected()
        if not p:
            return
        key = p["path"].lower()
        current = self.rules.get(key, {}).get("color", "自动分配")
        win = tk.Toplevel(self)
        win.title("程序标识颜色")
        win.transient(self)
        win.grab_set()
        win.configure(bg="white", padx=18, pady=16)
        tk.Label(win, text=p["name"] + " 的运行实例会使用同一种颜色", bg="white", fg="#202938",
                 font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(win, text="选择柔和色调；其他同路径进程会同步使用。", bg="white", fg="#778393",
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(5, 12))
        choice = tk.StringVar(value=current)
        names = ["自动分配"] + list(PROGRAM_COLORS.keys())
        for name in names:
            line = tk.Frame(win, bg="white")
            line.pack(fill="x", pady=2)
            if name == "自动分配":
                swatch, accent = ("#F0F2F5", "#697586")
            else:
                swatch, accent = PROGRAM_COLORS[name]
            tk.Label(line, text="●", bg=swatch, fg=accent, width=4, font=("Segoe UI", 13)).pack(side="left", padx=(0, 8))
            ttk.Radiobutton(line, text=name, value=name, variable=choice).pack(side="left")
        buttons = tk.Frame(win, bg="white")
        buttons.pack(fill="x", pady=(14, 0))
        def save_color():
            if choice.get() == "自动分配":
                self.set_program_color(None)
            else:
                self.set_program_color(choice.get())
            win.destroy()
        ttk.Button(buttons, text="保存颜色", command=save_color).pack(side="right")
        ttk.Button(buttons, text="取消", command=win.destroy).pack(side="right", padx=8)

    def automatic_color(self, path):
        digest = hashlib.sha256(path.lower().encode("utf-8", "replace")).digest()
        return list(PROGRAM_COLORS.keys())[digest[0] % len(PROGRAM_COLORS)]

    def render(self):
        # Rebuilding rows on the five-second live refresh must not discard the
        # user's multi-selection or jump the list back to the top.
        selected = set(self.tree.selection())
        restore_identities = self._selection_restore_identities
        self._selection_restore_identities = None
        if restore_identities is not None:
            selected = {str(pid) for pid in restore_identities}
        focused = self.tree.focus()
        try:
            scroll_position = self.tree.yview()[0]
        except (tk.TclError, IndexError):
            scroll_position = 0.0
        children = self.tree.get_children("")
        if children:
            self.tree.delete(*children)
        query = self.search.get().strip().lower()
        import ntpath
        drive = self.drive_filter.get()
        status_filter = self.status_filter.get()
        descending = self.memory_sort.get() != "内存：从低到高"
        for p in sorted(self.rows.values(), key=lambda x: x["memory"], reverse=descending):
            if query and query not in (p["name"] + " " + p["path"] + " " + p["publisher"]).lower(): continue
            process_drive = ntpath.splitdrive(p["path"])[0].upper()
            if drive != "所有磁盘" and process_drive != drive: continue
            rule = self.rules.get(p["path"].lower(), {}).get("state", "")
            path_readable = p.get("path_readable", not p["path"].startswith("不可读取"))
            memory_readable = p.get("memory_readable", p["memory"] > 0)
            access_limited = not path_readable or not memory_readable
            if rule == "whitelist":
                status = "白名单 · 读取受限" if access_limited else "白名单 · 运行中"
            elif rule == "blacklist":
                status = "黑名单标记 · 读取受限" if access_limited else "黑名单标记 · 运行中"
            else:
                status = "权限受限/未知" if access_limited else "运行中"
            if status_filter in ("有可见窗口", "无可见窗口") and p.get("window_state") != status_filter: continue
            if status_filter == "白名单" and rule != "whitelist": continue
            if status_filter == "黑名单标记" and rule != "blacklist": continue
            if status_filter == "读取受限" and not access_limited: continue
            path = p["path"]
            shown_path = path if len(path) < 83 else path[:39] + "…" + path[-40:]
            rule_data = self.rules.get(path.lower(), {})
            color_name = rule_data.get("color") or self.automatic_color(path)
            row_tag = "program_color_" + color_name if color_name in PROGRAM_COLORS else ""
            self.tree.insert("", "end", iid=str(p["pid"]), text=p["name"] + "\n" + shown_path,
                             image=self._icon(path) if not path.startswith("不可读取") else "",
                             values=("%s (%s)" % (p["parent_name"], p["parent_pid"]), p.get("window_state", "未知"), p["instance_count"], p["publisher"], status,
                                     fmt_bytes(p["memory"]), p["pid"], p["started_at"]),
                             tags=(row_tag,) if row_tag else ())
        visible_items = set(self.tree.get_children(""))
        if restore_identities is not None:
            selected = {iid for iid in selected if iid.isdigit() and
                        int(iid) in restore_identities and int(iid) in self.rows and
                        self.rows[int(iid)].get("creation_time_ticks") == restore_identities[int(iid)]}
        keep_selected = selected & visible_items
        if keep_selected:
            self.tree.selection_set(tuple(keep_selected))
        if focused in visible_items:
            self.tree.focus(focused)
        self.tree.yview_moveto(scroll_position)

    def selected(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("选择程序", "请先选择一个进程。"); return None
        return self.rows.get(int(selection[0]))

    def selected_processes(self):
        """Return the currently selected process rows in the visible list."""
        return [self.rows[int(iid)] for iid in self.tree.selection()
                if iid.isdigit() and int(iid) in self.rows]

    def restart_as_admin(self, preserve_monitor_state=True):
        """Relaunch this manager elevated so Windows allows access to more processes."""
        if self.is_admin:
            return
        executable = sys.executable
        arguments = list(sys.argv[1:])
        if not getattr(sys, "frozen", False):
            arguments.insert(0, os.path.abspath(__file__))
        state_path = ""
        if preserve_monitor_state:
            try:
                state_path = self._save_monitor_state_for_restart()
                os.environ["QINGGUAN_MONITOR_STATE"] = state_path
            except Exception as exc:
                messagebox.showerror("无法保留监测记录", "监测记录保存失败，未重新启动管理器。\n\n%s" % exc)
                return
        result = shell32.ShellExecuteW(None, "runas", executable,
                                       subprocess.list2cmdline(arguments),
                                       os.path.dirname(os.path.abspath(__file__)), 1)
        if result and result > 32:
            self.on_close()
        else:
            if state_path:
                os.environ.pop("QINGGUAN_MONITOR_STATE", None)
                try:
                    os.remove(state_path)
                except OSError:
                    pass
            messagebox.showinfo("需要管理员权限", "未获得管理员权限。普通用户仍可管理自己有权限操作的进程；受保护进程可能无法读取或结束。")

    def show_details(self):
        p = self.selected()
        if p: messagebox.showinfo(p["name"], "进程名称：%s\nPID：%s\n父进程：%s（PID %s）\n窗口：%s\n启动时间：%s\n同路径进程数：%s\n工作集内存：%s\n文件路径：%s\n发布者/签名：%s\n\n进程列表包含无窗口的后台组件。多个 PID 仅表示同路径程序有多个进程实例，不等于多开故障；无可见窗口也不能证明它未在工作或可以关闭。" % (p["name"], p["pid"], p["parent_name"], p["parent_pid"], p.get("window_state", "未知"), p["started_at"], p["instance_count"], fmt_bytes(p["memory"]), p["path"], p["publisher"]))

    def _duplicate_analysis(self):
        """Return same-path groups with heuristic process-tree relationships."""
        grouped = {}
        for proc in self.rows.values():
            path = proc["path"]
            identity = path.lower() if not path.startswith("不可读取") else "name:" + proc["name"].lower()
            grouped.setdefault(identity, []).append(proc)
        result = []
        for identity, procs in grouped.items():
            if len(procs) < 2:
                continue
            pids = {proc["pid"] for proc in procs}
            root_for_pid = {}
            for proc in procs:
                root = proc
                visited = {proc["pid"]}
                parent = self.rows.get(proc["parent_pid"])
                while parent and parent["pid"] in pids and parent["pid"] not in visited:
                    if (parent.get("creation_time_ticks") is not None and proc.get("creation_time_ticks") is not None
                            and parent["creation_time_ticks"] > proc["creation_time_ticks"]):
                        break
                    root = parent
                    visited.add(parent["pid"])
                    parent = self.rows.get(parent["parent_pid"])
                root_for_pid[proc["pid"]] = root["pid"]
            root_count = len(set(root_for_pid.values()))
            instances = []
            for proc in sorted(procs, key=lambda p: (root_for_pid[p["pid"]], p["started_at"], p["pid"])):
                instance = dict(proc)
                instance["same_path_root_pid"] = root_for_pid[proc["pid"]]
                instance["same_path_relation"] = ("子进程（根 PID %s）" % root_for_pid[proc["pid"]]
                                                    if proc["pid"] != root_for_pid[proc["pid"]]
                                                    else "根实例（未找到同路径父进程）")
                instances.append(instance)
            result.append({"identity": identity, "name": procs[0]["name"], "path": procs[0]["path"],
                           "instance_count": len(procs), "root_count": root_count,
                           "memory_bytes": sum(proc["memory"] for proc in procs), "instances": instances})
        return sorted(result, key=lambda group: group["memory_bytes"], reverse=True)

    def analyze_duplicates(self):
        """Group same-image processes and show same-path parent/child relationships."""
        duplicate_groups = self._duplicate_analysis()
        win = tk.Toplevel(self)
        win.title("同路径进程实例分析")
        win.geometry("1120x620")
        win.minsize(900, 460)
        win.transient(self)
        win.configure(bg="#f4f6f9")
        tk.Label(win, text="同一路径的多个进程实例", bg="#f4f6f9", fg="#202938",
                 font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=18, pady=(16, 3))
        tk.Label(win, text="按可执行文件路径统计进程数；这不等于重复启动或多开故障。父子关系只作线索。此窗口不会自动结束进程。",
                 bg="#f4f6f9", fg="#758194", font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(0, 10))

        box = tk.Frame(win, bg="white", highlightbackground="#e4e8ee", highlightthickness=1)
        box.pack(fill="both", expand=True, padx=18, pady=(0, 10))
        columns = ("parent", "relation", "started", "memory")
        tree = ttk.Treeview(box, columns=columns, show="tree headings")
        for col, title in [("#0", "程序 / PID / 路径"), ("parent", "父进程 / PID"),
                           ("relation", "同路径关系"), ("started", "启动时间"), ("memory", "工作集")]:
            tree.heading(col, text=title, anchor="w")
        tree.column("#0", width=340, minwidth=230, stretch=True)
        tree.column("parent", width=145, minwidth=120, stretch=True)
        tree.column("relation", width=240, minwidth=200, stretch=True)
        tree.column("started", width=155, minwidth=145, stretch=False)
        tree.column("memory", width=105, minwidth=95, anchor="e", stretch=False)
        scroll = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
        hscroll = ttk.Scrollbar(box, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=scroll.set, xscrollcommand=hscroll.set)
        hscroll.pack(side="bottom", fill="x")
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        if not duplicate_groups:
            tree.insert("", "end", text="当前快照中没有发现同路径多实例。")
        else:
            for group_index, group in enumerate(duplicate_groups):
                sample = group["instances"][0]
                path = group["path"]
                label_path = path if len(path) < 100 else path[:48] + "…" + path[-49:]
                group_name = "%s — %d 个同路径进程，%d 个父子进程树，工作集合计 %s\n%s" % (
                    group["name"], group["instance_count"], group["root_count"], fmt_bytes(group["memory_bytes"]), label_path)
                group_node = tree.insert("", "end", iid="dup_group_%d" % group_index, text=group_name,
                                         open=True, values=("", "仅供核查", "", fmt_bytes(group["memory_bytes"])))
                for proc in group["instances"]:
                    tree.insert(group_node, "end", text="PID %s · %s" % (proc["pid"], proc["name"]),
                                values=("%s (%s)" % (proc["parent_name"], proc["parent_pid"]), proc["same_path_relation"],
                                        proc["started_at"], fmt_bytes(proc["memory"])))

        note = ("解释：同一路径父子进程常见于浏览器、聊天软件等多进程架构；多个根实例表示快照中没有找到同路径父进程，可能是多次启动，也可能由启动器、服务或其他程序创建。\n"
                "此统计不是“重复软件”“未打开”或“可关闭”的判决。隐藏后台任务也会显示；无可见窗口不能证明它没在工作。内存工作集可能共享，组内相加仅供比较。")
        tk.Label(win, text=note, bg="#f4f6f9", fg="#667386", justify="left",
                 font=("Segoe UI", 9), wraplength=900).pack(fill="x", padx=18, pady=(0, 14))

    def export_report(self):
        if not self.rows:
            messagebox.showinfo("尚无进程数据", "等进程扫描完成后再导出。")
            return
        stamp = time.strftime("%Y%m%d_%H%M%S")
        target = filedialog.asksaveasfilename(
            title="导出进程文本报告",
            initialfile="process_report_%s.txt" % stamp,
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not target:
            return
        rows = sorted(self.rows.values(), key=lambda x: x["memory"], reverse=True)
        total_memory = sum(item["memory"] for item in rows)
        lines = [
            "Windows 后台进程报告",
            "导出时间：" + time.strftime("%Y-%m-%d %H:%M:%S"),
            "进程数：%d    工作集内存合计：%s" % (len(rows), fmt_bytes(total_memory)),
            "说明：这是当前进程快照，不包含命令行、账号信息或文件内容。",
            "签名状态仅供身份核对；签名有效不代表程序一定安全，无法验证也不代表恶意。",
            "本报告不能单独判断某程序是否可删除。请结合程序用途、安装来源、父进程和服务/启动项检查。",
            "=" * 100,
            ""
        ]
        duplicate_groups = self._duplicate_analysis()
        lines.extend(["同路径多进程分析（按完整路径统计；不等于重复启动，关系仅供核查）",
                      "同路径多进程组数：%d" % len(duplicate_groups), ""])
        for group in duplicate_groups:
            lines.extend(["[%s] 实例 %d 个；同路径根实例 %d 个；工作集合计 %s" % (
                group["name"], group["instance_count"], group["root_count"], fmt_bytes(group["memory_bytes"])),
                "  路径：%s" % group["path"]])
            for proc in group["instances"]:
                lines.append("  PID %s | 父进程 %s (PID %s) | 启动 %s | %s | 工作集 %s" % (
                    proc["pid"], proc["parent_name"], proc["parent_pid"], proc["started_at"],
                    proc["same_path_relation"], fmt_bytes(proc["memory"])))
            lines.append("")
        for index, item in enumerate(rows, 1):
            key = item["path"].lower()
            rule = self.rules.get(key, {})
            state = {"whitelist": "白名单标记", "blacklist": "黑名单标记"}.get(rule.get("state"), "无标记")
            color = rule.get("color", "自动色")
            lines.extend([
                "[%03d] %s" % (index, item["name"]),
                "  PID：%s    父进程：%s (PID %s)    启动时间：%s    同路径实例：%s" % (item["pid"], item["parent_name"], item["parent_pid"], item["started_at"], item["instance_count"]),
                "  内存工作集：%s    状态：%s    规则：%s    标识色：%s" % (fmt_bytes(item["memory"]), "运行中" if item["memory"] else "无法读取内存/状态待确认", state, color),
                "  发布者/签名：%s" % item["publisher"],
                "  完整路径：%s" % item["path"],
                ""
            ])
        with self.monitor_lock:
            monitor_events = [dict(event) for event in self.monitor_events]
        lines.extend(["自动检测到的前台帧时间尖峰", "说明：帧时间异常与内存变化只表示时间相关，不足以单独证明因果。"])
        if not monitor_events:
            lines.append("本次管理器运行期间尚未检测到自动帧时间尖峰。")
        for event in monitor_events:
            lines.append("[%s] 所属程序：%s | 识别依据：%s | 实际采样：%s PID %s | 峰值 %.2f ms | 基线 %.2f ms | 连续尖峰 %d" % (
                event["time_text"], event.get("app", "未知"),
                event.get("recognition_basis", "旧记录无识别依据字段"), event.get("process_name", "未知"),
                event["pid"], event["peak_frame_ms"],
                event["baseline_ms"], event["spike_count"]))
            if event.get("memory_changes"):
                for row in event["memory_changes"][:10]:
                    lines.append("  PID %s %s | 工作集增加 %s | 当前 %s | %s" % (
                        row["pid"], row["name"], fmt_bytes(row["delta_bytes"]),
                        fmt_bytes(row["memory_bytes"]), row["path"]))
            else:
                lines.append("  卡顿点前后内存样本尚未完成或未发现正向增长。")
            lines.append("")
        try:
            with open(target, "w", encoding="utf-8-sig", newline="\n") as handle:
                handle.write("\n".join(lines))
            messagebox.showinfo("报告已导出", "已保存 %d 个进程的信息：\n%s" % (len(rows), target))
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))

    def _file_identity(self, path):
        """A local matching ID for this export workflow, not a security signature."""
        try:
            absolute = os.path.normcase(os.path.abspath(path))
            stat = os.stat(absolute)
            source = "%s|%s|%s" % (absolute, stat.st_size, getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1000000000)))
            return hashlib.sha256(source.encode("utf-8", "replace")).hexdigest()
        except (OSError, ValueError):
            return None

    def _plan_item_fingerprint(self, item):
        immutable = {key: value for key, value in item.items() if key not in ("action", "reason")}
        immutable["instances"] = []
        for instance in item.get("instances", []):
            if isinstance(instance, dict):
                immutable["instances"].append({key: value for key, value in instance.items()
                                                if key not in ("action", "reason")})
            else:
                immutable["instances"].append(instance)
        canonical = json.dumps(immutable, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()

    def export_ai_template(self):
        if not self.rows:
            messagebox.showinfo("尚无进程数据", "等进程扫描完成后再导出。")
            return
        import platform
        export_id = str(uuid.uuid4())
        groups = {}
        duplicate_groups = self._duplicate_analysis()
        duplicate_by_instance = {}
        duplicate_by_identity = {}
        for duplicate_group in duplicate_groups:
            duplicate_by_identity[duplicate_group["identity"]] = duplicate_group
            for duplicate_instance in duplicate_group["instances"]:
                duplicate_by_instance[(duplicate_instance["pid"], duplicate_instance.get("creation_time_ticks"))] = duplicate_instance
        for proc in self.rows.values():
            path = proc["path"]
            if not path or path.startswith("不可读取"):
                continue
            app_id = self._file_identity(path)
            if not app_id:
                continue
            item = groups.setdefault(app_id, {"app_id": app_id, "name": proc["name"], "path": path,
                                               "publisher": proc["publisher"], "instance_count": 0,
                                               "memory_bytes": 0, "instances": [],
                                               "duplicate_analysis": {"same_path_instances": proc["instance_count"],
                                                                      "same_path_root_instances": 1,
                                                                      "group_working_set_bytes": 0,
                                                                      "note": "同路径关系按单次快照推断，仅供核查。"}})
            item["instance_count"] += 1
            item["memory_bytes"] += proc["memory"]
            duplicate_instance = duplicate_by_instance.get((proc["pid"], proc.get("creation_time_ticks")), {})
            duplicate_group = duplicate_by_identity.get(path.lower())
            if duplicate_group:
                item["duplicate_analysis"].update({"same_path_root_instances": duplicate_group["root_count"],
                                                    "group_working_set_bytes": duplicate_group["memory_bytes"]})
            item["instances"].append({"pid_at_export": proc["pid"], "parent_pid": proc["parent_pid"],
                                      "parent_name": proc["parent_name"], "started_at": proc["started_at"],
                                      "creation_time_ticks": proc["creation_time_ticks"],
                                      "working_set_bytes": proc["memory"],
                                      "same_path_root_pid": duplicate_instance.get("same_path_root_pid", proc["pid"]),
                                      "same_path_relation": duplicate_instance.get("same_path_relation", "当前只有一个同路径实例"),
                                      "action": "review", "reason": ""})
        if not groups:
            messagebox.showwarning("没有可识别的路径", "当前扫描中没有可读取路径并能核对文件信息的程序。")
            return
        with self.monitor_lock:
            monitor_events = [dict(event) for event in self.monitor_events]
        template = {
            "schema_version": 3,
            "export_id": export_id,
            "computer_name": platform.node(),
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "instructions": "请逐个分析 instances 中的 PID 实例，只修改每个 instances[] 内的 action 和 reason。action 只能为 review（待确认）、keep（保留）、close（请求该 PID 对应程序正常退出）或 end_task（只结束该 PID 对应的单个进程）。严禁在程序组级别提出整组关闭；不要更改、增删或重排其他任何字段、程序组或 PID 实例。AI 不能可靠判断实例此刻是否被用户使用；不确定时用 review。Windows、驱动、安全软件、输入法、网络组件和用途不明实例必须设为 review 或 keep。不要建议删除文件、禁用服务或阻止联网。结束任务可能丢失未保存内容。导入后程序会逐个重新核验 PID、启动时间和路径，并由用户最终确认。",
            "monitor_events": [{key: event[key] for key in ("time_text", "app", "pid", "frame_ms", "peak_frame_ms", "baseline_ms", "spike_count", "memory_changes")}
                               for event in monitor_events],
            "items": sorted(groups.values(), key=lambda x: x["memory_bytes"], reverse=True)
        }
        stamp = time.strftime("%Y%m%d_%H%M%S")
        target = filedialog.asksaveasfilename(title="导出进程分析清单",
                    initialfile="process_list_%s.json" % stamp,
                    defaultextension=".json",
                    filetypes=[("JSON 文本清单", "*.json"), ("所有文件", "*.*")])
        if not target:
            return
        try:
            with open(target, "w", encoding="utf-8-sig") as handle:
                json.dump(template, handle, ensure_ascii=False, indent=2)
            manifest = {"schema_version": 3, "export_id": export_id, "computer_name": platform.node(),
                        "items": {item["app_id"]: {"name": item["name"], "path": item["path"],
                                                       "immutable_hash": self._plan_item_fingerprint(item)}
                                  for item in template["items"]}}
            temp = self.manifest_path + ".tmp"
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(manifest, handle, ensure_ascii=False, indent=2)
            os.replace(temp, self.manifest_path)
            messagebox.showinfo("清单已导出", "共导出 %d 个程序组、%d 个可单独选择的 PID 实例。重复关系和近期自动卡顿事件已写入；AI 只能逐实例填写建议。\n\n%s" % (len(groups), sum(item["instance_count"] for item in groups.values()), target))
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))

    def _protected_close_reason(self, path, name):
        import ntpath
        protected_names = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
                           "lsass.exe", "winlogon.exe", "svchost.exe", "dwm.exe", "explorer.exe",
                           "fontdrvhost.exe", "audiodg.exe"}
        if name.lower() in protected_names:
            return "Windows 核心/桌面/音频进程受保护"
        windows_dir = os.environ.get("WINDIR", r"C:\Windows")
        try:
            if ntpath.commonpath([ntpath.normcase(path), ntpath.normcase(windows_dir)]) == ntpath.normcase(windows_dir):
                return "Windows 目录中的程序受保护"
        except (ValueError, TypeError):
            pass
        if os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(sys.argv[0])):
            return "管理器自身受保护"
        return ""

    def _post_close_windows(self, pids):
        wanted = set(int(pid) for pid in pids)
        windows = {pid: {"visible": 0, "hidden": 0, "posted": 0} for pid in wanted}
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def visit(hwnd, _lparam):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            process_id = int(pid.value)
            if process_id in wanted:
                key = "visible" if user32.IsWindowVisible(hwnd) else "hidden"
                windows[process_id][key] += 1
                # Hidden top-level windows are often internal/tray windows. Sending WM_CLOSE
                # to them may not exit the application, so only request close on visible windows.
                if key == "visible" and user32.PostMessageW(hwnd, WM_CLOSE, 0, 0):
                    windows[process_id]["posted"] += 1
            return True
        callback = callback_type(visit)
        user32.EnumWindows(callback, 0)
        return windows

    def import_close_plan(self):
        source = filedialog.askopenfilename(title="选择 AI 修改后的关闭清单",
                    filetypes=[("JSON 清单", "*.json"), ("所有文件", "*.*")])
        if not source:
            return
        try:
            with open(source, "r", encoding="utf-8-sig") as handle:
                plan = json.load(handle)
            with open(self.manifest_path, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
        except (OSError, ValueError) as exc:
            messagebox.showerror("无法读取清单", "JSON 格式错误或没有找到本机对应的导出记录。\n%s" % exc)
            return
        if not isinstance(plan, dict) or not isinstance(manifest, dict):
            messagebox.showerror("清单格式错误", "文件顶层必须是 JSON 对象。没有执行任何操作。")
            return
        if plan.get("schema_version") != 3 or manifest.get("schema_version") != 3 or plan.get("export_id") != manifest.get("export_id"):
            messagebox.showerror("清单不匹配", "这不是本机最近一次导出的清单，或身份校验字段已变化。没有执行任何操作。")
            return
        try:
            import platform
            if plan.get("computer_name") != platform.node() or manifest.get("computer_name") != platform.node():
                messagebox.showerror("电脑不匹配", "这个清单来自另一台电脑。没有执行任何操作。")
                return
        except Exception:
            pass
        allowed = manifest.get("items", {})
        if not isinstance(allowed, dict):
            messagebox.showerror("清单格式错误", "本机导出记录损坏或格式不支持。没有执行任何操作。")
            return
        chosen = []
        seen = set()
        items = plan.get("items")
        if not isinstance(items, list):
            messagebox.showerror("清单格式错误", "items 必须是列表。没有执行任何操作。"); return
        for item in items:
            if not isinstance(item, dict):
                messagebox.showerror("清单格式错误", "发现格式错误的项目。没有执行任何操作。"); return
            if "action" in item or "reason" in item:
                messagebox.showerror("清单格式错误", "操作只能写在具体 PID 实例内，不能在程序组级别设置关闭动作。没有执行任何操作。"); return
            app_id = item.get("app_id")
            if not isinstance(app_id, str):
                messagebox.showerror("清单格式错误", "程序身份标识格式错误。没有执行任何操作。"); return
            recorded = allowed.get(app_id)
            if (not recorded or app_id in seen or item.get("path") != recorded.get("path")
                    or item.get("name") != recorded.get("name")
                    or self._plan_item_fingerprint(item) != recorded.get("immutable_hash")):
                messagebox.showerror("身份校验失败", "操作清单新增、重复或改写了程序身份。没有执行任何操作。"); return
            seen.add(app_id)
            instances = item.get("instances")
            if not isinstance(instances, list) or not instances:
                messagebox.showerror("清单格式错误", "每个程序组必须保留全部 PID 实例。没有执行任何操作。"); return
            if len(instances) != item.get("instance_count"):
                messagebox.showerror("清单不完整", "%s 的实例数量与导出记录不一致。没有执行任何操作。" % recorded["name"]); return
            selected_instances = []
            instance_keys = set()
            for instance in instances:
                if not isinstance(instance, dict) or not isinstance(instance.get("reason"), str):
                    messagebox.showerror("清单格式错误", "每个 PID 实例都必须包含 action 和文本 reason。没有执行任何操作。"); return
                action = instance.get("action")
                if action not in ("review", "keep", "close", "end_task"):
                    messagebox.showerror("清单格式错误", "实例 action 只能是 review、keep、close 或 end_task。没有执行任何操作。"); return
                pid = instance.get("pid_at_export")
                ticks = instance.get("creation_time_ticks")
                if (not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0
                        or not isinstance(ticks, int) or isinstance(ticks, bool) or ticks <= 0):
                    messagebox.showerror("实例身份错误", "PID 或高精度启动时间无效。没有执行任何操作。"); return
                key = (pid, ticks)
                if key in instance_keys:
                    messagebox.showerror("实例重复", "%s 的 PID 实例重复。没有执行任何操作。" % recorded["name"]); return
                instance_keys.add(key)
                if action in ("close", "end_task"):
                    selected_instances.append(instance)
            if not selected_instances:
                continue
            reason = self._protected_close_reason(recorded["path"], recorded["name"])
            if reason:
                messagebox.showerror("包含受保护项目", "%s：%s\n没有执行任何操作。" % (recorded["name"], reason)); return
            if self._file_identity(recorded["path"]) != app_id:
                messagebox.showerror("程序文件已变化", "%s 的文件路径或文件版本信息已变化。请重新导出清单再分析。" % recorded["name"]); return
            chosen.append({"app_id": app_id, "name": recorded["name"], "path": recorded["path"],
                           "instances": selected_instances})
        if seen != set(allowed):
            messagebox.showerror("清单不完整", "操作清单项目被删除或缺失。请保留导出的全部条目，只填写 action 和 reason。没有执行任何操作。"); return
        if not chosen:
            messagebox.showinfo("没有待执行操作", "没有任何单个 PID 实例被标记为 close 或 end_task。")
            return
        try:
            current = snapshot_processes()
        except Exception as exc:
            messagebox.showerror("无法核对当前进程", "进程列表读取失败，没有执行任何操作。\n\n%s" % exc)
            return
        current_by_app = {}
        for proc in current:
            app_id = self._file_identity(proc["path"]) if proc["path"] and not proc["path"].startswith("不可读取") else None
            if app_id:
                current_by_app.setdefault(app_id, []).append(proc)
        targets = []
        skipped_instances = []
        for app in chosen:
            current_procs = current_by_app.get(app["app_id"], [])
            current_by_identity = {(proc["pid"], proc["creation_time_ticks"]): proc for proc in current_procs}
            for instance in app["instances"]:
                key = (instance["pid_at_export"], instance["creation_time_ticks"])
                proc = current_by_identity.get(key)
                if proc:
                    targets.append((app, instance, proc))
                else:
                    skipped_instances.append((app, instance))
        if not targets:
            messagebox.showinfo("导出实例已不在运行", "清单中选定的 PID 实例已退出或无法精确核验；没有对后来启动的同名程序执行操作。")
            return
        preview = []
        total_instances = 0
        total_memory = 0
        target_paths = {}
        target_actions = {}
        target_start_times = {}
        for app, instance, proc in targets:
            total_instances += 1
            total_memory += proc["memory"]
            target_paths[proc["pid"]] = app["path"]
            target_actions[proc["pid"]] = instance["action"]
            target_start_times[proc["pid"]] = proc["creation_time_ticks"]
            reason = str(instance.get("reason", "")).replace("\r", " ").replace("\n", " ")[:240]
            action_label = "正常退出" if instance["action"] == "close" else "结束任务（强制结束进程）"
            preview.append("• %s PID %s：%s，%s；%s\n  %s%s" % (app["name"], proc["pid"], action_label,
                           fmt_bytes(proc["memory"]), instance.get("same_path_relation", "实例关系未提供"), app["path"],
                           ("\n  AI 备注：" + reason) if reason else ""))
        if skipped_instances:
            preview.append("\n已跳过 %d 个所选实例：导出后退出或无法精确核验。" % len(skipped_instances))
        text = ("请核对以下操作和目标：\n\n%s\n\n共匹配 %d 个进程实例，工作集约 %s。" %
                ("\n".join(preview), total_instances, fmt_bytes(total_memory)))
        if not self._confirm_instance_operations(text):
            return
        # Pin each handle and re-check executable path plus creation time, so a recycled PID
        # cannot redirect an imported action to a different process instance.
        handles = {}
        inaccessible_pids = set()
        for pid, expected_path in target_paths.items():
            access = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
            if target_actions[pid] == "end_task":
                access |= PROCESS_TERMINATE
            handle = kernel32.OpenProcess(access, False, int(pid))
            if not handle:
                inaccessible_pids.add(pid)
                continue
            buffer = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buffer))
            path_ok = kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
            creation, exit_time, kernel_time, user_time = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            time_ok = kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time),
                                               ctypes.byref(kernel_time), ctypes.byref(user_time))
            actual_start = ((creation.dwHighDateTime << 32) | creation.dwLowDateTime) if time_ok else None
            if (not path_ok or os.path.normcase(os.path.abspath(buffer.value)) != os.path.normcase(os.path.abspath(expected_path))
                    or actual_start != target_start_times[pid]):
                kernel32.CloseHandle(handle)
                inaccessible_pids.add(pid)
                continue
            handles[pid] = handle
        graceful_pids = [pid for pid in handles if target_actions[pid] == "close"]
        window_info = self._post_close_windows(graceful_pids)
        terminate_failures = set()
        for pid, handle in handles.items():
            if target_actions[pid] == "end_task" and not kernel32.TerminateProcess(handle, 1):
                terminate_failures.add(pid)
        statuses = {}
        deadline = time.time() + 2.5
        while handles and time.time() < deadline:
            for pid, handle in list(handles.items()):
                if kernel32.WaitForSingleObject(handle, 0) == WAIT_OBJECT_0:
                    statuses[pid] = "结束任务完成" if target_actions[pid] == "end_task" else "正常退出完成"
                    kernel32.CloseHandle(handle); handles.pop(pid, None)
            if handles: time.sleep(0.1)
        for pid, handle in handles.items():
            if target_actions[pid] == "end_task":
                statuses[pid] = "结束任务失败，仍运行" if pid in terminate_failures else "结束任务后仍运行"
            else:
                info = window_info.get(pid, {})
                if info.get("posted", 0):
                    statuses[pid] = "已发退出请求，仍运行"
                elif info.get("visible", 0):
                    statuses[pid] = "可见窗口但发送失败"
                elif info.get("hidden", 0):
                    statuses[pid] = "仅隐藏窗口，未发请求"
                else:
                    statuses[pid] = "没有可见窗口，未发请求"
            kernel32.CloseHandle(handle)
        self.refresh()
        counts = {"正常退出完成": 0, "结束任务完成": 0, "已发退出请求，仍运行": 0, "没有可见窗口，未发请求": 0,
                  "仅隐藏窗口，未发请求": 0, "可见窗口但发送失败": 0,
                  "结束任务后仍运行": 0, "结束任务失败，仍运行": 0,
                  "无法核验（权限/进程变化）": 0}
        details = {}
        for app, instance, proc in targets:
            pid = proc["pid"]
            state = "无法核验（权限/进程变化）" if pid in inaccessible_pids else statuses.get(pid)
            if state in counts:
                counts[state] += 1
                key = "%s — %s" % (app["name"], app["path"])
                per_app = details.setdefault(key, {name: 0 for name in counts})
                per_app[state] += 1
        lines = ["操作结果（按导入时匹配到的实例核验）："]
        for label, count in counts.items():
            lines.append("%s：%d 个" % (label, count))
        lines.append("已跳过（导出后退出或无法精确核验）：%d 个" % len(skipped_instances))
        lines.append("\n按程序汇总：")
        for name, per_app in details.items():
            parts = ["%s %d" % (label, count) for label, count in per_app.items() if count]
            lines.append("• %s：%s" % (name, "；".join(parts)))
        lines.append("\n结束任务会直接终止进程，可能丢失未保存内容。Windows 核心进程和 Windows 目录中的程序仍受保护。若进程随后重新出现，说明仍有主程序、服务或启动项在拉起它。")
        messagebox.showinfo("操作结果", "\n".join(lines))

    def _confirm_instance_operations(self, summary, details=""):
        win = tk.Toplevel(self)
        win.title("确认逐个 PID 操作")
        screen_w, screen_h = win.winfo_screenwidth(), win.winfo_screenheight()
        dialog_w, dialog_h = min(760, screen_w - 80), min(500, screen_h - 120)
        dialog_w, dialog_h = max(520, dialog_w), max(360, dialog_h)
        win.geometry("%dx%d" % (dialog_w, dialog_h))
        win.minsize(min(520, screen_w), min(360, screen_h))
        win.resizable(True, True)
        win.transient(self)
        win.configure(bg="#f4f6f9", padx=16, pady=14)
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(2, weight=1)
        win.grid_rowconfigure(4, weight=0)
        win.grid_rowconfigure(5, weight=0)
        tk.Label(win, text="以下只操作列表中的具体 PID 实例", bg="#f4f6f9", fg="#202938",
                 font=("Segoe UI", 13, "bold")).grid(row=0, column=0, sticky="w")
        tk.Label(win, text="只会操作明确列出的实例；未列出的同名程序不会受影响。",
                 bg="#f4f6f9", fg="#687587", font=("Segoe UI", 9)).grid(row=1, column=0, sticky="w", pady=(4, 10))
        frame = tk.Frame(win, bg="white", highlightbackground="#e4e8ee", highlightthickness=1)
        frame.grid(row=2, column=0, sticky="nsew")
        text = tk.Text(frame, height=5, wrap="word", bg="white", fg="#202938", relief="flat",
                       font=("Consolas", 9), padx=10, pady=8)
        yscroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=yscroll.set)
        text.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        text.insert("1.0", summary + "\n\n“正常退出”会请求程序自行关闭；“结束任务”会立即强制结束，可能丢失未保存内容。此操作不会删除程序文件。")
        text.configure(state="disabled")
        details_row = None
        if details:
            detail_frame = tk.Frame(win, bg="#f4f6f9")
            detail_text = tk.Text(detail_frame, height=4, wrap="word", bg="white", fg="#536174",
                                  relief="flat", font=("Segoe UI", 8), padx=8, pady=6)
            detail_text.insert("1.0", details)
            detail_text.configure(state="disabled")
            detail_text.pack(fill="both", expand=True)
            detail_visible = {"value": False}
            detail_button = ttk.Button(win, text="查看完整路径")
            detail_button.grid(row=3, column=0, sticky="w", pady=(6, 0))
            def toggle_details():
                if detail_visible["value"]:
                    detail_frame.grid_remove()
                    detail_button.configure(text="查看完整路径")
                else:
                    detail_frame.grid(row=4, column=0, sticky="nsew", pady=(6, 0))
                    detail_button.configure(text="收起完整路径")
                detail_visible["value"] = not detail_visible["value"]
            detail_button.configure(command=toggle_details)
        result = {"confirmed": False}
        buttons = tk.Frame(win, bg="#f4f6f9")
        buttons.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        def finish(value):
            result["confirmed"] = value
            win.destroy()
        ttk.Button(buttons, text="取消", command=lambda: finish(False)).pack(side="right")
        ttk.Button(buttons, text="确认执行所列 PID", command=lambda: finish(True)).pack(side="right", padx=(0, 8))
        win.protocol("WM_DELETE_WINDOW", lambda: finish(False))
        win.bind("<Escape>", lambda _event: finish(False))
        win.grab_set()
        win.after(0, lambda: win.focus_set())
        self.wait_window(win)
        return result["confirmed"]

    def selected_rule_dialog(self):
        p = self.selected()
        if not p: return
        win = tk.Toplevel(self); win.title("程序规则"); win.transient(self); win.grab_set(); win.configure(bg="white", padx=18, pady=16)
        tk.Label(win, text=p["name"], bg="white", fg="#202938", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        tk.Label(win, text=p["path"], bg="white", fg="#758192", wraplength=430, justify="left", font=("Segoe UI", 8)).pack(anchor="w", pady=(6, 12))
        tk.Label(win, text="本版本只保存白/黑名单标记，不会自动阻止启动或联网。", bg="white", fg="#7e8997", wraplength=430, justify="left", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 12))
        bar = tk.Frame(win, bg="white"); bar.pack(fill="x")
        ttk.Button(bar, text="加入白名单", command=lambda: (self.set_rule("whitelist"), win.destroy())).pack(side="left")
        ttk.Button(bar, text="加入黑名单", command=lambda: (self.set_rule("blacklist"), win.destroy())).pack(side="left", padx=8)
        ttk.Button(bar, text="移除规则", command=lambda: (self.set_rule(None), win.destroy())).pack(side="left")
        ttk.Button(bar, text="关闭", command=win.destroy).pack(side="right")

    def context_menu(self, event):
        row = self.tree.identify_row(event.y)
        selected = tuple(self.tree.selection())
        if row and row not in selected:
            self.tree.selection_set(row)
            selected = (row,)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="查看详情", command=self.show_details)
        menu.add_command(label="管理白名单/黑名单规则", command=self.selected_rule_dialog)
        menu.add_command(label="查找该程序的开机启动项", command=self.show_selected_startup_item)
        menu.add_command(label="设置程序标识颜色…", command=self.choose_program_color)
        if row and row.isdigit() and int(row) in self.rows:
            clicked = self.rows[int(row)]
            menu.add_separator()
            menu.add_command(
                label="结束当前 PID %s…" % clicked["pid"],
                command=lambda iid=row: self.end_selected((iid,), operation_scope="current_pid"))
            path = clicked.get("path", "")
            if path and not path.startswith("不可读取"):
                normalized_path = os.path.normcase(os.path.abspath(path))
                menu.add_command(
                    label="选择并结束同路径 PID…",
                    command=lambda proc=dict(clicked): self.choose_same_path_processes(proc))
            else:
                menu.add_command(label="结束该程序同路径全部 PID（路径不可读）…", state="disabled")
        else:
            menu.add_separator()
            menu.add_command(label="结束当前 PID…", state="disabled")
            menu.add_command(label="结束该程序同路径全部 PID…", state="disabled")
        menu.tk_popup(event.x_root, event.y_root)
        return "break"

    def choose_same_path_processes(self, clicked):
        """Let the user explicitly choose same-image instances; never default-select."""
        path = clicked.get("path", "")
        if not path or path.startswith("不可读取"):
            messagebox.showinfo("无法精确筛选", "该进程路径不可读，无法安全列出同路径实例。请刷新或使用管理员模式读取路径。")
            return
        normalized = os.path.normcase(os.path.abspath(path))
        candidates = [dict(proc) for proc in self.rows.values()
                      if proc.get("path") and not proc["path"].startswith("不可读取")
                      and os.path.normcase(os.path.abspath(proc["path"])) == normalized]
        candidates.sort(key=lambda proc: (proc.get("started_at", ""), proc["pid"]))

        win = tk.Toplevel(self)
        win.title("选择要结束的 PID")
        win.transient(self)
        win.configure(bg="white")
        win.minsize(700, 360)
        screen_h = win.winfo_screenheight()
        dialog_h = min(560, max(360, screen_h - 100))
        win.geometry("900x%d" % dialog_h)
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(3, weight=1)
        tk.Label(win, text="选择要结束的进程实例", bg="white", fg="#202938",
                 font=("Segoe UI", 13, "bold")).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 0))
        tk.Label(win, text="先选择 PID（Ctrl/Shift 多选，Ctrl+A 全选），再点窗口右下角的“结束所选 PID”。只会操作选中的 PID。",
                 bg="white", fg="#687587", font=("Segoe UI", 9)).grid(row=1, column=0, sticky="w", padx=16, pady=(4, 8))
        tk.Label(win, text=path, bg="white", fg="#687587", font=("Segoe UI", 8),
                 wraplength=850, justify="left").grid(row=2, column=0, sticky="w", padx=16, pady=(0, 8))

        box = tk.Frame(win, bg="white")
        box.grid(row=3, column=0, sticky="nsew", padx=16)
        box.grid_columnconfigure(0, weight=1)
        box.grid_rowconfigure(0, weight=1)
        columns = ("pid", "memory", "started", "parent", "window")
        tree = ttk.Treeview(box, columns=columns, show="headings", selectmode="extended")
        for col, label, width in (("pid", "PID", 90), ("memory", "内存", 100),
                                  ("started", "启动时间", 155), ("parent", "父进程 / PID", 180),
                                  ("window", "窗口状态", 130)):
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="w")
        scrollbar = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        iid_to_proc = {}
        for proc in candidates:
            iid = tree.insert("", "end", values=(proc["pid"], fmt_bytes(proc.get("memory", 0)),
                                                  proc.get("started_at", "未知"),
                                                  "%s (%s)" % (proc.get("parent_name", "未知"), proc.get("parent_pid", "未知")),
                                                  proc.get("window_state", "未知")))
            iid_to_proc[iid] = proc
        tree.bind("<Control-a>", lambda _event: (tree.selection_set(tree.get_children()), "break")[1])
        tree.bind("<Control-A>", lambda _event: (tree.selection_set(tree.get_children()), "break")[1])

        buttons = tk.Frame(win, bg="white")
        buttons.grid(row=4, column=0, sticky="ew", padx=16, pady=12)
        ttk.Button(buttons, text="取消", command=win.destroy).pack(side="right")
        def submit():
            selected = [iid_to_proc[iid] for iid in tree.selection() if iid in iid_to_proc]
            if not selected:
                messagebox.showinfo("尚未选择 PID", "请先选择一个或多个要结束的 PID。", parent=win)
                return
            win.destroy()
            self.end_selected(operation_scope="selected_same_path", processes=selected)
        ttk.Button(buttons, text="结束所选 PID", command=submit).pack(side="right", padx=(0, 8))
        win.bind("<Escape>", lambda _event: win.destroy())
        win.grab_set()
        win.after(0, tree.focus_set)

    def end_selected(self, selected_iids=None, operation_scope="selected", processes=None):
        if processes is not None:
            chosen = list(processes)
        elif selected_iids is None:
            chosen = self.selected_processes()
        else:
            chosen = [self.rows[int(iid)] for iid in selected_iids
                      if str(iid).isdigit() and int(iid) in self.rows]
        if not chosen:
            messagebox.showinfo("选择程序", "请在列表中选择一个或多个进程。按住 Ctrl 或 Shift 可多选。")
            return
        protected = []
        targets = []
        for proc in chosen:
            reason = self._protected_close_reason(proc["path"], proc["name"])
            if proc["pid"] in (0, 4, os.getpid()) or reason:
                protected.append((proc, reason or "系统核心进程或管理器自身受保护"))
            else:
                targets.append(proc)
        if not targets:
            messagebox.showwarning("受保护进程", "所选项目均受保护，未执行任何操作。\n" + "\n".join(
                "%s PID %s：%s" % (p["name"], p["pid"], reason) for p, reason in protected))
            return
        if operation_scope == "current_pid":
            scope_text = "右键点选的当前 PID"
        elif operation_scope == "selected_same_path":
            scope_text = "你在同路径列表中勾选的 PID"
        elif operation_scope == "same_path":
            scope_text = "同一可执行文件路径下的全部 PID"
        else:
            scope_text = "当前选中的 PID"
        summary = "将结束%s，共 %d 个单独进程：\n\n%s\n\n未列出的进程不会被结束。" % (
            scope_text, len(targets), "\n".join("%s · PID %s · %s" % (p["name"], p["pid"], fmt_bytes(p["memory"]))
                                               for p in targets))
        summary += "\n操作前会再次核对 PID、完整路径和启动时间。未选中的 PID，以及操作后新启动的实例不会被结束。"
        details = "\n".join("%s · PID %s\n%s" % (p["name"], p["pid"], p["path"]) for p in targets)
        if protected:
            summary += "\n\n已排除受保护项目：\n" + "\n".join(
                "%s PID %s：%s" % (p["name"], p["pid"], reason) for p, reason in protected)
        if not self._confirm_instance_operations(summary, details):
            return

        if self.after_refresh:
            self.after_cancel(self.after_refresh)
            self.after_refresh = None
        self._refresh_generation += 1  # Invalidate any older scan still running.
        self.refresh_btn.configure(state="disabled")
        self.time_var.set("结束后核验中…")
        initial_identities = {(p["pid"], p.get("creation_time_ticks")) for p in self.rows.values()}
        selected_paths = {os.path.normcase(os.path.abspath(p["path"])) for p in targets
                          if p.get("path") and not p["path"].startswith("不可读取")}

        def work():
            results = {}
            handles = {}
            expected = {p["pid"]: p for p in targets}
            for proc in targets:
                pid = proc["pid"]
                if (not proc.get("creation_time_ticks") or not proc.get("path")
                        or proc["path"].startswith("不可读取")):
                    results[pid] = "身份信息不足，未操作"
                    continue
                handle = kernel32.OpenProcess(
                    PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
                if not handle:
                    results[pid] = "无法打开进程（权限不足或已退出），待刷新核验"
                    continue
                buf = ctypes.create_unicode_buffer(32768)
                size = wintypes.DWORD(len(buf))
                path_ok = kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
                creation, exit_time, kernel_time, user_time = FILETIME(), FILETIME(), FILETIME(), FILETIME()
                time_ok = kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time),
                                                   ctypes.byref(kernel_time), ctypes.byref(user_time))
                actual_ticks = ((creation.dwHighDateTime << 32) | creation.dwLowDateTime) if time_ok else None
                path_matches = (path_ok and os.path.normcase(os.path.abspath(buf.value)) ==
                                os.path.normcase(os.path.abspath(proc["path"])))
                if not path_matches or actual_ticks != proc["creation_time_ticks"]:
                    results[pid] = "进程身份已变化，已跳过"
                    kernel32.CloseHandle(handle)
                    continue
                if kernel32.WaitForSingleObject(handle, 0) == WAIT_OBJECT_0:
                    results[pid] = "操作前已退出"
                    kernel32.CloseHandle(handle)
                    continue
                if not kernel32.TerminateProcess(handle, 1):
                    results[pid] = "结束请求失败：%s" % ctypes.WinError(ctypes.get_last_error())
                    kernel32.CloseHandle(handle)
                    continue
                handles[pid] = handle
                results[pid] = "已发结束请求，等待退出核验"

            deadline = time.time() + 3.0
            while handles and time.time() < deadline:
                for pid, handle in list(handles.items()):
                    if kernel32.WaitForSingleObject(handle, 0) == WAIT_OBJECT_0:
                        results[pid] = "已核验退出"
                        kernel32.CloseHandle(handle)
                        del handles[pid]
                if handles:
                    time.sleep(0.1)
            for pid, handle in handles.items():
                results[pid] = "结束请求已发出，但目标 PID 仍运行"
                kernel32.CloseHandle(handle)

            # Allow immediate application relaunches to appear before reporting.
            time.sleep(1.0)
            fresh_data = None
            scan_error = ""
            newly_started_same_path = []
            try:
                fresh_data = snapshot_processes()
            except Exception as exc:
                scan_error = str(exc)

            if fresh_data is not None:
                # Detect relaunches for reporting only. The user confirmed an
                # exact PID set; never expand that set to newly created PIDs.
                newly_started_same_path = [p for p in fresh_data
                    if (p["pid"], p.get("creation_time_ticks")) not in initial_identities
                    and p.get("creation_time_ticks") is not None
                    and os.path.normcase(os.path.abspath(p.get("path", ""))) in selected_paths]
                try:
                    self._enrich_publishers(fresh_data)
                except Exception:
                    pass

                current = {p["pid"]: p for p in fresh_data}
                for pid, proc in expected.items():
                    current_proc = current.get(pid)
                    same_identity = bool(current_proc and
                        current_proc.get("creation_time_ticks") == proc.get("creation_time_ticks") and
                        os.path.normcase(os.path.abspath(current_proc.get("path", ""))) ==
                        os.path.normcase(os.path.abspath(proc.get("path", ""))))
                    if same_identity:
                        results[pid] = "目标进程仍在运行（刷新核验）"
                    elif current_proc and (not current_proc.get("creation_time_ticks") or
                                           current_proc.get("path", "").startswith("不可读取")):
                        if "待刷新核验" in results.get(pid, "") or "仍运行" in results.get(pid, ""):
                            results[pid] = "PID 仍存在，但身份字段受限，无法确认是否为原进程"
                    elif current_proc and "待刷新核验" in results.get(pid, ""):
                        results[pid] = "原进程已退出或 PID 已被复用（刷新核验）"
                    elif not current_proc and "待刷新核验" in results.get(pid, ""):
                        results[pid] = "刷新时目标 PID 已不存在，原进程已退出"
                selected_identities = {(p["pid"], p.get("creation_time_ticks")) for p in targets}
                remaining = [p for p in fresh_data if
                             (p["pid"], p.get("creation_time_ticks")) not in selected_identities and
                             os.path.normcase(os.path.abspath(p.get("path", ""))) in selected_paths]
            else:
                remaining = []

            def finish():
                if fresh_data is not None:
                    selection_identities = {
                        proc["pid"]: proc.get("creation_time_ticks") for proc in chosen
                        if proc.get("creation_time_ticks") is not None
                    }
                    self._apply(fresh_data, selection_identities=selection_identities)
                else:
                    self.refresh()
                lines = ["按所选 PID 核验结果："]
                for proc in targets:
                    lines.append("• %s PID %s：%s" % (proc["name"], proc["pid"],
                                                        results.get(proc["pid"], "未能确认")))
                if protected:
                    lines.append("\n受保护项目未操作：%d 个" % len(protected))
                if newly_started_same_path:
                    restarted = "、".join("%s PID %s" % (p["name"], p["pid"])
                                           for p in newly_started_same_path[:12])
                    lines.append("\n操作后发现同路径新实例：%s。为遵守你确认的 PID 范围，未自动结束；可能由启动器或守护进程重新启动。" % restarted)
                if fresh_data is not None and remaining:
                    pids = "、".join("%s PID %s" % (p["name"], p["pid"]) for p in remaining[:12])
                    lines.append("\n结束后仍检测到同路径的其他实例：" + pids)
                    lines.append("这可能是未选中的实例，也可能是程序或守护进程重新启动的实例；仅凭路径不能区分原因。")
                elif fresh_data is None:
                    lines.append("\n结束后刷新核验失败，当前列表保留旧结果。错误：%s" % scan_error)
                messagebox.showinfo("结束进程结果", "\n".join(lines))

            self.after(0, finish)

        threading.Thread(target=work, daemon=True).start()

    def on_close(self):
        if self.after_refresh: self.after_cancel(self.after_refresh)
        if self.foreground_refresh_after:
            try:
                self.after_cancel(self.foreground_refresh_after)
            except tk.TclError:
                pass
        self.monitor_stop.set()
        if self.presentmon_process and self.presentmon_process.poll() is None:
            if isinstance(self.presentmon_process, ElevatedProcess):
                try:
                    self.presentmon_process.terminate()
                    self.presentmon_process.wait(timeout=2.0)
                except Exception:
                    pass
            else:
                try:
                    self.presentmon_process.send_signal(getattr(__import__("signal"), "CTRL_BREAK_EVENT"))
                    self.presentmon_process.wait(timeout=2.5)
                except Exception:
                    try:
                        self.presentmon_process.terminate()
                        self.presentmon_process.wait(timeout=2.0)
                    except Exception:
                        pass
        reader = getattr(self, "presentmon_error_thread", None)
        if reader and reader.is_alive():
            reader.join(timeout=0.5)
        if self.presentmon_csv_path:
            try:
                if os.path.exists(self.presentmon_csv_path):
                    os.remove(self.presentmon_csv_path)
            except OSError:
                pass
        self.destroy()


if __name__ == "__main__":
    Manager().mainloop()
