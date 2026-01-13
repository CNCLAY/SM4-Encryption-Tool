import tkinter as tk
from tkinter import filedialog
import secrets
import os
import sys
from ctypes import windll


# ==========================================
# 资源路径获取函数 (支持 Nuitka/PyInstaller 单文件模式)
# ==========================================
def get_resource_path(relative_path):
    """
    兼容 Nuitka 和 PyInstaller 的资源路径获取函数
    """
    # Nuitka 会将程序解压到临时目录，通过 __file__ 访问
    base_path = os.path.dirname(os.path.abspath(__file__))
    
    # 如果是 PyInstaller (保留兼容性)
    if hasattr(sys, '_MEIPASS'):
        base_path = sys._MEIPASS
        
    return os.path.join(base_path, relative_path)


# ==========================================
# SM4 国产对称加密算法实现
# ==========================================
class SM4:
    def __init__(self):
        # S盒：用于非线性变换的查找表（16x16）
        self.Sbox = [
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
        ]
        # FK：系统参数，用于密钥扩展算法
        self.FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
        # CK：固定参数，用于密钥扩展生成轮密钥
        self.CK = [0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
                   0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
                   0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
                   0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279]

    def _rotl(self, x, n):
        """ 32位循环左移操作 """
        return ((x << n) & 0xffffffff) | (x >> (32 - n))

    def _t_transform(self, x):
        """ 加解密过程中的合成置换 T """
        # 1. 非线性置换：将32位分成4个字节，分别通过S盒
        b = [(x >> (24 - i * 8)) & 0xff for i in range(4)]
        b = [self.Sbox[i] for i in b]
        c = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
        # 2. 线性置换 L
        return c ^ self._rotl(c, 2) ^ self._rotl(c, 10) ^ self._rotl(c, 18) ^ self._rotl(c, 24)

    def _t_transform_key(self, x):
        """ 密钥扩展过程中的合成置换 T """
        # 1. 非线性置换（同上）
        b = [(x >> (24 - i * 8)) & 0xff for i in range(4)]
        b = [self.Sbox[i] for i in b]
        c = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
        # 2. 线性置换 L'（与加解密时的线性置换公式不同）
        return c ^ self._rotl(c, 13) ^ self._rotl(c, 23)

    def _expand_key(self, key):
        """ 密钥扩展算法：将128位原始密钥生成32个32位轮密钥 """
        # 将字节数组密钥转换为4个32位整数
        mk = [int.from_bytes(key[i:i + 4], 'big') for i in range(0, 16, 4)]
        # 初始化与FK参数异或
        k = [mk[i] ^ self.FK[i] for i in range(4)] + [0] * 32
        rk = []
        # 迭代生成32轮子密钥
        for i in range(32):
            k[i + 4] = k[i] ^ self._t_transform_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ self.CK[i])
            rk.append(k[i + 4])
        return rk

    def crypt_ecb(self, data, key, encrypt=True):
        """
        SM4 ECB模式加解密核心函数
        data: bytes 原始数据
        key: bytes 16字节密钥
        encrypt: bool True为加密，False为解密
        """
        rk = self._expand_key(key)
        # 如果是解密，则轮密钥反序使用
        if not encrypt: rk = rk[::-1]

        # 加密时进行 PKCS#7 填充
        if encrypt:
            pad = 16 - len(data) % 16
            data += bytes([pad] * pad)

        res = bytearray()
        # 按16字节（128位）为一个分组进行迭代
        for i in range(0, len(data), 16):
            # 将分块转为4个32位整数
            x = [int.from_bytes(data[i + j:i + j + 4], 'big') for j in range(0, 16, 4)]
            # 32轮迭代变换
            for r in range(32):
                x[0], x[1], x[2], x[3] = x[1], x[2], x[3], x[0] ^ self._t_transform(x[1] ^ x[2] ^ x[3] ^ rk[r])
            # 反序组合并转回字节
            res += b''.join(x[::-1][i].to_bytes(4, 'big') for i in range(4))

        # 解密后去除 PKCS#7 填充
        if not encrypt:
            pad = res[-1]
            if pad > 16: raise ValueError("密钥错误")
            res = res[:-pad]
        return bytes(res)


# ==========================================
# 自动关闭的提示弹窗组件
# ==========================================
class AutoCloseMessage(tk.Toplevel):
    def __init__(self, parent, title, message, color="#0062FF"):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x200")
        self.resizable(False, False)  # 禁止拉伸
        self.configure(bg="white")
        self.attributes("-topmost", True)  # 窗口置顶

        # 居中显示逻辑
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

        self.countdown = 3  # 设置3秒倒计时
        # 消息文本标签
        tk.Label(self, text=message, font=("Microsoft YaHei UI", 11), bg="white", fg="#1E293B",
                 wraplength=350, pady=30).pack()

        self.btn_text = tk.StringVar(value=f"确定 ({self.countdown})")
        # 确认按钮
        self.btn = tk.Button(self, textvariable=self.btn_text, bg=color, fg="white",
                             font=("Microsoft YaHei UI", 10, "bold"),
                             relief=tk.FLAT, padx=30, pady=8, command=self.destroy, cursor="hand2")
        self.btn.pack(pady=10)
        # 启动计时器
        self.update_clock()

    def update_clock(self):
        """ 递归执行倒计时 """
        if self.countdown > 1:
            self.countdown -= 1
            self.btn_text.set(f"确定 ({self.countdown})")
            self.after(1000, self.update_clock)
        else:
            self.destroy()  # 时间到则关闭窗口


# ==========================================
# 主程序逻辑类 (SM4App)
# ==========================================
class SM4App:
    def __init__(self, root):
        self.root = root

        # --- 1. 设置 Windows 任务栏图标关联 (防止显示Python默认图标) ---
        try:
            myappid = 'mycompany.sm4tool.v3.0'
            windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except:
            pass

        # 2. 加载窗口图标 (核心修改)
        icon_path = get_resource_path("app_icon.ico")
        try:
            if os.path.exists(icon_path):
                # 如果打包时包含了文件，直接加载
                self.root.iconbitmap(icon_path)
            else:
                # 关键：如果找不到 ico 文件，直接从运行的 exe 自身提取图标资源
                # sys.executable 指向当前运行的 .exe 文件路径
                self.root.iconbitmap(sys.executable)
        except Exception as e:
            print(f"图标加载失败: {e}")

        # --- 3. 基础界面设置 ---
        self.root.title("SM4文件加密解密工具")
        self.root.option_add('*HighlightThickness', '0')  # 全局移除控件高亮边框

        self.sm4 = SM4()  # 实例化加密算法类
        self.placeholder_txt = "请选择需要处理的文件..."

        # 定义核心变量（绑定UI）
        self.encrypt_file_path = tk.StringVar(value=self.placeholder_txt)
        self.decrypt_file_path = tk.StringVar(value=self.placeholder_txt)
        self.encrypt_key = tk.StringVar()
        self.decrypt_key = tk.StringVar()
        self.processed_data = {"encrypt": None, "decrypt": None}  # 暂存处理后的内存数据
        self.original_filename = {"encrypt": "", "decrypt": ""}  # 记录原文件名

        self.setup_colors()  # 初始化配色方案
        self.create_widgets()  # 构建UI界面
        self.root.bind("<Configure>", self.on_window_resize)  # 绑定窗口缩放事件

    def setup_colors(self):
        """ 定义UI所使用的现代感配色 """
        self.clr_bg = "#F8FAFC"
        self.clr_card = "#FFFFFF"
        self.clr_primary = "#0062FF"
        self.clr_primary_hover = "#0052D9"
        self.clr_success = "#10B981"
        self.clr_success_hover = "#059669"
        self.clr_download = "#6366F1"
        self.clr_disabled = "#E2E8F0"
        self.clr_disabled_txt = "#94A3B8"
        self.clr_border = "#E2E8F0"
        self.clr_text_main = "#1E293B"
        self.root.configure(bg=self.clr_bg)

    def show_msg(self, title, message, color="#0062FF"):
        """ 封装自定义消息弹窗的调用 """
        AutoCloseMessage(self.root, title, message, color)

    def create_modern_button(self, parent, text, bg, command, fg="white", font=("Microsoft YaHei UI", 10, "bold"),
                             pady=10):
        """ 快捷创建扁平化现代按钮 """
        btn = tk.Button(parent, text=text, bg=bg, fg=fg, font=font, relief=tk.FLAT, bd=0, cursor="hand2",
                        command=command, activeforeground="white", padx=20, pady=pady, takefocus=0)
        return btn

    def create_widgets(self):
        """ 核心界面布局构建 """
        # 头部标题区域
        header = tk.Frame(self.root, bg=self.clr_bg)
        header.pack(fill=tk.X, pady=(40, 20))
        tk.Label(header, text="SM4 文件加密解密", font=("Microsoft YaHei UI", 32, "bold"),
                 bg=self.clr_bg, fg=self.clr_text_main).pack()

        # 中部卡片容器（左右两栏布局）
        container = tk.Frame(self.root, bg=self.clr_bg)
        container.pack(fill=tk.X, padx=60, pady=10)
        container.columnconfigure(0, weight=1)
        container.columnconfigure(1, weight=1)

        # 构建加密卡片和解密卡片
        self.btn_dl_enc = self.build_card(container, 0, "文件加密", self.clr_primary, self.clr_primary_hover, "encrypt")
        self.btn_dl_dec = self.build_card(container, 1, "文件解密", self.clr_success, self.clr_success_hover, "decrypt")

        # 底部指南区域
        self.create_usage_instructions()

        # 最底部版权信息
        copyright_footer = tk.Frame(self.root, bg=self.clr_bg)
        copyright_footer.pack(side=tk.BOTTOM, fill=tk.X, pady=(0, 15))

    def build_card(self, container, col, title, theme_clr, theme_hover, mode):
        """ 构建单个功能卡片（加密或解密） """
        # 外层边框装饰
        wrap = tk.Frame(container, bg=self.clr_border, padx=1, pady=1)
        wrap.grid(row=0, column=col, padx=15, sticky="nsew")

        # 内层白色主体
        card = tk.Frame(wrap, bg=self.clr_card, padx=40, pady=30)
        card.pack(fill=tk.BOTH, expand=True)

        # 卡片标题
        tk.Label(card, text=title, font=("Microsoft YaHei UI", 18, "bold"), bg=self.clr_card).pack(anchor=tk.W,
                                                                                                   pady=(0, 20))

        # 1. 文件选择行
        f_row = tk.Frame(card, bg=self.clr_card)
        f_row.pack(fill=tk.X, pady=(0, 15))
        f_var = self.encrypt_file_path if mode == "encrypt" else self.decrypt_file_path
        ent = tk.Entry(f_row, textvariable=f_var, font=("Microsoft YaHei UI", 10), bg=self.clr_bg, bd=0,
                       fg=self.clr_disabled_txt)
        ent.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=7)
        btn_sel = self.create_modern_button(f_row, "选择文件", "#F1F5F9", command=lambda: self.browse_file(mode, ent),
                                            fg="#1E293B", pady=5)
        btn_sel.bind("<Enter>", lambda e: btn_sel.config(bg="#E2E8F0"))  # 悬停效果
        btn_sel.bind("<Leave>", lambda e: btn_sel.config(bg="#F1F5F9"))
        btn_sel.pack(side=tk.RIGHT, padx=(10, 0))

        # 2. 密钥输入行
        k_row = tk.Frame(card, bg=self.clr_card)
        k_row.pack(fill=tk.X, pady=(0, 25))
        k_var = self.encrypt_key if mode == "encrypt" else self.decrypt_key
        kent = tk.Entry(k_row, textvariable=k_var, font=("Consolas", 12), bg=self.clr_bg, bd=0)
        kent.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=7)

        # 仅加密模式提供“随机密钥”功能
        if mode == "encrypt":
            btn_gen = self.create_modern_button(k_row, "随机密钥", "#F1F5F9", command=self.generate_random_key,
                                                fg="#1E293B", pady=5)
            btn_gen.bind("<Enter>", lambda e: btn_gen.config(bg="#E2E8F0"))
            btn_gen.bind("<Leave>", lambda e: btn_gen.config(bg="#F1F5F9"))
            btn_gen.pack(side=tk.RIGHT, padx=(10, 0))

        # 3. 立即执行按钮
        btn_act = self.create_modern_button(card, f"立即执行{title}", theme_clr,
                                            command=lambda: self.execute_task(mode))
        btn_act.bind("<Enter>", lambda e: btn_act.config(bg=theme_hover))
        btn_act.bind("<Leave>", lambda e: btn_act.config(bg=theme_clr))
        btn_act.pack(fill=tk.X, ipady=10)

        # 4. 保存按钮（初始化为禁用状态）
        dl_btn = self.create_modern_button(card, "⬇ 保存处理结果", self.clr_disabled,
                                           command=lambda: self.download_file(mode), fg=self.clr_disabled_txt)
        dl_btn.pack(fill=tk.X, pady=(15, 0), ipady=8)
        return dl_btn

    def create_usage_instructions(self):
        """ 创建界面底部的蓝色使用指南框 """
        footer = tk.Frame(self.root, bg=self.clr_bg)
        footer.pack(fill=tk.X, padx=75, pady=(5, 15))
        self.instr_box = tk.Frame(footer, bg="#EFF6FF", padx=30, pady=15)
        self.instr_box.pack(fill=tk.X)
        tk.Label(self.instr_box, text="💡 使用指南", font=("Microsoft YaHei UI", 12, "bold"), bg="#EFF6FF",
                 fg=self.clr_primary).pack(anchor=tk.W, pady=(0, 5))
        self.guide_texts = [
            "• 第一步：在左侧或右侧区域选择您想要处理的文件。",
            "• 第二步：输入32位16进制密钥（加密可点击“随机密钥”生成）。",
            "• 第三步：点击“立即执行”，待提示成功后，下载按钮将激活供您保存。"
        ]
        self.guide_labels = [
            tk.Label(self.instr_box, text=t, font=("Microsoft YaHei UI", 9), bg="#EFF6FF", fg="#475569",
                     justify=tk.LEFT, anchor=tk.W) for t in self.guide_texts]
        for lbl in self.guide_labels: lbl.pack(fill=tk.X, pady=1)

    def on_window_resize(self, event):
        """ 处理窗口大小改变时，指南文本的自动换行宽度 """
        if event.widget == self.root:
            try:
                w = self.instr_box.winfo_width() - 60
                if w > 100:
                    for lbl in self.guide_labels: lbl.configure(wraplength=w)
            except:
                pass

    def browse_file(self, mode, entry_widget):
        """ 弹出文件对话框并更新对应路径变量 """
        p = filedialog.askopenfilename()
        if p:
            if mode == "encrypt":
                self.encrypt_file_path.set(p)
            else:
                self.decrypt_file_path.set(p)
            entry_widget.config(fg=self.clr_text_main)
            self.processed_data[mode] = None  # 重置已处理的数据，强迫用户重新点击执行
            self.set_button_disabled(mode)  # 禁用保存按钮

    def set_button_active(self, mode):
        """ 激活保存结果按钮 """
        btn = self.btn_dl_enc if mode == "encrypt" else self.btn_dl_dec
        btn.config(bg=self.clr_download, fg="white")
        btn.bind("<Enter>", lambda e: btn.config(bg="#4F46E5"))
        btn.bind("<Leave>", lambda e: btn.config(bg=self.clr_download))

    def set_button_disabled(self, mode):
        """ 禁用保存结果按钮 """
        btn = self.btn_dl_enc if mode == "encrypt" else self.btn_dl_dec
        btn.config(bg=self.clr_disabled, fg=self.clr_disabled_txt)
        btn.unbind("<Enter>")
        btn.unbind("<Leave>")

    def generate_random_key(self):
        """ 生成符合SM4要求的128位（32位16进制字符）随机密钥 """
        self.encrypt_key.set(secrets.token_hex(16).upper())
        self.processed_data["encrypt"] = None
        self.set_button_disabled("encrypt")

    def execute_task(self, mode):
        """ 执行实际的加解密逻辑 """
        file_path = self.encrypt_file_path.get() if mode == "encrypt" else self.decrypt_file_path.get()
        key_hex = self.encrypt_key.get().strip() if mode == "encrypt" else self.decrypt_key.get().strip()

        # 验证输入有效性
        if file_path == self.placeholder_txt or not file_path:
            self.show_msg("提示", "⚠️ 请先选择一个有效的文件进行处理", "#E11D48")
            return
        if len(key_hex) != 32:
            self.show_msg("密钥错误", "❌ 请输入或生成32位16进制密钥", "#E11D48")
            return

        try:
            # 将输入的16进制字符串转为字节流
            key_bytes = bytes.fromhex(key_hex)
            # 读取原始文件
            with open(file_path, 'rb') as f:
                data = f.read()
            # 调用 SM4 算法进行处理
            res = self.sm4.crypt_ecb(data, key_bytes, encrypt=(mode == "encrypt"))

            # 将处理结果暂存在内存中
            self.processed_data[mode] = res
            self.original_filename[mode] = os.path.basename(file_path)
            self.set_button_active(mode)  # 激活保存按钮
            self.show_msg("操作成功", f"🎉 文件已成功{'加密' if mode == 'encrypt' else '解密'}！\n结果已就绪，请保存。",
                          self.clr_success)
        except Exception:
            self.show_msg("处理失败", "⚠️ 密钥不正确或文件已损坏", "#E11D48")

    def download_file(self, mode):
        """ 将内存中处理好的数据保存到物理文件 """
        data = self.processed_data.get(mode)
        if data is None:
            self.show_msg("下载失败", f"请先点击上方的“立即执行{'文件加密' if mode == 'encrypt' else '文件解密'}”",
                          "#E11D48")
            return

        # 智能生成默认保存的文件名
        orig_name = self.original_filename[mode]
        name, ext = os.path.splitext(orig_name)
        default_name = f"{name}-enc{ext}" if mode == "encrypt" else (
            name.replace("-enc", "") + ext if "-enc" in name else "dec_" + orig_name)

        # 弹出保存路径对话框
        save_p = filedialog.asksaveasfilename(initialfile=default_name, title="选择保存路径")
        if save_p:
            with open(save_p, 'wb') as f: f.write(data)
            self.show_msg("保存成功", "✅ 文件已成功下载到本地", self.clr_success)


# ==========================================
# 程序启动入口
# ==========================================
if __name__ == "__main__":
    # 高 DPI 适配：解决 Windows 下界面缩放导致的模糊问题
    try:
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass

    root = tk.Tk()

    # --- 核心改动：初始化时先隐藏窗口，防止由于计算尺寸导致的视觉跳动 ---
    root.withdraw()

    # 设置默认窗口尺寸
    root.geometry("1100x750")

    # 初始化应用逻辑
    app = SM4App(root)

    # 强制让所有界面布局逻辑在后台完成计算
    root.update_idletasks()

    # --- 核心改动：一切准备就绪后再显示主窗口 ---
    root.deiconify()

    # 进入 Tkinter 事件主循环
    root.mainloop()