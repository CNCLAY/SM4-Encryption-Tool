# SM4 File Encryptor & Decryptor | 国产SM4文件加解密工具
[English](#english) | [中文说明](#中文说明)  | [下载地址](#download)
<a id="中文说明"></a>
## 中文说明

### 简介

这是一个基于 Python 和 Tkinter 开发的现代 GUI 工具，用于实现国产商用密码算法 **SM4 (GB/T 32907-2016)** 的文件加解密。该工具采用 ECB 模式，支持 128 位密钥，具有界面简洁、操作直观、无第三方依赖等特点。

### 核心功能

- **国产算法支持**：纯 Python 实现的标准 SM4 算法（含 S 盒、线性变换、密钥扩展）。
- **现代 UI 设计**：采用扁平化设计风格，支持自动关闭的提示弹窗和高 DPI 适配（防止界面模糊）。
- **安全随机密钥**：内置基于 secrets 模块的强随机密钥生成器。
- **内存安全处理**：文件处理在内存中完成，待用户确认后再写入磁盘。
- **兼容性优化**：完美适配 Nuitka 和 PyInstaller 打包模式，支持嵌入图标。

### 快速开始

1. **环境要求**：Python 3.6+

2. **运行程序**：

   ```sehll
   python sm4_tool.py
   ```

3. **使用步骤**：

   - 选择需要加密/解密的文件。
   - 输入或生成 32 位十六进制密钥。
   - 点击“立即执行”，验证成功后点击“保存处理结果”。

### 打包发布

本项目特别优化了打包逻辑。推荐使用 **Nuitka**（性能更好）或 **PyInstaller**。

**使用 Nuitka 打包（推荐）：**

```shell
nuitka --standalone --onefile --windows-disable-console --plugin-enable=tk-inter --windows-icon-from-ico=app_icon.ico sm4_tool.py
```

------



<a id="english"></a>
## English Description

### Introduction

A modern GUI utility built with Python and Tkinter for file encryption and decryption using the **SM4 (GB/T 32907-2016)** Chinese national standard symmetric algorithm. It implements SM4 in ECB mode with a 128-bit key length, offering a clean, intuitive interface without external dependencies.

### Key Features

- **Native SM4 Implementation**: Pure Python implementation including S-box, linear transformations, and key expansion.
- **Modern UI**: Flat design with auto-closing notification components and High-DPI awareness for Windows.
- **Secure Random Key**: Integrated cryptographically strong random key generator using the secrets module.
- **In-Memory Processing**: Data is processed in memory first, ensuring integrity before writing to disk.
- **Distribution Ready**: Fully compatible with Nuitka and PyInstaller single-file packaging.

### Quick Start

1. **Prerequisites**: Python 3.6+

2. **Run**:

   ```
   python sm4_tool.py
   ```

3. **Usage**:

   - Select the target file.
   - Enter or generate a 32-character hex key.
   - Click "Execute" and then "Save Results" once finished.

### Building Executables

The code includes logic for resource path handling in compiled environments.

**Using PyInstaller:**

```shell
pyinstaller --noconfirm --onefile --windowed --icon "app_icon.ico" "sm4_tool.py"
```
<a id="download"></a>
## 🚀 下载地址 (Download)

| 平台 | 版本 | 下载链接 |
| :--- | :--- | :--- |
| Windows | v1.0.0 | [点击下载 Sm4 eencryption_tool.exe](https://github.com/CNCLAY/SM4-Encryption-Tool/releases/tag/v1.0.0) |

> **提示**：如果是直接下载运行，Windows 可能会弹出“已保护你的电脑”，请点击“更多信息” -> “仍要运行”。这是因为个人开发者生成的 EXE 没有经过昂贵的微软数字签名。
