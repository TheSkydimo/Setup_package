# ALL_EXE Installer Builder（Unified Inno Setup）

这个目录用于**为多个产品生成 Inno Setup 安装包**，并且在编译前会**自动从产品 EXE 读取版本信息**，写回 `Unified.iss` 中对应产品的版本宏，然后调用 `ISCC.exe` 输出安装包。

## 支持的产品

脚本内置映射（见 `SignBat_All_EXE.py` 的 `PRODUCTS`）：

- **SKYDIMO**：`..\Skydimo\Skydimo.exe`
- **APEX**：`..\APEX\Apex Light.exe`
- **MAGEELIFE**：`..\MageeLife\MageeLife.exe`
- **AARGB**：`..\AARGB\AARGB.exe`

如果你的 EXE 路径不同，可以用 `--exe` 覆盖（见下文）。

## 依赖与前置条件

### 运行环境

- **Windows**
- **Python（带 pip）**
- **Inno Setup（含编译器 `ISCC.exe`）**

### Python 依赖

脚本会用到：

- `pefile`：读取 PE 信息（回退逻辑）
- `pywin32`：通过 `win32api.GetFileVersionInfo` 读取版本信息
- `requests`：调用远程签名服务（sign server）

安装：

```powershell
python -m pip install --upgrade pip
python -m pip install pefile pywin32 requests
```

备注：pywin32 新版本将 postinstall 脚本作为 console script 提供；如果你遇到 COM/注册相关问题，可尝试运行 `pywin32_postinstall`（一般仅在特定环境需要）。

### Inno Setup（ISCC.exe）定位方式

脚本会按以下优先级寻找 `ISCC.exe`：

- **命令行参数**：`--iscc "C:\...\ISCC.exe"`
- **环境变量**：`ISCC_EXE`
- **PATH**：`ISCC` / `ISCC.exe`
- **常见安装路径**：
  - `C:\Program Files (x86)\Inno Setup 6\ISCC.exe`
  - `C:\Program Files\Inno Setup 6\ISCC.exe`
  - `C:\Program Files (x86)\Inno Setup 5\ISCC.exe`
  - `C:\Program Files\Inno Setup 5\ISCC.exe`

## 快速开始

在当前目录（`ALL_EXE`）运行：

```powershell
python .\SignBat_All_EXE.py --product SKYDIMO
python .\SignBat_All_EXE.py --product AARGB
python .\SignBat_All_EXE.py --product MAGEELIFE
python .\SignBat_All_EXE.py --product APEX
```

## 发生了什么（工作流程）

执行 `SignBat_All_EXE.py` 时：

1. **（可选）先签名产品 EXE（就地覆盖回原目录）**
2. **读取目标 EXE 的版本信息**
   - 优先读取数值型 **FileVersion**
   - 优先读取字符串型 **ProductVersion**（如果存在，作为 `AppVersionFull`，可带后缀）
3. **只更新 `Unified.iss` 中对应产品块**
   - 仅更新 `#ifdef PROD_<PRODUCT>` 这一段里的：
     - `#define AppVersionFull "..."`
     - `#define AppVersionFile "..."`
   - 不会误改其他产品的版本号
4. **调用 Inno Setup 编译**
   - 编译命令等价于：
     - `ISCC.exe .\Unified.iss /DPROD_<PRODUCT>`
5. **（可选）签名生成的安装包 EXE（就地覆盖，位于 OutputDir）**

## 输出位置与文件名

由 `Unified.iss` 控制输出：

- **输出目录**：`OutputDir=..\Setup_package`
- **输出文件名**：`OutputBaseFilename={#SetupOutputBase}{#AppVersionFull}`

也就是说最终安装包会输出到 `..\Setup_package\`，文件名类似：

- `SkydimoSetup_<AppVersionFull>.exe`
- `APEXSetup_<AppVersionFull>.exe`
- `MageeLifeSetup_<AppVersionFull>.exe`
- `AARGBSetup_<AppVersionFull>.exe`

## 命令行参数（SignBat_All_EXE.py）

- **`--product`（必选）**：`SKYDIMO | AARGB | MAGEELIFE | APEX`
- **`--iss`**：指定 `Unified.iss` 路径  
  - 默认：`<项目根>\ALL_EXE\Unified.iss`
- **`--exe`**：覆盖脚本内置的 EXE 路径（当你的目录结构不同/EXE 改名时使用）
- **`--no-compile`**：只更新 `.iss`，不调用 `ISCC.exe` 编译
- **`--iscc`**：指定 `ISCC.exe` 的完整路径（也可用环境变量 `ISCC_EXE`）
- **`--sign-server`**：远程签名服务地址（或环境变量 `SIGN_SERVER`）
- **`--sign-api-key`**：可选 API Key（header: `x-api-key`，或环境变量 `SIGN_API_KEY`）
- **`--sign-user`**：可选用户（header: `x-user`，或环境变量 `SIGN_USER`）
- **`--sign-password`**：可选密码（HTTP Basic Auth，或环境变量 `SIGN_PASSWORD`）
- **`--no-sign-exe`**：不签名产品 EXE
- **`--no-sign-installer`**：不签名生成的安装包 EXE

## 常用命令（只签/只打包）

### 只签产品 EXE（不编译安装包）

> 这会先签名 EXE（就地覆盖），然后更新 `Unified.iss` 版本宏，但不调用 ISCC 编译。

```powershell
python .\SignBat_All_EXE.py --product SKYDIMO --no-compile
```

### 只签安装包（会先编译生成安装包，但不签产品 EXE）

```powershell
python .\SignBat_All_EXE.py --product SKYDIMO --no-sign-exe
```

### 只签安装包（不重新编译）

直接对安装包文件签名（就地覆盖输出文件）：

```powershell
python .\remote_sign_client.py sign ..\Setup_package\SkydimoSetup_2.0.2.6e4c602.exe --sync --out ..\Setup_package\SkydimoSetup_2.0.2.6e4c602.exe
```

（把文件名替换成你实际生成的版本号即可。）

## 一步到底：签名 + 打包 + 签名安装包 + 自动上传 360 检测（默认开启）

```powershell
python .\SignBat_All_EXE.py --product SKYDIMO
```

如果你希望在同一条命令里直接写入 360 账号密码（内部使用）：

```powershell
python .\SignBat_All_EXE.py --product SKYDIMO --q360-account "13570806357" --q360-password "你的密码"
```

如果你希望 360 上传时用无头浏览器：

```powershell
python .\SignBat_All_EXE.py --product SKYDIMO --upload-360-headless
```

如果你这次不想上传 360：

```powershell
python .\SignBat_All_EXE.py --product SKYDIMO --no-upload-360
```

> 说明：
> - 360 上传脚本为 `360_auto_upload.py`，它需要 selenium 相关依赖；只有在“未使用 `--no-upload-360`”时才会执行到上传步骤。
> - 安装包路径会由 `SignBat_All_EXE.py` 在编译完成后自动计算并传给 `360_auto_upload.py`。

示例：只更新版本，不编译：

```powershell
python .\SignBat_All_EXE.py --product SKYDIMO --no-compile
```

示例：自定义 EXE 路径 + 指定 ISCC：

```powershell
python .\SignBat_All_EXE.py --product APEX --exe "D:\build\Apex Light.exe" --iscc "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
```

## 直接用 ISCC 编译（不走 Python）

`Unified.iss` 也支持直接编译（你需要自己维护版本宏）：

```powershell
ISCC.exe .\Unified.iss /DPROD_SKYDIMO
ISCC.exe .\Unified.iss /DPROD_APEX
ISCC.exe .\Unified.iss /DPROD_MAGEELIFE
ISCC.exe .\Unified.iss /DPROD_AARGB
```

## 常见报错

- **`ModuleNotFoundError: No module named 'win32api'`**
  - 安装 pywin32：
    - `python -m pip install pywin32`
- **`ModuleNotFoundError: No module named 'pefile'`**
  - 安装 pefile：
    - `python -m pip install pefile`
- **`Error: ISCC.exe not found`**
  - 安装 Inno Setup，或通过 `--iscc` / `ISCC_EXE` 指定路径
- **`Error: EXE not found`**
  - 检查脚本内 `PRODUCTS` 的默认路径是否与你本地一致，或使用 `--exe` 指定实际路径

