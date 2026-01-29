## 可视化启动器（ALL_EXE Launcher）

本目录用于**新增**一个"可视化启动器"，把仓库根目录中的：
- `SignBat_All_EXE.py`（签名/更新版本/编译安装包/可选上传 360）
- `remote_sign_client.py`（远程签名）
- `360_auto_upload.py`（360 开放平台自动登录+提交）
- `updata_app.py`（上传到 FTP/SFTP/Cloudflare R2）
- `Unified.iss`（Inno Setup 脚本）

串成一个 GUI 工具，并最终用 PyInstaller 打包成 EXE。

> 约束：只在 `可视化/` 目录新增文件，不修改仓库现有脚本。

### 使用方式（开发态）

在仓库根目录（`ALL_EXE`）执行：

```powershell
python -m pip install --upgrade pip
python -m pip install -r .\可视化\requirements.txt
python .\可视化\launcher_gui.py
```

### 打包成 EXE

在仓库根目录执行：

```powershell
pwsh -ExecutionPolicy Bypass -File .\可视化\build\build.ps1
```

输出默认在：
- `可视化\dist\ALL_EXE_Launcher.exe`

### 运行要求（重要）

该 EXE **默认会自动定位**本仓库根目录（向上查找 `SignBat_All_EXE.py` 与 `Unified.iss`），并执行磁盘上的原脚本。

因此请把 `ALL_EXE_Launcher.exe` 放在以下任意位置运行：
- 仓库根目录 `ALL_EXE\` 下
- 或其子目录（例如 `ALL_EXE\可视化\dist\`）

如果你把 EXE 拿到别的机器/目录运行，但旁边没有这些脚本文件，会提示你手动选择"仓库根目录"。

### 新增功能：上传到服务器

现在支持在编译安装包后自动上传到配置的服务器（FTP/SFTP/Cloudflare R2）。

#### 使用方式

1. **配置上传服务器**：编辑 `config.json`，配置你的服务器信息（见下文示例）
2. **在 GUI 中勾选**："上传到服务器（FTP/SFTP/Cloudflare R2，默认关）"
3. **指定配置文件路径**：默认为 `config.json`，可以浏览选择其他路径
4. **执行流水线**：
   - 签名产品 EXE
   - 更新版本号
   - 编译安装包
   - 签名安装包
   - （可选）上传到 360
   - **（可选）上传到配置的服务器**

#### config.json 配置示例

```json
{
  "software": {
    "local_exe_path": "",
    "upload_name_template": "{version}"
  },
  "cloudflare": {
    "account_id": "your_account_id",
    "access_key_id": "your_access_key",
    "secret_access_key": "your_secret_key",
    "bucket_name": "app-release",
    "remote_dir": "skydimo-setup"
  },
  "servers": [
    {
      "name": "langlangyun",
      "type": "sftp",
      "host": "114.66.28.100",
      "port": 22,
      "username": "root",
      "password": "your_password",
      "remote_dir": "/var/www/files/skydimo-setup/"
    },
    {
      "name": "bt",
      "type": "sftp",
      "host": "47.104.194.96",
      "port": 22,
      "username": "root",
      "password": "your_password",
      "remote_dir": "/www/wwwroot/cn3-dl.skydimo.com/skydimo-setup/"
    }
  ]
}
```

**注意**：
- `local_exe_path` 留空，启动器会自动填入编译后的安装包路径
- `upload_name_template` 可以使用 `{version}` 占位符，会被替换为实际版本号
- 支持多个服务器同时上传（FTP、SFTP、Cloudflare R2）

#### 执行顺序

勾选上传选项后，完整流程为：

1. 签名产品 EXE → 更新版本 → 编译安装包 → 签名安装包
2. （如勾选）上传到 360
3. （如勾选）上传到服务器（FTP/SFTP/Cloudflare R2）

默认情况下，"上传到服务器"选项是**关闭**的，避免意外上传。

