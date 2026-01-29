; Unified installer script for Skydimo / Apex Light / MageeLife / AARGB
; Build examples (PowerShell):
;   ISCC.exe .\Unified.iss /DPROD_SKYDIMO
;   ISCC.exe .\Unified.iss /DPROD_APEX
;   ISCC.exe .\Unified.iss /DPROD_MAGEELIFE
;   ISCC.exe .\Unified.iss /DPROD_AARGB

;------------------------------------------------------
; Product selection (exactly one must be defined)
;------------------------------------------------------
#if (defined(PROD_SKYDIMO) + defined(PROD_APEX) + defined(PROD_MAGEELIFE) + defined(PROD_AARGB)) != 1
  #error "Define exactly one product: /DPROD_SKYDIMO or /DPROD_APEX or /DPROD_MAGEELIFE or /DPROD_AARGB"
#endif

;------------------------------------------------------
; Per-product configuration
;------------------------------------------------------
#ifdef PROD_SKYDIMO
  #ifndef AppVersionFull
#define AppVersionFull "2.0.2.6e4c602"
  #endif
  #ifndef AppVersionFile
#define AppVersionFile "2.0.2.0"
  #endif
  #define MyAppName "Skydimo"
  #define MyAppPublisher "Shenzhen Guang yvzhou Technology Co., Ltd."
  #define MyAppURL "https://www.skydimo.com"
  #define MyAppExeName "Skydimo.exe"
  #define MyAppId "{{8D06DDFC-021C-4853-85AE-81798EF0AF0B}}"
  #define SetupOutputBase "SkydimoSetup_"
  #define SetupLicenseFile "..\License\Skydimo_EN.txt"
  #define SetupLicenseCNFile "..\License\Skydimo_CN.txt"
  #define Source_path "..\Skydimo"
#endif

#ifdef PROD_APEX
  #ifndef AppVersionFull
#define AppVersionFull "2.0.3.1366294"
  #endif
  #ifndef AppVersionFile
#define AppVersionFile "2.0.3.0"
  #endif
  #define MyAppName "Apex Light"
  #define MyAppPublisher "Shenzhen Guang yvzhou Technology Co., Ltd."
  #define MyAppURL " "
  #define MyAppExeName "Apex Light.exe"
  #define MyAppId "{{591829A4-48F0-4082-94B6-A5159B3EB49F}}"
  #define SetupOutputBase "APEXSetup_"
  #define SetupLicenseFile "..\License\license_EN.txt"
  #define SetupLicenseCNFile "..\License\license_CN.txt"
  #define Source_path "..\APEX"
#endif

#ifdef PROD_MAGEELIFE
  #ifndef AppVersionFull
#define AppVersionFull "2.0.2.97c8568"
  #endif
  #ifndef AppVersionFile
#define AppVersionFile "2.0.2.0"
  #endif
  #define MyAppName "MageeLife"
  #define MyAppPublisher "Shenzhen Guang yvzhou Technology Co., Ltd."
  #define MyAppURL "https://www.mageelife.com/"
  #define MyAppExeName "MageeLife.exe"
  #define MyAppId "{{591829A4-48F0-4082-94B6-A5159B3EB49F}}"
  #define SetupOutputBase "MageeLifeSetup_"
  #define SetupLicenseFile "..\License\license_EN.txt"
  #define SetupLicenseCNFile "..\License\license_CN.txt"
  #define Source_path "..\MageeLife"
#endif

#ifdef PROD_AARGB
  #ifndef AppVersionFull
#define AppVersionFull "2.0.2.3223981"
  #endif
  #ifndef AppVersionFile
#define AppVersionFile "2.0.2.0"
  #endif
  #define MyAppName "AARGB"
  #define MyAppPublisher "Shenzhen Guang yvzhou Technology Co., Ltd."
  #define MyAppURL " "
  #define MyAppExeName "AARGB.exe"
  #define MyAppId "{{591829A4-48F0-4082-94B6-A5159B3EB49F}}"
  #define SetupOutputBase "AARGBSetup_"
  #define SetupLicenseFile "..\License\license_EN.txt"
  #define SetupLicenseCNFile "..\License\license_CN.txt"
  #define Source_path "..\AARGB"
#endif

#define MyAppVersion AppVersionFull
#define MyProductVersion AppVersionFull
#define MyFileVersion AppVersionFile

;------------------------------------------------------
; Registry: autorun (common)
;------------------------------------------------------
[Registry]
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";  ValueName: {#MyAppName}; ValueType: none; Flags: deletevalue;
Root: HKCU; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";  ValueName: {#MyAppName}; ValueType: none; Flags: deletevalue;

Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: {#MyAppName}; \
    ValueData: """{app}\{#MyAppExeName}"" --auto_startup"; \
    Flags: uninsdeletevalue; Tasks: startup; Check: IsAdminInstall;

Root: HKCU; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: {#MyAppName}; \
    ValueData: """{app}\{#MyAppExeName}"" --auto_startup"; \
    Flags: uninsdeletevalue; Tasks: startup; Check: not IsAdminInstall;

;------------------------------------------------------
; Setup (common)
;------------------------------------------------------
[Setup]
AppId={#MyAppId}
AppMutex=skydimo2_Main,Global\skydimo2_Main

AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

DefaultDirName={autopf}\{#MyAppName}
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64
UninstallDisplayName={#MyAppName}
DisableProgramGroupPage=yes
ShowLanguageDialog=yes
LanguageDetectionMethod=uilanguage
UsePreviousLanguage=no

LicenseFile={#SetupLicenseFile}
PrivilegesRequiredOverridesAllowed=dialog

OutputDir=..\Setup_package
SetupLogging=yes
OutputBaseFilename={#SetupOutputBase}{#AppVersionFull}

Compression=lzma
SolidCompression=yes
WizardStyle=modern
UsePreviousAppDir=no

;------------------------------------------------------
; Languages (common list, per-product CN license)
;------------------------------------------------------
[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"; LicenseFile: "{#SetupLicenseCNFile}"
Name: "english"; MessagesFile: "compiler:Default.isl";
Name: "arabic"; MessagesFile: "compiler:Languages\Arabic.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "japanese"; MessagesFile: "compiler:Languages\Japanese.isl"
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"
Name: "portuguese"; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "vietnamese"; MessagesFile: "compiler:Languages\Vietnamese.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"

;------------------------------------------------------
; Tasks (common)
;------------------------------------------------------
[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}";
Name: "startup"; Description: "{cm:AutoStartProgram,{#MyAppName}}"; GroupDescription: "{cm:AdditionalIcons}";

;------------------------------------------------------
; Files (mostly common, conditional extras)
;------------------------------------------------------
[Files]
; VC++ 2015–2022 x64 runtime (temp for silent install)
Source: "{#Source_path}\VC\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

; Keep offline copy
#ifdef PROD_SKYDIMO
Source: "{#Source_path}\VC\vc_redist.x64.exe"; DestDir: "{app}\VC"; Flags: ignoreversion
#else
Source: "{#Source_path}\VC\vc_redist.x64.exe"; DestDir: "{app}\Redist\VC"; Flags: ignoreversion
Source: "{#Source_path}\VC\vc_redist.x64.exe"; DestDir: "{app}\VC"; Flags: ignoreversion
#endif

; CH340/CH341 driver (Skydimo only)
#ifdef PROD_SKYDIMO
Source: "{#Source_path}\CH340\CH341SER.EXE"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "{#Source_path}\CH340\CH341SER.EXE"; DestDir: "{app}\CH340"; Flags: ignoreversion
#endif

; Main program
Source: "{#Source_path}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion signonce;

; Other data files (exclude exe)
Source: "{#Source_path}\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs; \
    Excludes: "*.exe"

;------------------------------------------------------
; Shortcuts (common)
;------------------------------------------------------
[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon;

;------------------------------------------------------
; Deletes (common)
;------------------------------------------------------
[InstallDelete]
Type: filesandordirs; Name: "{app}"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

;------------------------------------------------------
; Code (common + Skydimo-only old uninstall + CH340 detection)
;------------------------------------------------------
[Code]
const
  VC_KEY    = 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64';
  MIN_MAJOR = 14;
  MIN_MINOR = 38;
  MIN_BLD   = 0;
  MIN_RBLD  = 0;

#ifdef PROD_SKYDIMO
const
  // Old x86 Skydimo used AppId {5918...}
  OLD_APPID_GUID = '{591829A4-48F0-4082-94B6-A5159B3EB49F}';
  OLD_UNINST_KEY = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + OLD_APPID_GUID + '_is1';
#endif

#ifdef PROD_SKYDIMO
procedure SplitCommandLine(const CmdLine: string; var Exe, Params: string);
var
  S: string;
  P: Integer;
begin
  S := Trim(CmdLine);
  Exe := '';
  Params := '';

  if S = '' then
    Exit;

  if S[1] = '"' then
  begin
    Delete(S, 1, 1);
    P := Pos('"', S);
    if P = 0 then
    begin
      Exe := S;
      Exit;
    end;
    Exe := Copy(S, 1, P - 1);
    Params := Trim(Copy(S, P + 1, MaxInt));
  end
  else
  begin
    P := Pos(' ', S);
    if P = 0 then
    begin
      Exe := S;
      Exit;
    end;
    Exe := Copy(S, 1, P - 1);
    Params := Trim(Copy(S, P + 1, MaxInt));
  end;
end;

function QueryOldUninstallCmd(const RootKey: Integer; var Exe, Params: string): Boolean;
var
  Cmd: string;
begin
  Result :=
    RegQueryStringValue(RootKey, OLD_UNINST_KEY, 'QuietUninstallString', Cmd) or
    RegQueryStringValue(RootKey, OLD_UNINST_KEY, 'UninstallString', Cmd);

  if Result then
  begin
    SplitCommandLine(Cmd, Exe, Params);
    Result := (Exe <> '');
  end;
end;

function RunOldUninstaller(const Exe, Params: string): Boolean;
var
  RC: Integer;
  P: string;
begin
  P := Trim(Params);
  if Pos('/VERYSILENT', Uppercase(P)) = 0 then
    P := Trim(P + ' /VERYSILENT /NORESTART');

  Result := Exec(Exe, P, '', SW_SHOW, ewWaitUntilTerminated, RC) and (RC = 0);
end;

function InitializeSetup(): Boolean;
var
  Exe, Params: string;
begin
  Result := True;

  if QueryOldUninstallCmd(HKLM32, Exe, Params) then
  begin
    if not IsAdmin then
    begin
      MsgBox(
        '检测到旧版（x86）Skydimo 已按“所有用户”安装。' + #13#10 +
        '请以管理员身份运行安装包以完成卸载后再安装。',
        mbError, MB_OK);
      Result := False;
      Exit;
    end;

    if MsgBox(
      '检测到旧版（x86）Skydimo。为避免同时存在两套程序，需要先卸载旧版。' + #13#10 +
      '是否现在卸载？',
      mbConfirmation, MB_YESNO) <> IDYES then
    begin
      Result := False;
      Exit;
    end;

    if not RunOldUninstaller(Exe, Params) then
    begin
      MsgBox(
        '旧版卸载失败。请先在“应用和功能/程序和功能”中手动卸载旧版后再运行安装包。',
        mbError, MB_OK);
      Result := False;
      Exit;
    end;

    DelTree(ExpandConstant('{pf32}\{#MyAppName}'), True, True, True);
  end
  else if QueryOldUninstallCmd(HKCU32, Exe, Params) then
  begin
    if MsgBox(
      '检测到旧版（x86）Skydimo（当前用户）。为避免冲突，需要先卸载旧版。' + #13#10 +
      '是否现在卸载？',
      mbConfirmation, MB_YESNO) <> IDYES then
    begin
      Result := False;
      Exit;
    end;

    if not RunOldUninstaller(Exe, Params) then
    begin
      MsgBox(
        '旧版卸载失败。请先手动卸载旧版后再运行安装包。',
        mbError, MB_OK);
      Result := False;
      Exit;
    end;

    DelTree(ExpandConstant('{pf32}\{#MyAppName}'), True, True, True);
  end;
end;
#endif

function IsVCRedistMissing(): Boolean;
var
  Installed, Major, Minor, Bld, RBld: Cardinal;
begin
  Result := True;

  if not RegQueryDWordValue(HKLM, VC_KEY, 'Installed', Installed) then
    Exit;
  if Installed <> 1 then
    Exit;

  if RegQueryDWordValue(HKLM, VC_KEY, 'Major', Major) and
     RegQueryDWordValue(HKLM, VC_KEY, 'Minor', Minor) and
     RegQueryDWordValue(HKLM, VC_KEY, 'Bld',   Bld) and
     RegQueryDWordValue(HKLM, VC_KEY, 'RBld',  RBld) then
  begin
    if (Major > MIN_MAJOR) or
       ((Major = MIN_MAJOR) and (Minor > MIN_MINOR)) or
       ((Major = MIN_MAJOR) and (Minor = MIN_MINOR) and (Bld > MIN_BLD)) or
       ((Major = MIN_MAJOR) and (Minor = MIN_MINOR) and (Bld = MIN_BLD) and (RBld >= MIN_RBLD)) then
      Result := False;
  end
  else
  begin
    Result := False;
  end;
end;

#ifdef PROD_SKYDIMO
function IsCH340Missing(): Boolean;
begin
  Result := True;

  if FileExists(ExpandConstant('{sys}\drivers\CH341S64.SYS')) then
  begin
    Result := False;
    Exit;
  end;

  if FileExists(ExpandConstant('{sys}\drivers\usbser.sys')) then
  begin
    Result := False;
    Exit;
  end;

  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\CH341SER') then
  begin
    Result := False;
    Exit;
  end;

  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\wchusbser') then
  begin
    Result := False;
    Exit;
  end;

  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\usbser') then
  begin
    Result := False;
    Exit;
  end;
end;
#endif

procedure CurStepChanged(CurStep: TSetupStep);
var
  logfilepathname, logfilename, newfilepathname: string;
begin
  logfilepathname := ExpandConstant('{log}');
  logfilename := ExtractFileName(logfilepathname);
  newfilepathname := ExpandConstant('{app}\') + logfilename;

  if CurStep = ssDone then
    FileCopy(logfilepathname, newfilepathname, False);
end;

function IsAdminInstall(): Boolean;
begin
  Result := (IsAdmin and (GetShellFolderByCSIDL($30, True) = ExpandConstant('{commonappdata}')));
end;

// ------------------------------------------------------
// Run (common + conditional)
// ------------------------------------------------------
[Run]
Filename: "{tmp}\vc_redist.x64.exe"; \
    Parameters: "/install /quiet /norestart"; \
    Flags: runhidden waituntilterminated; \
    StatusMsg: "Installing Microsoft VC++ Runtime..."; \
    Check: IsVCRedistMissing()

#ifdef PROD_SKYDIMO
Filename: "{tmp}\CH341SER.EXE"; \
    Parameters: "/SILENT /NORESTART"; \
    Flags: runhidden waituntilterminated; \
    StatusMsg: "Installing CH340/CH341 USB-Serial driver..."; \
    Check: IsCH340Missing() and IsAdmin
#endif

Filename: "{app}\{#MyAppExeName}"; \
    Description: "{cm:LaunchProgram,{#MyAppName}}"; \
    WorkingDir: "{app}"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser

