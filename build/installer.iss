; Inno Setup script for WebForensics
; Run with: iscc.exe build\installer.iss

#define MyAppName       "WebForensics"
#define MyAppVersion    "1.0.0"
#define MyAppPublisher  "WixaDevelop"
#define MyAppURL        "https://github.com/WixaDevelop/WebForensics"
#define MyAppExeName    "WebForensics.exe"

[Setup]
AppId={{C9F0B5E0-5C5C-4F5A-9A1B-WEBFORENSICS01}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=WebForensics-{#MyAppVersion}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\{#MyAppExeName}
LicenseFile=..\LICENSE
; SetupIconFile=icon.ico   ; uncomment once you drop a build/icon.ico in here

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; PyInstaller emits everything into dist\WebForensics\.
Source: "..\dist\WebForensics\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}";       Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
