$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Version = "0.36.0"
$MontoyaVersion = "2026.7"
$Deps = Join-Path $Here ".deps"
$Classes = Join-Path $Here "build\classes\java\main"
$Libs = Join-Path $Here "build\libs"
$MontoyaJar = Join-Path $Deps "montoya-api-$MontoyaVersion.jar"
New-Item -ItemType Directory -Force -Path $Deps,$Classes,$Libs | Out-Null
if (-not (Get-Command javac -ErrorAction SilentlyContinue)) { throw "Se requiere JDK 21 o superior." }
if (-not (Test-Path $MontoyaJar)) {
  $Url = "https://repo.maven.apache.org/maven2/net/portswigger/burp/extensions/montoya-api/$MontoyaVersion/montoya-api-$MontoyaVersion.jar"
  Write-Host "[INFO] Descargando Montoya API $MontoyaVersion..."
  Invoke-WebRequest -Uri $Url -OutFile $MontoyaJar
}
Remove-Item -Recurse -Force $Classes -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Classes,$Libs | Out-Null
$Sources = Get-ChildItem -Recurse (Join-Path $Here "src\main\java") -Filter *.java | ForEach-Object { $_.FullName }
& javac --release 21 -encoding UTF-8 -cp $MontoyaJar -d $Classes @Sources
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$Manifest = Join-Path $Here "build\manifest.mf"
"Manifest-Version: 1.0`nImplementation-Title: Negro Burp Bridge`nImplementation-Version: $Version`n" | Set-Content -Encoding ascii $Manifest
$Out = Join-Path $Libs "negro-burp-bridge-$Version.jar"
& jar --create --file $Out --manifest $Manifest -C $Classes .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "[OK] Extensión compilada: $Out"
