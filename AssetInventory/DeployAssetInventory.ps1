Param (
    [Parameter(Position=0,Mandatory=$true)]
    [string]$BucketName,
    [Parameter(Position=1)]
    [string]$AccessKey,
    [Parameter(Position=2)]
    [string]$SecretKey
)

$Module = Get-Module -ListAvailable | Where-Object {$_.Name -eq "AssetInventory"}

if ($Module -eq $null)
{
    Install-Module AssetInventory -Force -Confirm:$false
}
else
{
    Update-Module AssetInventory -Force -Confirm:$false
}

$BucketName = $BucketName.ToLower()

$Content = @"
`$File = `$env:COMPUTERNAME + "_Inventory_" + (Get-Date -Format yyyyMMdd-hhmmss).ToString() + ".json"
`$Path = `$env:ALLUSERSPROFILE + "\AssetInventory\" + `$File
`$S3key = `$env:COMPUTERNAME + "\" + `$File

Import-Module AssetInventory
Get-AssetInventory -AsJson | Out-File -FilePath `$Path -Force
try
{
    Write-S3Object -BucketName $BucketName -Key `$S3key -File `$Path -SecretKey $SecretKey -AccessKey $AccessKey
}
catch [Exception] {

}
finally {
	Remove-Item -Path `$Path
}
"@

$Folder = $env:ALLUSERSPROFILE + "\\AssetInventory"
$ScriptPath = $Folder + "\\RunAndUpload.ps1"

New-Item -Path $Folder -ItemType Directory -Force | Out-Null
Set-Content -Path $ScriptPath -Value $Content -Force

$Argument = @"
-NoProfile -WindowStyle Hidden -File $ScriptPath
"@

$STAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $Argument
$STTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 10pm
$STPrincipal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$STSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -RestartCount 3 -DontStopIfGoingOnBatteries -StartWhenAvailable -WakeToRun -MultipleInstances IgnoreNew
$ST = New-ScheduledTask -Action $STAction -Trigger $STTrigger -Principal $STPrincipal -Description "Collects asset inventory and uploads to S3" -Settings $STSettings

try 
{
    $OldTask = Get-ScheduledTask -TaskName "Asset Inventory"
    if ($OldTask -ne $null)
    {
        Set-ScheduledTask -TaskName "Asset Inventory" -Principal $STPrincipal -Trigger $STTrigger -Action $STAction -Settings $STSettings
    }
    else
    {
        Register-ScheduledTask -InputObject $ST -TaskName "Asset Inventory"
    }
}
catch [Exception] 
{
    Register-ScheduledTask -InputObject $ST -TaskName "Asset Inventory"
}