@{
RootModule = './tjTools.psm1'
ModuleVersion = '0.1.7'
GUID = '94a93801-0736-42a9-ac75-ee85d694a36f'
Author = 'Thomas Jaekel'
Copyright = '(c) 2016 Thomas Jaekel. All rights reserved.'
Description = 'Userful tools.'
FunctionsToExport = @('Remove-tjDashesInMac',
                      'Show-tjVmSwitch',
                      'PublishToMyGet-Module',
                      'Get-tjVmRdpConfig',
                      'Set-tjVhdPermission',
                      'Get-tjDockerEngine',
                      'Get-tjDockerForWindows',
                      'Switch-tjDockerEngine',
                      'Add-tjDockerWindowsBaseImageTag',
                      'Get-WindowsVersion',
                      'Get-tjIpAddress',
                      'Get-tjIsAdmin')

CmdletsToExport = @()
VariablesToExport = '*'
AliasesToExport = @()
# DscResourcesToExport = @()

# HelpInfo-URI dieses Moduls
# HelpInfoURI = ''

# Standardpräfix für Befehle, die aus diesem Modul exportiert werden. Das Standardpräfix kann mit "Import-Module -Prefix" überschrieben werden.
# DefaultCommandPrefix = ''

}