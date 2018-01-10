function Get-tjVmRdpConfig {
[CmdletBinding()]Param(
[Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][string]$VmName
)
$VmGuid = Get-VM -Name $VmName | % VMId | % Guid 
$VmRdpConfig = "$HOME\AppData\Roaming\Microsoft\Windows\Hyper-V\Client\1.0\vmconnect.rdp.$VmGuid.config"
if (Test-Path $VmRdpConfig)
   {Write-Output $VmRdpConfig} else {Write-Warning "$VmName : No RDP config found."}
}

function Set-tjVhdPermission {
[CmdletBinding()]Param(
[Parameter(Mandatory=$true,Position=1)][string]$VmName
)
$VhdPath = Get-VM -Name $VmName | % HardDrives | % Path
$VhdPath2 = '"' + $VhdPath + '"'

$VmGuid = Get-VM -Name $VmName | % VMId | % Guid 
$VmPrincipal = "NT VIRTUAL MACHINE\$VmGuid"
$VmPrincipal2 = '"' + $VmPrincipal + '"' + ':(F)'

# icacls "E:\VMs\VMName\Disk0.vhd" /grant "NT VIRTUAL MACHINE\5FC5C385-BD98-451F-B3F3-1E50E06EE663":(F)
cmd /c "icacls $VhdPath2 /grant $VmPrincipal2"
}

function Get-tjDockerEngine {
   docker version
}
function Get-tjDockerForWindows {
  $command = @'
  cmd.exe /C "c:\Program Files\Docker\Docker\DockerCli.exe" -Version
'@
  
  Invoke-Expression -Command:$command
}
function Switch-tjDockerEngine {
  $command = @'
  cmd.exe /C "c:\Program Files\Docker\Docker\DockerCli.exe" -SwitchDaemon
'@
  
  Invoke-Expression -Command:$command
}

function Add-tjDockerWindowsBaseImageTag {
<#
.Synopsis
   Adds the OS version as tag to a Windows base image

.DESCRIPTION
   This function adds a tag to a Windows base image pulled from the Docker hub.
   The tag is the OS version of the Windows base image found by 'docker inspect'.

   Due to Windows updates there are many 'latest' base images. Tagging makes it easy
   to differ these versions. (What is the real 'latest'?)

   docker image list
     
                          before tagging

   REPOSITORY                    TAG               IMAGE ID         CREATED          SIZE
   microsoft/windowsservercore   latest            2cddde20d95d     2 weeks ago      10.3GB
   microsoft/windowsservercore   latest            590c0c2590e4     5 months ago     10.1GB


                           after tagging
     
   REPOSITORY                    TAG               IMAGE ID         CREATED          SIZE
   microsoft/windowsservercore   10.0.14393.1715   2cddde20d95d     2 weeks ago      10.3GB
   microsoft/windowsservercore   latest            2cddde20d95d     2 weeks ago      10.3GB
   microsoft/windowsservercore   10.0.14393.1066   590c0c2590e4     5 months ago     10.1GB


.PARAMETER BaseImage
   Specifies the Windows baseimage name (a.k.a. repository)

.PARAMETER Tag
   Specifies the tag already set to the Windows base image. Default is 'latest'.

.EXAMPLE
   Set-tjDockerBaseImageTag -BaseImage microsoft/windowsservercore
#>

[CmdletBinding()]Param(
[Parameter(Mandatory=$true,Position=1)][string]$BaseImage,
[Parameter(Mandatory=$false,Position=2)][string]$Tag = "latest"
)

$SourceImage = $BaseImage + ':' + $Tag

$OsVersion = docker inspect --format='{{.OsVersion}}' $SourceImage

$TargetImage = $BaseImage + ':' + $OsVersion

docker tag $SourceImage $TargetImage

}

function Get-WindowsVersion {  
<#    
.SYNOPSIS    
    List Windows Version from computer.  
    
.DESCRIPTION  
    List Windows Version from computer. 
     
.PARAMETER ComputerName 
    Name of server to list Windows Version from remote computer.

.PARAMETER SearchBase 
    AD-SearchBase of server to list Windows Version from remote computer.
                         
.NOTES    
    Name: Get-WindowsVersion.psm1 
    Author: Johannes Sebald
    Version: 1.2.1
    DateCreated: 2016-09-13
    DateEdit: 2016-09-14
            
.LINK    
    http://www.dertechblog.de

.EXAMPLE    
    Get-WindowsVersion
    List Windows Version on local computer.
.EXAMPLE    
    Get-WindowsVersion -ComputerName pc1
    List Windows Version on remote computer.   
.EXAMPLE    
    Get-WindowsVersion -ComputerName pc1,pc2
    List Windows Version on multiple remote computer.  
.EXAMPLE    
    Get-WindowsVersion -SearchBase "OU=Computers,DC=comodo,DC=com"
    List Windows Version on Active Directory SearchBase computer. 
.EXAMPLE    
    Get-WindowsVersion -ComputerName pc1,pc2 -Force
    List Windows Version on multiple remote computer and disable the built-in Format-Table and Sort-Object by ComputerName.                         
#>  
    [cmdletbinding()]
    param (
    [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [string[]]$ComputerName = "localhost",
    [string]$SearchBase,
    [switch]$Force
    )

    if($SearchBase)
    {
        if(Get-Command Get-AD* -ErrorAction SilentlyContinue)
            {
                if(Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$SearchBase'" -ErrorAction SilentlyContinue)
                    {
                        $Table = Get-ADComputer -SearchBase $SearchBase -Filter *
                        $ComputerName = $Table.Name
                    }
                else{Write-Warning "No SearchBase found"}
            }
        else{Write-Warning "No Active Directory cmdlets found"}
    }

    # Parameter Force
    if(-not($Force)){$tmp = New-TemporaryFile}

    foreach ($Computer in $ComputerName) 
        {
            if(Test-Connection -ComputerName $Computer -Count 1 -ea 0)
                { 
                    if(Get-Item -Path "\\$Computer\c$" -ErrorAction SilentlyContinue)
                        {                    
                            # Variables
                            $WMI = [WmiClass]"\\$Computer\root\default:stdRegProv"
                            $HKLM = 2147483650
                            $Key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"

                            $ValueName = "CurrentMajorVersionNumber"
                            $Major = $WMI.GetDWordValue($HKLM,$Key,$ValueName).UValue

                            $ValueName = "CurrentMinorVersionNumber"
                            $Minor = $WMI.GetDWordValue($HKLM,$Key,$ValueName).UValue

                            $ValueName = "CurrentBuildNumber"
                            $Build = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue

                            $ValueName = "UBR"
                            $UBR = $WMI.GetDWordValue($HKLM,$Key,$ValueName).UValue

                            $ValueName = "ReleaseId"
                            $ReleaseId = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue

                            $ValueName = "ProductName"
                            $ProductName = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue

                            $ValueName = "ProductId"
                            $ProductId = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue

                            # Variables for Windows 6.x
                            if($Major.Length -le 0)
                                {
                                    $ValueName = "CurrentVersion"
                                    $Major = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue 
                                }
                            
                            if($ReleaseId.Length -le 0)
                                {
                                    $ValueName = "CSDVersion"
                                    $ReleaseId = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue 
                                }

                            # Add Points
                            if(-not($Major.Length -le 0)){$Major = "$Major."}
                            if(-not($Minor.Length -le 0)){$Minor = "$Minor."}
                            if(-not($UBR.Length -le 0)){$UBR = ".$UBR"}

                            # Table Output
                            $OutputObj = New-Object -TypeName PSobject
                            $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.toUpper()
                            $OutputObj | Add-Member -MemberType NoteProperty -Name ProductName -Value $ProductName
                            $OutputObj | Add-Member -MemberType NoteProperty -Name WindowsVersion -Value $ReleaseId
                            $OutputObj | Add-Member -MemberType NoteProperty -Name WindowsBuild -Value "$Major$Minor$Build$UBR"
                            $OutputObj | Add-Member -MemberType NoteProperty -Name ProductId -Value $ProductId
                            
                            # Parameter Force
                            if(-not($Force)){$OutputObj | Export-Csv -Path $tmp -Append}else{$OutputObj}
                        }
                    else
                        {            
                            Write-Warning "$Computer no access"       
                        } 
                }
            else
                {            
                    Write-Warning "$Computer not reachable"       
                } 
        }

        # Parameter Force
        if(-not($Force))
            {                            
                Import-Csv -Path $tmp | Sort-Object -Property ComputerName | Format-Table -AutoSize
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            }
    }
function Get-tjIpAddress {
  $IfIndex = @()

  # Adding loopback adapter
  $IfIndex += 1

  # Adding adapter having both: status "up" and TCP/IPv4 bound
  Get-NetAdapter | ? Status -EQ "Up" | 
    ForEach-Object { if ( Get-NetAdapterBinding -Name $_.Name -DisplayName "Internet Protocol Version 4 (TCP/IPv4)" | % Enabled ) 
                        {$IfIndex += $_.ifIndex} 
    } 

  # Formating
  $IfIndex | Sort-Object | ForEach-Object { Get-NetIPAddress -ifIndex $_ -AddressFamily IPv4 } | 
      Format-Table @{l="Index";e={$_.ifIndex}}, `
                   @{l="Name";e={$_.InterfaceAlias}}, `
                   @{l="Address";e={$_.IPAddress}}, `
                   @{l="Mask"; e={$_.PrefixLength}}, `
                   @{l="Origin";  e={$_.PrefixOrigin};a="left"}
}
function Get-tjIsAdmin {

# http://www.interact-sw.co.uk/iangblog/2007/02/09/pshdetectelevation

  $wid=[System.Security.Principal.WindowsIdentity]::GetCurrent()
  $prp=new-object System.Security.Principal.WindowsPrincipal($wid)
  $adm=[System.Security.Principal.WindowsBuiltInRole]::Administrator
  $IsAdmin=$prp.IsInRole($adm)
  if ($IsAdmin) { $true } else { $false }
}

function PublishToMyGet-Module {
  [CmdletBinding()]Param(
  [Parameter(Mandatory=$true,Position=1)][string]$ModuleName
  )

  Get-PSRepository | ft Name,SourceLocation,PublishLocation
  
  $PathDefault = "C:\Git\$ModuleName"
  [string]$PathToModule = Read-Host -Prompt "Path to module  [$PathDefault]"
  if ([string]::IsNullOrEmpty($PathToModule)) {$PathToModule = $PathDefault}

  $RepoDefault = "MyGet"
  [string]$Repo = Read-Host -Prompt "Repo  [$RepoDefault]"
  if ([string]::IsNullOrEmpty($Repo)) {$Repo = $RepoDefault}

  $NuGetApiKey = Read-Host -Prompt "NuGetApiKey" 

  $PathTemp = "$PathToModule\temp\$ModuleName"
  mkdir $PathTemp | Out-Null
  copy "$PathToModule\$ModuleName.psm1" $PathTemp
  copy "$PathToModule\$ModuleName.psd1" $PathTemp
 
  Publish-Module -Path $PathTemp -Repository $Repo -NuGetApiKey $NuGetApiKey

  Remove-Item -Path "$PathToModule\temp" -Recurse -Force
}

function Remove-tjDashesInMac {
  param ($MacWithDashes)

  $mac1 = $MacWithDashes.Split("-")[0]
  $mac2 = $MacWithDashes.Split("-")[1]
  $mac3 = $MacWithDashes.Split("-")[2]
  $mac4 = $MacWithDashes.Split("-")[3]
  $mac5 = $MacWithDashes.Split("-")[4]
  $mac6 = $MacWithDashes.Split("-")[5]
  $mac = $mac1 + $mac2 +$mac3 + $mac4 +$mac5 +$mac6
  $mac
}
function Show-tjVmSwitch {
  <#
   Problem: "VMNetworkAdapter" hat keine Property "IpAddress", aber eine Property "MacAddress"
   Lösung: Suche zu dem VMNetworkAdapter den NetAdapter mit der gleichen MAC Adresse.
  
                      IP     MAC
    ----------------------------
    VMNetworkAdapter  nein   ja
    NetAdapter        ja     ja
  #>

  $VMSwitches = Get-VMSwitch
  $NetAdapters = Get-NetAdapter | where Virtual -EQ $true

  foreach ($Switch in $VMSwitches) {
      $VMNetworkAdapter = Get-VMNetworkAdapter -ManagementOS | where SwitchName -eq $Switch.Name
      $VMNA_Mac = $VMNetworkAdapter.MacAddress

      Clear-Variable NetAdapter
      foreach ($NA in $NetAdapters) {
        $NA_Mac = Remove-tjDashesInMac $NA.MacAddress
        if ($NA_Mac -eq $VMNA_Mac) {$NetAdapter=$NA}
      }

      $NetIPAddress = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $NetAdapter.InterfaceIndex

      $Switch | 
        select @{n="VMSwitch";e={$_.Name}},`
               @{n="VMNetworkAdapter";e={$VMNetworkAdapter.Name}},`
               @{n="NetAdapter";e={$NetAdapter.Name}},`
               @{n="IPAddress";e={$NetIPAddress.IPAddress}},`
               @{n="PrefixLength";e={$NetIPAddress.PrefixLength}},`
               @{n="PrefixOrigin";e={$NetIPAddress.PrefixOrigin}}
  }
}
