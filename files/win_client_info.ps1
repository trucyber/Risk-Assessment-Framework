<# 
    .Synopsis
    Returns IPv4 address details for the local machine.
    Information is gathered from the active interface being used by the default route.
#>
[CmdletBinding()]
[OutputType([string])]
Param ()

Write-Verbose -Message ("Begin: " + $MyInvocation.MyCommand.Path)

<#
    .Synopsis
    This function uses regular expressions to return the first IPv4
    dotted decimal notation string in the list of strings passed.
#>
function Get-First
{
    [CmdletBinding()]
    [OutputType([string])]
    Param( $List )
    [Regex]$reg = "\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}"
    $result = ""
    foreach ($ip in $List)
    {
        $match = $reg.Match($ip)
        if ($match.Success)
        {
            $result = $match.Groups[0].Value
            break
        }
    }
    $result
}

Write-Verbose -Message "Getting the interface index being used by the default route."
$NICIndex = Get-CimInstance -ClassName Win32_IP4RouteTable |
    Where-Object { $_.Destination -eq "0.0.0.0"-and $_.Mask -eq "0.0.0.0" } |
    Sort-Object Metric1 |
    Select-Object -First 1 |
    Select-Object -ExpandProperty InterfaceIndex

Write-Verbose -Message "Getting the default route network adapter configuration."
$AdapterConfig = Get-CimInstance -ClassName Win32_NetworkAdapter |
    Where-Object { $_.InterfaceIndex -eq $NICIndex } |
    Get-CimAssociatedInstance -ResultClassName Win32_NetworkAdapterConfiguration

Write-Verbose -Message "Populating a custom PSObject with the desired details."
$ipconfig = [PSCustomObject]@{Description = $AdapterConfig.Description;
                              MACAddress = $AdapterConfig.MACAddress;
                              Address = (Get-First $AdapterConfig.IPAddress);
                              NetMask = (Get-First $AdapterConfig.IPSubnet);
                              Gateway = (Get-First $AdapterConfig.DefaultIPGateway);
                              DHCPServer = $AdapterConfig.DHCPServer;
                              DNSHostName = $AdapterConfig.DNSHostName;
                              DNSDomain = $AdapterConfig.DNSDomain;
                              DNSSearch = $AdapterConfig.DNSDomainSuffixSearchOrder}

# Return the result.
# $ipconfig
# Write-Verbose -Message ("End: " + $MyInvocation.MyCommand.Path)

# Get installed apps list
#Opt1: Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize
#Opt2: Get-WmiObject -Class Win32_Product
#Opt3: Get-WmiObject -Class Win32_Product | where vendor -eq CodeTwo | select Name, Version


# Write specific information to a file.
"HostName,"+$AdapterConfig.DNSHostName > win_node_config.txt
"HostIP,"+(Get-First $AdapterConfig.IPAddress) >> win_node_config.txt
"HostGateway,"+(Get-First $AdapterConfig.DefaultIPGateway) >> win_node_config.txt 
"HostOS,"+(Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ProductName')+" Build "+(Get-WmiObject Win32_OperatingSystem).BuildNumber >> win_node_config.txt

# Write installed application list to a file.
"Application list for "+ (Get-First $AdapterConfig.IPAddress) > win_apps_list.txt
Get-WmiObject -Class Win32_Product | select Name, Version >> win_apps_list.txt
