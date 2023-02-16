#Requires -Version 3.0
[CmdletBinding()] 
    Param (
    [switch]$serverinfo,
    [switch]$driveinformation,
    [switch]$getuptime,
    [switch]$pendingreboot,
    [switch]$rebootdetails,
    [switch]$avcheck,
    [switch]$installedsoftware,
    [switch]$patchcheck,
    [switch]$checkupdates,
    [switch]$installupdates,
    [switch]$protocolcheck,
    [switch]$ciphercheck,
    [switch]$showarmorservices,
    [switch]$checkports
    )

Begin {
    Function Get-Serverinfo
        {
        
        <#.Example: PS C:\Test Script> .\wininfo-v4.ps1 -serverinfo
        This section will display the general server information (ie. Hostname, drive Information, CPU, Memory, etc.)
        #>
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Server Information"
        $host.ui.RawUI.ForegroundColor = "White"
        Function get-driveinfo {
        $c=$env:COMPUTERNAME
        $disks= gwmi win32_diskdrive -Comp $c|select __path,@{n="SCSI_Id";e={[string]$([int]$_.scsiport)+":"+$_.scsitargetid}},serialnumber,Type
        function match($p,$l,$c){$l2p=gwmi win32_logicaldisktopartition -comp $c|?{$_.dependent -eq $l.__PATH}
        $d2p=gwmi win32_diskdrivetodiskpartition -comp $c|?{$_.dependent -eq $l2p.antecedent}
        $tmp=Get-WmiObject Win32_DiskPartition -comp $c|?{$_.__PATH -eq $l2p.Antecedent}
        $t=switch -Regex ($tmp.type){'^GPT'{'GPT'};'^Ins'{'MBR'}
        default{'unavailable'}}$p=$p|?{$_.__path -eq $d2p.antecedent};$p.Type=$t;$p}

        $return = gwmi win32_logicaldisk -comp $c |?{$_.drivetype -eq '3'}|%{$d = match $disks $_ $c
        New-Object psobject -Property @{Computer=$c;Drive=$_.deviceid;Name=$_.volumename;SCSIID=$d.SCSI_Id;SizeGB=[Math]::Round($_.size/1GB)
        FreeGB=[Math]::Round($_.FreeSpace/1GB);Serial=$d.serialnumber;Type=$d.Type}}

        return  ($return|select Computer,Type,Drive,Name, FreeGB,SizeGB,SCSIID,Serial)
        }
        $os = Get-CimInstance Win32_OperatingSystem
        $ips = Get-NetAdapter -Physical | Get-NetIPAddress -AddressFamily IPv4
        $drives = get-driveinfo
        [string[]]$dns = Get-NetAdapter -Physical | 
            Get-DnsClientServerAddress -AddressFamily IPv4 |
                Where-Object { $_.ServerAddresses} | 
                    ForEach-Object { '{0}: {1}' -f $_.InterfaceAlias,($_.ServerAddresses -join ', ')
                    }
        $hostname = [System.Net.Dns]::GetHostName()
        $domain = (Get-CimInstance Win32_ComputerSystem).Domain
        $dns = Get-DnsClientServerAddress -InterfaceAlias "Ethernet*"  | select -ExpandProperty ServerAddresses | Where-Object {$_ -notlike "*:*"}
        $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | ForEach-Object {"{0} GB" -f ([math]::round(($_.Sum / 1GB)))}
        $phys = Get-CimInstance win32_processor
        $logical = $phys | Measure-Object -Property NumberOfLogicalProcessors,NumberOfCores -Sum
        
        New-Object psobject -Property ([ordered]@{
            Computer = $hostname
            OS = $os.Caption
            Domain = $domain
            IPAddresses = $ips.IPv4Address -join ', '
            DNS = $dns -join "`n`r"
            CPU = 'Sockets: {0}; CoresPerSocket: {2}; LogicalProcessors: {1}' -f ($phys|Measure-Object).Count, $logical[0].Sum, $logical[1].Sum
            Memory = $memory
            Disks = foreach($drive in $drives){"Drive: {0}; Type: {1};Location: {2}; Free/Total Storage: {3} GB /{4} GB`n`r" -f $drive.Drive, $drive.Type, $drive.SCSIID, $drive.FreeGB, $drive.SizeGB}
        })
        }#end Get-Serverinfo

        Function Get-DriveInformation
            {
            $c=$env:COMPUTERNAME;$disks=gwmi win32_diskdrive -Comp $c|select __path,@{n="SCSI_Id";e={[string]$([int]$_.scsiport)+":"+$_.scsitargetid}},serialnumber,Type
            function match($p,$l,$c){$l2p=gwmi win32_logicaldisktopartition -comp $c|?{$_.dependent -eq $l.__PATH}
            $d2p=gwmi win32_diskdrivetodiskpartition -comp $c|?{$_.dependent -eq $l2p.antecedent}
            $tmp=Get-WmiObject Win32_DiskPartition -comp $c|?{$_.__PATH -eq $l2p.Antecedent};$t=switch -Regex ($tmp.type){'^GPT'{'GPT'};'^Ins'{'MBR'}
            default{'unavailable'}}$p=$p|?{$_.__path -eq $d2p.antecedent};$p.Type=$t;$p}
            gwmi win32_logicaldisk -comp $c |?{$_.drivetype -eq '3'}|%{$d = match $disks $_ $c;New-Object psobject -Property @{Computer=$c;Drive=$_.deviceid;Name=$_.volumename
            SCSIID=$d.SCSI_Id;SizeGB=[Math]::Round($_.size/1GB);FreeGB=[Math]::Round($_.FreeSpace/1GB);Serial=$d.serialnumber
            Type=$d.Type}}|ft -a Computer,Name,Drive,Type,SCSIID,FreeGB,SizeGB,Serial
            }    
    Function Get-Uptime
        <#.Example: PS C:\Test Script> .\wininfo-v3.ps1 -getuptime
        This section will show uptime for the server (ie. last reboot time and how long since last reboot)
        #>
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Server Uptime"
        $host.ui.RawUI.ForegroundColor = "White"
        $os = Get-WmiObject win32_operatingsystem
        $uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
        $Display = "" + $Uptime.Days + " days, " + $Uptime.Hours + " hours, " + $Uptime.Minutes + " minutes" 
        $lastboottime = Get-CimInstance CIM_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
        Write-Output "System Uptime:"
        Write-Output $Display
        Write-Output "Last Rebooted:"$lastboottime
        }
    function Get-PendingReboot
        <#.Example: PS C:\Test Script> .\wininfo-v3.ps1 -pendingreboot
        This section will show if there are any pending reboot flags on the server
        #>
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Pending Reboot"
        $host.ui.RawUI.ForegroundColor = "White"
        if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
        if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
        if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
        try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if(($status -ne $null) -and $status.RebootPending){
        return $true
        }
        }catch{}

        return $false
        }
    Function Get-RebootDetails
        {
        Try
        {
        $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
        $CBSRebootPend = $null
        $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ErrorAction Stop
        $HKLM = [UInt32] "0x80000002"
        $WMI_Reg = [WMIClass] "\\$env:COMPUTERNAME\root\default:StdRegProv"
        If ([Int32]$WMI_OS.BuildNumber -ge 6001) {$RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\");$CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"}
        $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
        $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
        $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
        $RegValuePFRO = $RegSubKeySM.sValue
        $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
        $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')
        $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")           
        $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")
        If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {$CompPendRen = $true}
        If ($RegValuePFRO) {$PendFileRename = $true}
        $CCMClientSDK = $null
        $CCMSplat = @{
        NameSpace='ROOT\ccm\ClientSDK'
        Class='CCM_ClientUtilities'
        Name='DetermineIfRebootPending'
        ComputerName=$env:COMPUTERNAME
        ErrorAction='Stop'
        }
        ## Try CCMClientSDK
        Try {$CCMClientSDK = Invoke-WmiMethod @CCMSplat} Catch [System.UnauthorizedAccessException] {
        $CcmStatus = Get-Service -Name CcmExec -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue
        If ($CcmStatus.Status -ne 'Running') {
            Write-Warning "Error - CcmExec service is not running."
            $CCMClientSDK = $null
        }
        } Catch {
        $CCMClientSDK = $null
        }
        If ($CCMClientSDK) {
        If ($CCMClientSDK.ReturnValue -ne 0) {
            Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"         
        }
        If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
            $SCCM = $true
        }
        }
        Else {
        $SCCM = $null
        }
        ## Creating Custom PSObject and Select-Object Splat
        $SelectSplat = @{
        Property=(
            'Computer',
            'CBServicing',
            'WindowsUpdate',
            'CCMClientSDK',
            'PendComputerRename',
            'PendFileRename',
            'PendFileRenVal',
            'RebootPending'
        )}
        $results = New-Object -TypeName PSObject -Property @{
        Computer=$WMI_OS.CSName
        CBServicing=$CBSRebootPend
        WindowsUpdate=$WUAURebootReq
        CCMClientSDK=$SCCM
        PendComputerRename=$CompPendRen
        PendFileRename=$PendFileRename
        PendFileRenVal=$($temp=$RegValuePFRO;for($i=0;$i -lt $temp.count;$i++){if(($temp[$i] -ne "") -or ($i %2 -eq 0)){$temp[$i]}})
        RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
        } | Select-Object @SelectSplat
        }catch{Write-Warning "$_"}
        $results
        }
    Function Get-ProtocolInfo
        <#.Example: PS C:\Test Script> .\wininfo-v3.ps1 -protocolcheck
        This section will display which, if any, protocol suites are enabled (ie. TLS 1.2)
        #>
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Protocol Information"
        $host.ui.RawUI.ForegroundColor = "White"
        $ErrorActionPreference = "SilentlyContinue"
        $OScheck = Get-CimInstance Win32_OperatingSystem | select -ExpandProperty Caption | Select-String -Pattern '20\d\d' | ForEach-Object { $_.Matches.Value }
        $SSL2 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' | select -ExpandProperty Enabled
        $SSL3 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' | select -ExpandProperty Enabled
        $tls10 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' | select -ExpandProperty Enabled
        $tls11 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' | select -ExpandProperty Enabled
        $tls12 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' | select -ExpandProperty Enabled
        If ($tls10 -eq 0 -or $tls10 -eq $null){Write-Output "TLS 1.0 is Disabled"}Else{Write-Output "TLS 1.0 is Enabled"}
        If ($OScheck -gt 2012)
        {
        If ($tls11 -eq 0) {Write-Output "TLS 1.1 is Disabled"}Else{Write-Output "TLS 1.1 is Enabled"}
        If ($tls12 -eq 0) {Write-Output "TLS 1.2 is Disabled"}Else{Write-Output "TLS 1.2 is Enabled"}
        }Else{
        If ($tls11 -eq 0 -eq $null) {Write-Output "TLS 1.1 is Disabled"}Else{Write-Output "TLS 1.1 is Enabled"}
        If ($tls12 -eq 0 -eq $null) {Write-Output "TLS 1.2 is Disabled"}Else{Write-Output "TLS 1.2 is Enabled"}
        }}
    function Get-CipherInfo {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Cipher Suite Information"
        $host.ui.RawUI.ForegroundColor = "White"
        $ciphercheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002\ -Name Functions | select -ExpandProperty Functions 
        $ciphercheck2 = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003\ -Name Functions | select -ExpandProperty Functions
        $reply = Read-Host -Prompt "Do you wish to view the Ciphers?[y/n]"
        ""
        If ( $reply -like "y" ) 
        {Write-Output 
        $ciphercheck 
        $ciphercheck2}
        Else{Write-Output "Skipping Cipher Check"}
        }
    function Get-AVCheck 
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Installed Antivirus"
        $host.ui.RawUI.ForegroundColor = "White" 
        $ErrorActionPreference = "SilentlyContinue"
        $antivirus = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -match "avast|avg|bitdefender|clamav|crowdstrike|endpoint protection|eset|internet security|kapersky|mcafee|norton|smart security|sophos|symantec|trend|virus" } | Select-Object -Property DisplayName | Select -ExpandProperty DisplayName
        If ($antivirus -eq $null)
        {Write-Output "No Antivirus Installed" | Out-Default}Else{$antivirus | Out-Default}
        }
    Function Get-PatchInfo
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Most Recent Patches Installed"
        $host.ui.RawUI.ForegroundColor = "White"
        #$patchcheck = Get-HotFix | Select-Object -Property Description,HotFixID,InstalledOn | Select-Object -Last 10 | Sort-Object -Descending 'InstalledOn' | Format-Table
        $patchcheck = Get-HotFix | select -Property Description,HotFixID,InstalledOn | Sort-Object -Descending 'HotFixID' | ft -a
        Write-Output $patchcheck | Out-Default
        }
    Function Check-Updates
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Running check for available patches"
        $host.ui.RawUI.ForegroundColor = "White"
        If (wuauclt.exe /resetauthorization /detectnow /updatenow){
        $ErrorActionPreference = "SilentlyContinue"
        Write-Host "Searching for updates, please wait... (This will NOT Download any patches)"
        $SearchResult = (New-Object -ComObject Microsoft.Update.Searcher).Search("IsInstalled=0").Updates | ? {$_.MsrcSeverity -ne $null}
        $updates = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $SearchResult) { $updates.Add($update) >> $null}
        }Else{
        Write-Host "No Updates Available"
        }

        Write-Host "Downloading $($SearchResult.count) important updates..."
        $downloader = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateDownLoader()
        $downloader.Updates = $updates
        $downloader.Download()
        }
    Function Install-Updates
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Downloading and Installing Available Patches"
        $host.ui.RawUI.ForegroundColor = "White"
        Function Run-Updates
        {
        wuauclt.exe /resetauthorization /detectnow /updatenow
        Write-Host "Searching for updates, please wait..."
        $SearchResult = (New-Object -ComObject Microsoft.Update.Searcher).Search("IsInstalled=0").Updates | ? {$_.MsrcSeverity -ne $null}
        $updates = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $SearchResult) { $updates.Add($update) >> $null}
        Write-Host "Downloading $($SearchResult.count) important updates..."
        $downloader = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateDownLoader()
        $downloader.Updates = $updates
        $downloader.Download()
        Write-Host "Installing $($SearchResult.count) important updates..."
        $installer = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateInstaller()
        $installer.Updates = $updates
        $Result = $installer.Install()
        }
        $reply = Read-Host -Prompt "!!!WARNING!!! Performing this action will require a reboot, do you wish to proceed?[y/n]"
        ""
        If ( $reply -like "y" ){Run-Updates}Else{Write-Host "Halting Patch Check" -ForegroundColor Yellow}
        }         
    Function Get-InstalledSoftware 
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Installed Software"
        $host.ui.RawUI.ForegroundColor = "White"
        $ErrorActionPreference = 'silentlycontinue'
        If (Test-Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server') {
        $inst = (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances
        foreach ($i in $inst)
        {
        $p = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL').$i
        #$i
        $edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Edition
        $version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Version
        $product = Switch -regex ($version) {
        '^10' { "Microsoft SQL Server 2008/R2" }
        '^11' { "Microsoft SQL Server 2012" }
        '^12' { "Microsoft SQL Server 2014" }
        '^13' { "Microsoft SQL Server 2016" }
        '^14' { "Microsoft SQL Server 2017" }
        '^15' { "Microsoft SQL Server 2019" }
        '^16' { "Microsoft SQL Server 2022" }
        Default { "Unsupported version." }
        }
        Write-Output ""
        #Write-Output "Instance: $i"
        Write-Output "Product: $product"
        Write-Output "Edition: $edition"
        Write-Output "Version: $version"
        Write-Output ""
        }
        }Else{
        Write-Output "SQL Software not installed"
        }
        ""
        $iis = (Get-WindowsFeature web-server).InstallState
        if ($iis -eq "Installed") {Write-Output "IIS is Installed"} Else {Write-Output "IIS is NOT Installed"}
        " "
        $vormetricagent = gsv secfsd | select Status
        $vormetricversion = & 'C:\Program Files\Vormetric\DataSecurityExpert\agent\secfs\sec\bin\secfsd.exe' | findstr Version
        $vormetricrelease = $vormetricversion.split(" ")[12]
        If ($vormetricagent -eq $null){Write-Output "Vormetric Agent is Not Installed"}Else{Write-Output "Vormetric Agent Version: $vormetricrelease"}
        " "
        $r1softagent = gsv cdp | select Status
        If ($r1softagent -eq $null){Write-Output "R1soft Agent is NOT Installed"}Else{Write-Output "R1soft Agent is installed"}
        " "
        $rubrikagent = gsv "Rubrik Backup Service" | select Status
        If ($rubrikagent -eq $null){Write-Output "Rubrik Agent is not Installed"}Else{Write-Output "Rubrik Agent is Installed"}
        }
    Function Get-ArmorAgentPort
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Armor Agent Port Check (API)"
        $host.ui.RawUI.ForegroundColor = "White"
        $ErrorActionPreference = "SilentlyContinue"
        $agentport = (New-Object System.Net.Sockets.TcpClient("agent.api.secure-prod.services", 443)).Connected
        If ($agentport -eq "True"){Write-Output "Armor Agent is Connected"}Else{Write-Output "Armor Agent is not connected, please confirm outbound firewall rule to 99.83.175.90 and 75.2.84.73 on port 443 is properly set"}
        }
   Function Get-TrendPorts
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Trend Port Check (FIM/Malware Protection/IDS)"
        $host.ui.RawUI.ForegroundColor = "White"
        $ErrorActionPreference = "SilentlyContinue"
        $4119 = (New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4119)).Connected
        $4120 = (New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4120)).Connected
        $4121 = (New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4121)).Connected
        If ($4119,$4120,$4121 -eq "True"){Write-Output "All Trend Service Ports are Connected"}
        Else{
        If ($4119 -ne "True"){Write-Output "Port 4119 is not connected"}
        If ($4120 -ne "True"){Write-Output "Port 4120 is not connected"}
        If ($4121 -ne "True"){Write-Output "Port 4121 is not connected"}
        }}
    Function Get-LogRelay
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Log Relay Port Check"
        $host.ui.RawUI.ForegroundColor = "White"
        $ErrorActionPreference = "SilentlyContinue"
        $relayports = (New-Object System.Net.Sockets.TcpClient("1d.log.armor.com", 5443)).Connected
        If ($relayports -eq "True"){Write-Output "Log Relay Port is connected"}Else{Write-Output "Log Relay Port is not connected, please check firewall rules to confirm 52.38.171.243, 52.26.92.237, and 35.155.168.100 are open to port 5443"}
        }
    Function Get-QualysPort
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Vulnerability Scanning Port Check (Qualys)"
        $host.ui.RawUI.ForegroundColor = "White"
        $ErrorActionPreference = "SilentlyContinue"
        $qualysport = (New-Object System.Net.Sockets.TcpClient("qagpublic.qg3.apps.qualys.com", 443)).Connected
        If ($qualysport -eq "True"){Write-Output "Vulnerability Scanning port is connected"}Else{Write-Output "Vulnerability Scanning port is not connected, please confirm outbound firewall rule for 64.39.96.0/20 on port 443 is open"}
        }
    Function Get-Panopta
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Panopta Check (Monitoring)"
        $host.ui.RawUI.ForegroundColor = "White"
        $ErrorActionPreference = "SilentlyContinue"
        $panoptacheck = (New-Object System.Net.Sockets.TcpClient("146.88.106.200", 8443)).Connected
        If ($panoptacheck -eq "True"){Write-Output "Server is able to establish connection to Panopta"}Else{Write-Output "Unable to establish connection to Panopta, check connectivity to 1a.mon.armor.com on port 8443 and troubleshoot accordingly"}
        }
    Function Get-LogPort
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Log Management Port Check (Winglogbeat/Filebeat)"
        $host.ui.RawUI.ForegroundColor = "White"
        $ErrorActionPreference = "SilentlyContinue"
        $logport = (New-Object System.Net.Sockets.TcpClient("1d.log.armor.com", 5516)).Connected
        If ($logport -eq "True"){Write-Output "Log Management port is connected"}Else{Write-Output "Log Management port is not connected, please confirm outbound firewall rule for 52.38.171.243, 52.26.92.237, and 35.155.168.100 on port 5516 are open"}
        }
    Function Check-Ports
        {
        $checkports = ""
                      Get-ArmorAgentPort
                      Get-TrendPorts
                      #Get-LogRelay
                      Get-LogPort
                      Get-QualysPort
                      Get-Panopta
        } 
    Function Agent-Version
        {
        $agentversion = C:\.armor\opt\armor.exe --v
        $agentversion = $agentversion.split(" ")[2]
        $supervisor = C:\.armor\opt\armor-supervisor.exe version
        $supervisor = $supervisor.split(" ")[1]
        If ($agentversion -eq $null){Write-Output "Armor Agent is not installed"}Else{Write-Output "Armor Agent Version: $agentversion"}
        If ($supervisor -eq $null){Write-Output "Armor Supervisor not installed"}Else{Write-Output "Armor Supervisor Version: $supervisor"}
        }
        $ErrorActionPreference = "SilentlyContinue"
        
    Function Agent-Info
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Armor Agent Information"
        $host.ui.RawUI.ForegroundColor = "White"
        $ErrorActionPreference = 'silentlycontinue'
        $armoragent = gsv armor-agent | select -ExpandProperty Status
        If ($armoragent -eq $null) {Write-Output "Armor Agent Status: Not Installed"}Else{Write-Output "Armor Agent Status: $armoragent"}
        
        }
    Function show-subagents
        {
        $output = @()
        $reg = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty
        "Trend","FortiMonitorAgent","Qualys" | ForEach-Object {
        $tmpout = '' | select Subagent,Version,Installed
        $tmpout.Subagent = $_
        $key = $reg | Where-Object { $_ -match $tmpout.Subagent }
        $tmpout.Installed = ( -not [string]::IsNullOrEmpty($key) )
        $tmpout.Version = try{ $key[0].displayversion } catch {$null}
        
        $output+= $tmpout
        }
        'Filebeat','Winlogbeat' | ForEach-Object {
        $tmpout = '' | select Subagent,Version,Installed
        $tmpout.Subagent = $_
        try {
        $filepath = Get-ChildItem -Path "c:\.armor\opt\$_*" -ErrorAction Stop | Where-Object{$_.PSIsContainer} | select -First 2
        $tmpout.Installed = $true
        $tmpout.Version = ($filepath.Name | Select-String "\d\.\d\.\d").Matches[0].Value
        } catch {
        $tmpout.Installed = $false
        $tmpout.Version = $null
        }
        $output += $tmpout
        }
        $output
        }
        
    Function Armor-Services
        {
        $services = @{}
        $servicenames = @('AMSP','ds_agent','ds_monitor','ds_notifier','ds_agent', 'Armor-Filebeat', 'Armor-Winlogbeat','QualysAgent', 'FortiMonitorAgent')
        Foreach ($servicename in $servicenames ) {
        try {
        $servicestatus = gsv $servicename -ErrorAction Stop | select -ExpandProperty status
        #$servicedisplay = gsv $servicename -ErrorAction Stop | select -ExpandProperty DisplayName
        } catch {
        $servicestatus = 'Not Installed'        
        }
        $services.Add($servicename , $servicestatus)
        }
        New-Object psobject -Property $services | Out-Default
        }
        $ErrorActionPreference = "SilentlyContinue"
    Function Show-Armorservices
        {
        $titlecolor = $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "Armor Agent Information"
        $host.ui.RawUI.ForegroundColor = "White"
        $showarmorservices = Agent-Info;Agent-Version;show-subagents;Armor-Services
        }
        }

    
        


Process
    {switch ( $true ) {
        $serverinfo        { Get-Serverinfo | Out-Default }
        $driveinformation  { Get-DriveInformation | Out-Default }
        $getuptime         { Get-Uptime | Out-Default }
        $pendingreboot     { Get-PendingReboot | Out-Default }
        $rebootdetails     { Get-RebootDetails | Out-Default }
        $avcheck           { Get-AVCheck | Out-Default }
        $installedsoftware { Get-InstalledSoftware | Out-Default }
        $patchcheck        { Get-PatchInfo | Out-Default }
        $checkupdates      { Check-Updates | Out-Default }
        $installupdates    { Install-Updates | Out-Default }
        $protocolcheck     { Get-ProtocolInfo | Out-Default }
        $ciphercheck       { Get-CipherInfo | Out-Default }
        $showarmorservices { Show-Armorservices | Out-Default }
        $checkports        { Check-Ports | Out-Default}
        default {
            Get-Serverinfo | Out-Default
            Get-Uptime | Out-Default
            Get-PendingReboot | Out-Default
            Get-AVCheck | Out-Default
            Get-InstalledSoftware | Out-Default
            Get-PatchInfo | Out-Default
            Get-ProtocolInfo | Out-Default
            Get-CipherInfo | Out-Default
            Show-Armorservices | Out-Default
                }
    }
    }
End {

}