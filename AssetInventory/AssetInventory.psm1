Function Get-AssetInventory {
	<#
		.SYNOPSIS
			Retrieves asset information including software inventory, installed windows updates, system information, and hardware information.

		.DESCRIPTION
			The Get-AssetInventory cmdlet is a function that retrieves information from the computer the script is running on.

        .EXAMPLE
			Get-AssetInventory 
	        
			Returns a full inventory of software, updates, and system information from the local computer as a powershell object.

		.EXAMPLE
			Get-AssetInventory -ComputerName remotecomputer
			
			Returns a full inventory from a remote computer, it will prompt for credentials.

		.EXAMPLE
			Get-AssetInventory -AsJson

			Returns the inventory information formatted in JSON.

		.PARAMETER ComputerName
			The computer to run the cmdlet against, if it is not supplied, or is localhost or 127.0.0.1, the cmdlet will run locally.

		.PARAMETER AsJson
			A switch to specify the output should be in JSON instead of a PSObject.

		.PARAMETER AsXml
			A switch to specify the output should be an Xml string instead of a PSObject.

		.PARAMETER Credentials
			The credentials to run the cmdlet with.

		.INPUTS
			System.String

		.OUTPUTS
			System.Management.Automation.PSObject

			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 3/31/2016
	#>

    [CmdletBinding(DefaultParameterSetName="JSON")]
	Param
	( 
		[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)] 
		$ComputerName = "localhost",
		[Parameter(Position=1, ParameterSetName="JSON")]
		[switch] $AsJson = $false, 
		[Parameter(Position=1, ParameterSetName="XML")]
		[switch] $AsXML = $false,
		[Parameter(Position=2)]
		[switch] $IgnorePing = $false,
		[Parameter(Position=3)]
		[PSCredential]$Credential = [PSCredential]::Empty
	)

	Begin {
		if ($Credential -eq $null) {
			$Credential = [PSCredential]::Empty
		}
	}

	Process {

		$total = 18
		$completed = 0

		if ($ComputerName.ToLower() -eq "localhost" -or $ComputerName -eq "127.0.0.1" -or $ComputerName.ToLower() -eq $env:COMPUTERNAME.ToLower())
		{
			$systemInfo = Get-ComputerSystemInformation
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )

			$disk = Get-DiskInformation
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
	
			$bios = Get-BIOS
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )

			$cpu = Get-CPU 
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
	
			$os = Get-OperatingSystem
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
    
			$network = Get-NetworkAdapters
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
	
			$bit32 = Get-32BitSoftware
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
    
			$bit64 = Get-64BitSoftware
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
	
			$wsus = Get-MicrosoftUpdates
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )

			$missing = Get-MissingWindowsUpdates
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
    
			$reboots = Get-PendingReboots
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
    
			$usb = Get-USBDevices
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
	
			$memory = Get-MemoryStatistics
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )	
    
			$services = Get-SystemServices
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )	
    
			$tcp = Get-TCPPorts
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )	
    
			$udp = Get-UDPPorts
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
    
			$features = Get-InstalledWindowsFeatures
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 ) 
			
			$GPResult = Get-GPResult
			$status = (++$completed).ToString() + " of " + $total.ToString()
			Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 ) 
		}
		else
		{
			if ((Ping-Host -ComputerName $ComputerName) -or $IgnorePing)
			{
				if ($Credential -eq $null)
				{
					$Credential = Get-Credential
				}

				$session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
				Invoke-Command -Session $session -ScriptBlock {Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process}
        
				$systemInfo = Invoke-Command -Session $session -ScriptBlock ${function:Get-ComputerSystemInformation} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )

				$disk = Invoke-Command -Session $session -Scriptblock ${function:Get-DiskInformation} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
	
				$bios = Invoke-Command -Session $session -Scriptblock ${function:Get-BIOS} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )

				$cpu = Invoke-Command -Session $session -Scriptblock ${function:Get-CPU} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
	
				$os = Invoke-Command -Session $session -Scriptblock ${function:Get-OperatingSystem} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
    
				$network = Invoke-Command -Session $session -Scriptblock ${function:Get-NetworkAdapters} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
	
				$bit32 = Invoke-Command -Session $session -Scriptblock ${function:Get-32BitSoftware} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
    
				$bit64 = Invoke-Command -Session $session -Scriptblock ${function:Get-64BitSoftware} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
	
				$wsus = Invoke-Command -Session $session -Scriptblock ${function:Get-MicrosoftUpdates} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )

				$missing = Invoke-Command -Session $session -Scriptblock ${function:Get-MissingWindowsUpdates}
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
    
				$reboots = Invoke-Command -Session $session -Scriptblock ${function:Get-PendingReboots} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
    
				$usb = Invoke-Command -Session $session -Scriptblock ${function:Get-USBDevices} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
	
				$memory = Invoke-Command -Session $session -Scriptblock ${function:Get-MemoryStatistics} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )	
    
				$services = Invoke-Command -Session $session -Scriptblock ${function:Get-SystemServices} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )	
    
				$tcp = Invoke-Command -Session $session -Scriptblock ${function:Get-TCPPorts} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )	
    
				$udp = Invoke-Command -Session $session -Scriptblock ${function:Get-UDPPorts} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )
    
				$features = Invoke-Command -Session $session -Scriptblock ${function:Get-InstalledWindowsFeatures} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )   

				$GPResult = Invoke-Command -Session $session -Scriptblock ${function:Get-GPResult} 
				$status = (++$completed).ToString() + " of " + $total.ToString()
				Write-Progress -Activity "Collecting Information" -Status $status -PercentComplete ( ($completed / $total) * 100 )   
			}
		}

		$Result = New-Object -TypeName PSObject -Property @{"System Info" = $systemInfo; "Disks" = $disk; "BIOS" = $bios; "CPU" = $cpu; 
				"Operating System" = $os; "Network Adapters" = $network; "Software (32 bit)" = $bit32; "Software (64 bit)" = $bit64;
				"Windows Updates" = $wsus; "Missing Updates" = $missing; "Pending Reboots" = $reboots; "USB Devices" = $usb; "Memory" = $memory; 
				"Services" = $services;"TCP Ports" = $tcp;"UDP Ports"=$udp; "Windows Features" = $features; "Group Policy" = $GPResult}
	}

	End {
		if ($AsJson)
		{
			Write-Output (ConvertTo-Json -InputObject $Result -Depth 10)
		}
		else
		{
			if ($AsXML) 
			{
				Write-Output (ConvertTo-Xml -InputObject $Result -Depth 4 -As String)
			}
			else
			{
				Write-Output $Result
			}		
		}
	}
}

Function Ping-Host {
	<#
		.SYNOPSIS
			Tests connectivity to a host with a single ping.

		.DESCRIPTION
			The Ping-Host cmdlet sends one ping to the remote host to check for connectivity.

        .EXAMPLE
			Ping-Host -ComputerName remotehost

	        Returns true or false depending on the ping result.

		.PARAMETER ComputerName
		    The name of the host to ping.

		.INPUTS
			System.String

		.OUTPUTS
			System.Boolean

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string]$ComputerName
	)

	Begin {}

	Process {
		$Result = Test-Connection -Quiet -Count 1 -ComputerName $ComputerName
	}

	End {
		Write-Output $Result
	}
}

Function Test-RegistryEntry {
	<#
		.SYNOPSIS
			Tests the existence of a registry value.

		.DESCRIPTION
			The Test-RegistryEntry cmdlet test the extistence of a registry value (property of a key).

        .EXAMPLE
			Test-RegistryEntry -Key "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing" -PropertyName PendingFileRenameOperations 

	        Returns true or false depending on the existence of the property

		.PARAMETER Key
			The registry key to test for containing the property.

		.PARAMETER PropertyName
			The property name to test for.

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	Param (
		[Parameter(Position=0, Mandatory=$true)]
		[string]$Key,
		[Parameter(Position=1, Mandatory=$true)]
		[string]$PropertyName
	)

	Begin {

	}

	Process {
		Get-ItemProperty -Path $Key -Name $PropertyName -ErrorAction SilentlyContinue | Out-Null
		Write-Output $?
	}

	End {

	}

}

Function Get-UDPPorts {
	<#
		.SYNOPSIS
			Gets the open UDP Ports on the host/

		.DESCRIPTION
			The Get-UDPPorts cmdlet uses netstat to get the open UDP ports, and outputs the ports, the listening local address, and the process using the port.

		.EXAMPLE
			Get-UDPPorts

			Outputs the open udp ports on the system and the processes associated with them.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Invoke-Expression -Command "netstat -ano" | 
			Select-String -Pattern "\s+(UDP)" | 
			Select-Object -Property @{Name="Data"; Expression={$_.Line.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)}} | 
			Where-Object { $_.Data[1] -notmatch "^\[::"} | 
			ForEach-Object {     
				$localAddress = $_.Data[1].Substring(0, $_.Data[1].LastIndexOf(":"))
				$port = $_.Data[1].Substring($_.Data[1].LastIndexOf(":") + 1)
				$processId = $_.Data[3]
				$processName = Get-Process -Id $processId | Select-Object -ExpandProperty Name
				return New-Object -TypeName PSObject -Property @{"Local Address"=$localAddress;"Port"=$port;"Process Id"=$processId;"Process Name"=$processName}
			}
	}

	End {
		$Result
	}
}
	
Function Get-TCPPorts {
	<#
		.SYNOPSIS
			Gets the open TCP Ports on the host.

		.DESCRIPTION
			The Get-UDPPorts cmdlet uses Get-NetTCPConnection to get the open TCP ports, and outputs the ports, the listening local address, and the process using the port.

		.EXAMPLE
			Get-TCPPorts

			Outputs the open tcp ports on the system and the processes associated with them.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
			Where-Object {$_.State -eq "Listen" -and $_.LocalAddress -notmatch "^::"} | 
			Select-Object -Property @{Name="Local Address";Expression={$_.LocalAddress}}, 
									@{Name="Port";Expression={$_.LocalPort}},
									@{Name="Process Id";Expression={$_.OwningProcess}},
									@{Name="Process Name";Expression={Get-Process -Id $_.OwningProcess | Select-Object -ExpandProperty Name}}        
	}

	End {
		Write-Output $Result
	}
} 
	
Function Get-SystemServices {
	<#
		.SYNOPSIS
			Gets all services on the host.

		.DESCRIPTION
			The Get-SystemServices cmdlet uses Get-Service to get the services on the system.

		.EXAMPLE
		    Get-SystemServices

			Produces similar output as Get-Service, but sets the error action to silently continue.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Get-Service -ErrorAction SilentlyContinue | Select-Object -Property Name,DisplayName,@{Name="Status";Expression={$_.Status.ToString()}} 		
	}

	End {
		Write-Output $Result
	}
}   
	
Function Get-USBDevices {
	<#
		.SYNOPSIS
			Gets installed usb devices on the system.

		.DESCRIPTION
			The Get-USBDevices cmdlet retrieves USB devices from WMI.

		.EXAMPLE
			Get-USBDevices

			Returns the installed USB devices

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Get-WmiObject -Class Win32_USBControllerDevice -ErrorAction SilentlyContinue | 
			ForEach-Object { [wmi]($_.Dependent)} | 
			Select-Object -Property Name,Description,DeviceID,HardwareID,Service,Present,Status,Manufacturer,@{Name="Install Date";Expression={$_.InstallDate}}
	}

	End {
		Write-Output $Result
	}
}  

Function Get-PendingReboots {
	<#
		.SYNOPSIS
			Identifies any sub system that has a required pending reboot.

		.DESCRIPTION
			The Get-PendingReboots cmdlet checks Windows Update, Component Based Servicing, File Rename Operations, Computer Rename, and the CCM Client for pending reboots.

		.EXAMPLE
			Get-PendingReboots

			Returns the status of each component and if they have a pending reboot.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {	
		$cbsReboot = $false
		$sccmReboot = $false
	}

	Process {
		$wmi_os = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber -ErrorAction SilentlyContinue | Select-Object -ExpandProperty BuildNumber
		$wuReboot = Test-Path -Path "HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

		#if OS is Vista/2008 or greater
		if ([Int32]$wmi_os -ge 6001)
		{
			$cbsReboot = (Get-ChildItem -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing" | Select-Object -ExpandProperty Name | Where-Object {$_ -contains "RebootPending"}) -ne $null
		}

		$fileRenameReboot = Test-RegistryEntry -Key "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" -PropertyName "PendingFileRenameOperations" 

		$computerRenameReboot = (Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName" -Name ComputerName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ComputerName) -ne 
			(Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName" -Name ComputerName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ComputerName)

		try
		{
			$sccmClientSDK = Invoke-WmiMethod -Class CCM_ClientUtilities -Name "DetermineIfRebootPending" -Namespace "ROOT\\ccm\\ClientSDK" -ErrorAction Stop
			$sccmReboot = ($sccmClientSDK.IsHardRebootPending -or $sccmClientSDK.RebootPending)
		}
		catch {}
	}

	End {
		Write-Output (New-Object -TypeName PSObject -Property @{"Windows Update"= $wuReboot;"Component Based Servicing"=$cbsReboot;"File Rename"=$fileRenameReboot;"Computer Rename"=$computerRenameReboot;"CCM Client"=$sccmReboot})
	}
}

Function Get-MicrosoftUpdates {
	<#
		.SYNOPSIS
			Gets all of the Microsoft Updates installed through the Windows Update Agent.

		.DESCRIPTION
			The Get-MicrosoftUpdates cmdlet checks the installed Microsoft Updates using the Microsoft.Update.Session COM object. It does not report on updates that were installed manually or outside of WUA. The cmdlet will report on the action and status of each update.

		.EXAMPLE
			Get-MicrosoftUpdates

			Returns all Microsoft Update operations on the machine.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>
	
	[CmdletBinding()]
	Param()

	Begin {
		[regex]$Regex = “KB\d*”
	}

	Process {

		$Session = New-Object -ComObject Microsoft.Update.Session
		$Searcher = $Session.CreateUpdateSearcher()
		$History = $Searcher.GetTotalHistoryCount()

		$Result = $Searcher.QueryHistory(1, $History) | Select-Object -Property @{Name="Hot Fix ID";Expression={$Regex.Match($_.Title).Value}},
		Title,
		@{Name="Operation";Expression={switch($_.Operation) {
					1 {"Install"};
					2 {"Uninstall"};
					3 {"Other"}
				}
			}
		},
		@{Name="Status";Expression={switch($_.ResultCode) {
					1 {"In Progress"};
					2 {"Succeeded"};
					3 {"Succeeded With Errors"};
					4 {"Failed"};
					5 {"Aborted"};
				}
			}
		},
		@{Name="Date";Expression={(Get-Date($_.Date) -Format FileDateTimeUniversal).ToString()}}
	}

	End {
		Write-Output $Result
	}
}

Function Get-MissingWindowsUpdates {
	<#
		.SYNOPSIS
			Gets all missing windows updates as reported by the windows update agent.

		.DESCRIPTION
			Retrieves all the missing updates on the system. Requires an active internet connection or connection to a WSUS server.

		.EXAMPLE
			Get-MissingWindowsUpdates

			Returns all of the missing updates

		.PARAMETER RecommendedOnly
			Specify if only missing recommended updates are returned.

		.PARAMETER ProxyAddress
			If a proxy is required to connect to WSUS, specify the address.

		.INPUTS
			System.Boolean, System.String

		.OUTPUTS
			System.Management.Automation.PSObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/10/2016
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipelineByPropertyName=$true)]
		[bool]$RecommendedOnly = $false,
		[Parameter(Position=1,ValueFromPipelineByPropertyName=$true)]
		[string]$ProxyAddress = $null
	)

	Begin {
		$MissingUpdates = @()
	}

	Process {
		try {
			$Session = New-Object -ComObject Microsoft.Update.Session

			if ($ProxyAddress -ne $null) { 
				Write-Verbose "Setting Proxy" 
				$Proxy = New-Object -ComObject Microsoft.Update.WebProxy
				$Session.WebProxy.Address = $ProxyAddress 
				$Session.WebProxy.AutoDetect = $false 
				$Session.WebProxy.BypassProxyOnLocal = $true 
			} 

			$Searcher = $Session.CreateUpdateSearcher()

			if ($RecommendedOnly) {
				$SearchResults = $Searcher.Search("IsInstalled=0 and AutoSelectOnWebsites=1")
			}
			else {
				$SearchResults = $Searcher.Search("IsInstalled=0")
			}

			$SearchResults.RootCategories | ForEach-Object {
				foreach($Update in $_.Updates) {
					$KB = [Regex]::Match($Update.Title, "^.*\b(KB[0-9]+)\b.*$").Groups[1].Value

					$UpdateObject = New-Object -TypeName PSObject -Property @{"KB"=$KB;"Category"=$_.Name;"Title"=$Update.Title;"Type"=$Update.Type;"IsDownloaded"=$Update.IsDownloaded}
					$MissingUpdates += $UpdateObject
				}
			}
		}
		catch [Exception] {

		}
	}

	End {
		Write-Output $MissingUpdates
	}
}

Function Get-64BitSoftware {
	<#
		.SYNOPSIS
			Gets all 64 bit software installed on the computer.

		.DESCRIPTION
			The Get-64BitSoftware cmdlet gets all of the software registered at "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" that has a DisplayName property.

		.EXAMPLE
			Get-64BitSoftware

			Returns all of the installed 64 bit software installed.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
    $Result = Get-ChildItem -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" -ErrorAction SilentlyContinue | 
		Get-ItemProperty | 
		Where-Object {$_.DisplayName} | 
		Select-Object -Property @{Name="Name"; Expression={$_.DisplayName}},
			@{Name="Version";Expression={$_.DisplayVersion}},
			Publisher,
			@{Name="Install Date"; Expression={ (Get-Date ($_.InstallDate.Substring(4,2) + "/" + $_.InstallDate.Substring(6,2) + "/" + $_.InstallDate.Substring(0, 4)) -Format FileDateUniversal).ToString()}},
			@{Name="Install Source";Expression={$_.InstallSource}},
			@{Name="Install Location";Expression={$_.IntallLocation}},
			@{Name="Uninstall String";Expression={$_.UninstallString}}
	}

	End {
		Write-Output $Result
	}
}

Function Get-32BitSoftware {
	<#
		.SYNOPSIS
			Gets all 32 bit software installed on the computer.

		.DESCRIPTION
			The Get-32BitSoftware cmdlet gets all of the software registered at "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" that has a DisplayName property.

		.EXAMPLE
			Get-32BitSoftware

			Returns all of the installed 64 bit software installed.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Get-ChildItem -Path "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" -ErrorAction SilentlyContinue | 
		Get-ItemProperty | 
		Where-Object {$_.DisplayName} | 
		Select-Object -Property @{Name="Name"; Expression={$_.DisplayName}},
			@{Name="Version";Expression={$_.DisplayVersion}},
			Publisher,
			@{Name="Install Date"; Expression={ (Get-Date ($_.InstallDate.Substring(4,2) + "/" + $_.InstallDate.Substring(6,2) + "/" + $_.InstallDate.Substring(0, 4)) -Format FileDateUniversal).ToString()}},
			@{Name="Install Source";Expression={$_.InstallSource}},
			@{Name="Install Location";Expression={$_.IntallLocation}},
			@{Name="Uninstall String";Expression={$_.UninstallString}}
	}

	End {
		Write-Output $Result
	}
}

Function Get-NetworkAdapters {
	<#
		.SYNOPSIS
			Gets information on network adapters that have an active IP address.

		.DESCRIPTION
			The Get-NetworkAdapters cmdlet retrieves information on every active network adapter retrieved from WMI with an assigned IP address.

		.EXAMPLE
			Get-NetworkAdapters

			Returns information on active network adapters.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | 
			Where-Object {$_.IPAddress -match '\S+'} | 
			Select-Object @{Name="DHCP Enabled"; Expression={$_.DHCPEnabled}},
				IPAddress,
				@{Name="Default Gateway"; Expression={$_.DefaultIPGateway}},
				@{Name="DNS Domain"; Expression={$_.DNSDomain}},
				Description,
				Index           
	}

	End {
		Write-Output $Result
	}
}

Function Get-MemoryStatistics {
	<#
		.SYNOPSIS
			Gets current information on system memory usage and availability.

		.DESCRIPTION
			The Get-MemoryStatistics cmdlet get information of the total, used, and free memory on the system from the Win32_OperatingSystem WMI class.

		.EXAMPLE
			Get-MemoryStatistics

			Returns information on current memory usage and availability.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | 
			Select-Object -Property @{Name="Total Physical Memory (MB)"; Expression={$_.TotalVisibleMemorySize/1MB}},
				@{Name="Free Physical Memory (MB)";Expression={$_.FreePhysicalMemory/1MB}},
				@{Name="Used Physical Memory (MB)";Expression={($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/1MB}},
				@{Name="Total Virtual Memory (MB)";Expression={$_.TotalVirtualMemorySize/1MB}},
				@{Name="Free Virtual Memory (MB)";Expression={$_.FreeVirtualMemory/1MB}},
				@{Name="Used Virtual Memory (MB)";Expression={($_.TotalVirtualMemorySize - $_.FreeVirtualMemory)/1MB}}
	}

	End {
		Write-Output $Result
	}
}

Function Get-OperatingSystem {
	<#
		.SYNOPSIS
			Gets information about the currently installed operating system.

		.DESCRIPTION
			The Get-OperatingSystem cmdlet retrieves information from Win32_OperatingSystem about the OS.

		.EXAMPLE
			Get-OperatingSystem

			Returns information on the installed OS.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {

		$Result = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | 
			Select-Object -Property @{Name="Build Number";Expression={$_.BuildNumber}},
				@{Name="Name"; Expression={$_.Caption}},
				CurrentTimeZone,
				@{Name="Install Date"; Expression={(Get-Date($_.ConvertToDateTime($_.InstallDate)) -Format FileDateTimeUniversal).ToString()}},
				@{Name="Boot Time"; Expression={(Get-Date($_.ConvertToDateTime($_.LastBootUpTime)) -Format FileDateTimeUniversal).ToString()}},
				Manufacturer,
				@{Name="Architecture";Expression={$_.OSArchitecture}},
				@{Name="Serial Number";Expression={$_.SerialNumber}},
				@{Name="Service Pack";Expression={$_.ServicePackMajorVersion.ToString() + "." + $_.ServicePackMinorVersion.ToString()}},
				@{Name="System Device"; Expression={$_.SystemDevice}},
				@{Name="System Directory";Expression={$_.SystemDirectory}},
				@{Name="System Drive";Expression={$_.SystemDrive}},
				Version,
				@{Name="Windows Directory";Expression={$_.WindowsDirectory}} 
	}

	End {
		Write-Output $Result
	}
}

Function Get-CPU {
	<#
		.SYNOPSIS
			Gets information about the CPU on the host.

		.DESCRIPTION
			The Get-CPU cmdlet retrieves information from Win32_Processor about the CPUs on the host.

		.EXAMPLE
			Get-CPU

			Returns information on the CPUs on the host.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue | Select-Object -Property Name,ProcessorId,MaxClockSpeed,CurrentClockSpeed,NumberOfCores,DeviceID,CurrentVoltage,SocketDesignation,Status,ThreadCount,AddressWidth,DataWidth,Architecture       
	}

	End {
		Write-Output $Result
	}
}

Function Get-BIOS {
	<#
		.SYNOPSIS
			Gets information about the BIOS on the host.

		.DESCRIPTION
			The Get-BIOS cmdlet retrieves information from Win32_BIOS.

		.EXAMPLE
			Get-BIOS

			Returns information on the BIOS.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Get-WmiObject -Class Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -Property "Name","SerialNumber","Version"
	}

	End {
		Write-Output $Result
	}
}

Function Get-DiskInformation {
	<#
		.SYNOPSIS
			Gets information about the attached disks on the system.

		.DESCRIPTION
			The Get-DiskInformation cmdlet retrieves total and free space on disks from Win32_LogicalDisk where "DriveType=3".

		.EXAMPLE
			Get-DiskInformation

			Returns information on the attached disks.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | Select-Object DeviceID,
			@{Name="Free Space (MB)";Expression={$_.FreeSpace/1MB}},
			@{Name="Size (MB)";Expression={$_.Size/1MB}}    
	}

	End {
		Write-Output $Result
	}
}

Function Get-ComputerSystemInformation {
	<#
		.SYNOPSIS
			Gets general information about the host.

		.DESCRIPTION
			The Get-ComputerSystemInformation cmdlet retrieves basic information about the host.

		.EXAMPLE
			Get-ComputerSystemInformation

			Returns general information about the system.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {
		$Result = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object Name,Domain,Manufacturer,Model
	}

	End {
		Write-Output $Result
	}
}

Function Get-DnsInformation {
	<#
		.SYNOPSIS
			Gets information from DNS about the specified computer.

		.DESCRIPTION
			The Get-DNSInformation cmdlet retrieves DNS entries.

		.EXAMPLE
			Get-DnsInformation -ComputerName remotecomputer

			Returns all IP addresses associated with the specified computer.

		.PARAMETER ComputerName
			The host to look up in DNS.

		.INPUTS
			None

		.OUTPUTS
			System.String[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string]$ComputerName = "localhost"
	)

	Begin {
		$Temp = $ErrorActionPreference
		$ErrorActionPreference = 'SilentlyContinue'
	}

	Process {
		$IPAddresses = [System.Net.Dns]::GetHostAddresses($ComputerName) | Select-Object -ExpandProperty IPAddressToString
	}

	End {
		$ErrorActionPreference = $Temp
		Write-Output $IPAddresses
	}
}

Function Get-InstalledWindowsFeatures {
	<#
		.SYNOPSIS
			Gets information about installed windows features.

		.DESCRIPTION
			The Get-InstalledWindowsFeatures cmdlet retrieves the installed features.

		.EXAMPLE
			Get-InstalledWindowsFeatures

			Returns all installed windows features.
			
		.INPUTS
			None

		.OUTPUTS
			System.String[]
		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/3/2015
	#>

	[CmdletBinding()]
	Param()

	Begin {}

	Process {

		$OS = Get-WmiObject -Class Win32_OperatingSystem 

		if ($OS.ProductType -ne 1)
		{
			$Result = Get-WindowsFeature | Where-Object {$_.Installed -eq $true} | Select-Object Name
		}
		else
		{
			$Result = $null
		}
	}

	End {
		Write-Output $Result
	}
}

Function Get-GPResult {
	<#
		.SYNOPSIS
			Gets information about the currently applied group policy.

		.DESCRIPTION
			The Get-GPResult cmdlet retrieves a current resultant set of policy in different available formats. It utilizes the Get-ResultantSetOfPolicy cmdlet and modifies the output.

		.EXAMPLE
			Get-GPResult

			Returns the currently applied group policy as a JSON object.

		.PARAMETER AsJson
			Returns the policy results in JSON.

		.PARAMETER AsXml
			Returns the policy results in XML.
		
		.PARAMETER AsHtml
			Returns the policy results in HTML.
			
		.INPUTS
			None

		.OUTPUTS
			System.String

			System.Collections.Hashtable

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 3/31/2015
	#>

	[CmdletBinding(DefaultParameterSetName="Default")]
	Param(
		[Parameter()]
		[string]$ComputerName = $env:COMPUTERNAME,
		[Parameter()]
		[string]$UserName = "$env:USERDOMAIN\$env:USERNAME",
		[Parameter()]
		[switch]$ComputerOnly,
		[Parameter(ParameterSetName="Json")]
		[switch]$AsJson,
		[Parameter(ParameterSetName="Json")]
		[int]$Depth = 10,
		[Parameter(ParameterSetName="Xml")]
		[switch]$AsXml,
		[Parameter(ParameterSetName="Html")]
		[switch]$AsHtml
	)

	Begin {
		$GPResult = [System.String]::Empty

		$GPM = New-Object -ComObject GPMgmt.GPM
		$Constants = $GPM.GetConstants()
	}

	Process {
		$RSOP = $GPM.GetRSOP($Constants.RSOPModeLogging,$null,0)

		if ([System.String]::IsNullOrEmpty($ComputerName)) {
			$ComputerName = $env:COMPUTERNAME
		}

		$RSOP.LoggingComputer = $ComputerName

		if (!$ComputerOnly) {
			if ([System.String]::IsNullOrEmpty($UserName)) {
				$UserName = "$env:USERDOMAIN\$env:USERNAME"
			}

			$RSOP.LoggingUser = $UserName
		}
		else {
			$RSOP.LoggingFlags = $Constants.RsopLoggingNoUser
		}

		$RSOP.CreateQueryResults()

		switch ($PSCmdlet.ParameterSetName) {
			"Json" {
				$Result = @{}
				$Result.ComputerResults = @()
				$Result.UserResults = @()

				[System.Xml.XmlDocument]$Xml = $RSOP.GenerateReport($Constants.ReportXML).Result

				$Xml.GetElementsByTagName("UserResults") | ForEach-Object {
					$Result.UserResults += (ConvertFrom-Xml -InputObject $_)
				}

				$Xml.GetElementsByTagName("ComputerResults") | ForEach-Object {
					$Result.ComputerResults += (ConvertFrom-Xml -InputObject $_)
				}

				$GPResult = ConvertTo-Json -InputObject $Result -Depth $Depth
				break
			}
			"Xml"{
				$GPResult = $RSOP.GenerateReport($Constants.ReportXML).Result
				break
			}
			"Html" {
				$GPResult = $RSOP.GenerateReport($Constants.ReportHTML).Result
				break
			}
			default {
				$GPResult = @{}
				$GPResult.ComputerResults = @()
				$GPResult.UserResults = @()

				[System.Xml.XmlDocument]$Xml = $RSOP.GenerateReport($Constants.ReportXML).Result

				$Xml.GetElementsByTagName("UserResults") | ForEach-Object {
					$GPResult.UserResults += (ConvertFrom-Xml -InputObject $_)
				}

				$Xml.GetElementsByTagName("ComputerResults") | ForEach-Object {
					$GPResult.ComputerResults += (ConvertFrom-Xml -InputObject $_)
				}
			}
		}
	}

	End {
		Write-Output $GPResult
	}
}