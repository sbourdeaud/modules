#region functions

#region helper functions
function Write-LogOutput
{
<#
.SYNOPSIS
Outputs color coded messages to the screen and/or log file based on the category.

.DESCRIPTION
This function is used to produce screen and log output which is categorized, time stamped and color coded.

.PARAMETER Category
This the category of message being outputed. If you want color coding, use either "INFO", "WARNING", "ERROR" or "SUM".

.PARAMETER Message
This is the actual message you want to display.

.PARAMETER LogFile
If you want to log output to a file as well, use logfile to pass the log file full path name.

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Write-LogOutput -category "ERROR" -message "You must be kidding!"
Displays an error message.

.LINK
https://github.com/sbourdeaud
#>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

	param
	(
		[Parameter(Mandatory)]
        [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS','STEP','DEBUG')]
        [string]
        $Category,

        [string]
		$Message,

        [string]
        $LogFile
	)

    process
    {
        $Date = get-date #getting the date so we can timestamp the output entry
	    $FgColor = "Gray" #resetting the foreground/text color
	    switch ($Category) #we'll change the text color depending on the selected category
        {
            "INFO" {$FgColor = "Green"}
            "WARNING" {$FgColor = "Yellow"}
            "ERROR" {$FgColor = "Red"}
            "SUM" {$FgColor = "Magenta"}
            "SUCCESS" {$FgColor = "Cyan"}
            "STEP" {$FgColor = "Magenta"}
            "DEBUG" {$FgColor = "White"}
        }

	    Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
	    if ($LogFile) #add the entry to the log file if -LogFile has been specified
        {
            Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
            Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
        }
    }

}#end function Write-LogOutput

#helper-function Get-RESTError
function Help-RESTError 
{
    $global:helpme = $body
    $global:helpmoref = $moref
    $global:result = $_.Exception.Response.GetResponseStream()
    $global:reader = New-Object System.IO.StreamReader($global:result)
    $global:responseBody = $global:reader.ReadToEnd();

    return $global:responsebody

    break
}#end function Get-RESTError

#function used to display progress with a percentage bar
Function New-PercentageBar
{
	
<#
.SYNOPSIS
	Create percentage bar.
.DESCRIPTION
	This cmdlet creates percentage bar.
.PARAMETER Percent
	Value in percents (%).
.PARAMETER Value
	Value in arbitrary units.
.PARAMETER MaxValue
	100% value.
.PARAMETER BarLength
	Bar length in chars.
.PARAMETER BarView
	Different char sets to build the bar.
.PARAMETER GreenBorder
	Percent value to change bar color from green to yellow (relevant with -DrawBar parameter only).
.PARAMETER YellowBorder
	Percent value to change bar color from yellow to red (relevant with -DrawBar parameter only).
.PARAMETER NoPercent
	Exclude percentage number from the bar.
.PARAMETER DrawBar
	Directly draw the colored bar onto the PowerShell console (unsuitable for calculated properties).
.EXAMPLE
	PS C:\> New-PercentageBar -Percent 90 -DrawBar
	Draw single bar with all default settings.
.EXAMPLE
	PS C:\> New-PercentageBar -Percent 95 -DrawBar -GreenBorder 70 -YellowBorder 90
	Draw the bar and move the both color change borders.
.EXAMPLE
	PS C:\> 85 |New-PercentageBar -DrawBar -NoPercent
	Pipeline the percent value to the function and exclude percent number from the bar.
.EXAMPLE
	PS C:\> For ($i=0; $i -le 100; $i+=10) {New-PercentageBar -Percent $i -DrawBar -Length 100 -BarView AdvancedThin2; "`r"}
	Demonstrates advanced bar view with custom bar length and different percent values.
.EXAMPLE
	PS C:\> $Folder = 'C:\reports\'
	PS C:\> $FolderSize = (Get-ChildItem -Path $Folder |measure -Property Length -Sum).Sum
	PS C:\> Get-ChildItem -Path $Folder -File |sort Length -Descending |select -First 10 |select Name,Length,@{N='SizeBar';E={New-PercentageBar -Value $_.Length -MaxValue $FolderSize}} |ft -au
	Get file size report and add calculated property 'SizeBar' that contains the percent of each file size from the folder size.
.EXAMPLE
	PS C:\> $VolumeC = gwmi Win32_LogicalDisk |? {$_.DeviceID -eq 'c:'}
	PS C:\> Write-Host -NoNewline "Volume C Usage:" -ForegroundColor Yellow; `
	PS C:\> New-PercentageBar -Value ($VolumeC.Size-$VolumeC.Freespace) -MaxValue $VolumeC.Size -DrawBar; "`r"
	Get system volume usage report.
.NOTES
	Author      :: Roman Gelman @rgelman75
	Version 1.0 :: 04-Jul-2016 :: [Release] :: Publicly available
.LINK
	https://ps1code.com/2016/07/16/percentage-bar-powershell
#>
	
	[CmdletBinding(DefaultParameterSetName = 'PERCENT')]
	Param (
		[Parameter(Mandatory, Position = 1, ValueFromPipeline, ParameterSetName = 'PERCENT')]
		[ValidateRange(0, 100)]
		[int]$Percent
		 ,
		[Parameter(Mandatory, Position = 1, ValueFromPipeline, ParameterSetName = 'VALUE')]
		[ValidateRange(0, [double]::MaxValue)]
		[double]$Value
		 ,
		[Parameter(Mandatory, Position = 2, ParameterSetName = 'VALUE')]
		[ValidateRange(1, [double]::MaxValue)]
		[double]$MaxValue
		 ,
		[Parameter(Mandatory = $false, Position = 3)]
		[Alias("BarSize", "Length")]
		[ValidateRange(10, 100)]
		[int]$BarLength = 20
		 ,
		[Parameter(Mandatory = $false, Position = 4)]
		[ValidateSet("SimpleThin", "SimpleThick1", "SimpleThick2", "AdvancedThin1", "AdvancedThin2", "AdvancedThick")]
		[string]$BarView = "SimpleThin"
		 ,
		[Parameter(Mandatory = $false, Position = 5)]
		[ValidateRange(50, 80)]
		[int]$GreenBorder = 60
		 ,
		[Parameter(Mandatory = $false, Position = 6)]
		[ValidateRange(80, 90)]
		[int]$YellowBorder = 80
		 ,
		[Parameter(Mandatory = $false)]
		[switch]$NoPercent
		 ,
		[Parameter(Mandatory = $false)]
		[switch]$DrawBar
	)
	
	Begin
	{
		
		If ($PSBoundParameters.ContainsKey('VALUE'))
		{
			
			If ($Value -gt $MaxValue)
			{
				Throw "The [-Value] parameter cannot be greater than [-MaxValue]!"
			}
			Else
			{
				$Percent = $Value/$MaxValue * 100 -as [int]
			}
		}
		
		If ($YellowBorder -le $GreenBorder) { Throw "The [-YellowBorder] value must be greater than [-GreenBorder]!" }
		
		Function Set-BarView ($View)
		{
			Switch -exact ($View)
			{
				"SimpleThin"	{ $GreenChar = [char]9632; $YellowChar = [char]9632; $RedChar = [char]9632; $EmptyChar = "-"; Break }
				"SimpleThick1"	{ $GreenChar = [char]9608; $YellowChar = [char]9608; $RedChar = [char]9608; $EmptyChar = "-"; Break }
				"SimpleThick2"	{ $GreenChar = [char]9612; $YellowChar = [char]9612; $RedChar = [char]9612; $EmptyChar = "-"; Break }
				"AdvancedThin1"	{ $GreenChar = [char]9632; $YellowChar = [char]9632; $RedChar = [char]9632; $EmptyChar = [char]9476; Break }
				"AdvancedThin2"	{ $GreenChar = [char]9642; $YellowChar = [char]9642; $RedChar = [char]9642; $EmptyChar = [char]9643; Break }
				"AdvancedThick"	{ $GreenChar = [char]9617; $YellowChar = [char]9618; $RedChar = [char]9619; $EmptyChar = [char]9482; Break }
			}
			$Properties = [ordered]@{
				Char1 = $GreenChar
				Char2 = $YellowChar
				Char3 = $RedChar
				Char4 = $EmptyChar
			}
			$Object = New-Object PSObject -Property $Properties
			$Object
		} #End Function Set-BarView
		
		$BarChars = Set-BarView -View $BarView
		$Bar = $null
		
		Function Draw-Bar
		{
			
			Param (
				[Parameter(Mandatory)]
				[string]$Char
				 ,
				[Parameter(Mandatory = $false)]
				[string]$Color = 'White'
				 ,
				[Parameter(Mandatory = $false)]
				[boolean]$Draw
			)
			
			If ($Draw)
			{
				Write-Host -NoNewline -ForegroundColor ([System.ConsoleColor]$Color) $Char
			}
			Else
			{
				return $Char
			}
			
		} #End Function Draw-Bar
		
	} #End Begin
	
	Process
	{
		
		If ($NoPercent)
		{
			$Bar += Draw-Bar -Char "[ " -Draw $DrawBar
		}
		Else
		{
			If ($Percent -eq 100) { $Bar += Draw-Bar -Char "$Percent% [ " -Draw $DrawBar }
			ElseIf ($Percent -ge 10) { $Bar += Draw-Bar -Char " $Percent% [ " -Draw $DrawBar }
			Else { $Bar += Draw-Bar -Char "  $Percent% [ " -Draw $DrawBar }
		}
		
		For ($i = 1; $i -le ($BarValue = ([Math]::Round($Percent * $BarLength / 100))); $i++)
		{
			
			If ($i -le ($GreenBorder * $BarLength / 100)) { $Bar += Draw-Bar -Char ($BarChars.Char1) -Color 'DarkGreen' -Draw $DrawBar }
			ElseIf ($i -le ($YellowBorder * $BarLength / 100)) { $Bar += Draw-Bar -Char ($BarChars.Char2) -Color 'Yellow' -Draw $DrawBar }
			Else { $Bar += Draw-Bar -Char ($BarChars.Char3) -Color 'Red' -Draw $DrawBar }
		}
		For ($i = 1; $i -le ($EmptyValue = $BarLength - $BarValue); $i++) { $Bar += Draw-Bar -Char ($BarChars.Char4) -Draw $DrawBar }
		$Bar += Draw-Bar -Char " ]" -Draw $DrawBar
		
	} #End Process
	
	End
	{
		If (!$DrawBar) { return $Bar }
	} #End End
	
} #EndFunction New-PercentageBar

#endregion

#region prism
#this function is used to make a REST api call to Prism
function Invoke-PrismAPICall
{
<#
.SYNOPSIS
  Makes api call to prism based on passed parameters. Returns the json response.
.DESCRIPTION
  Makes api call to prism based on passed parameters. Returns the json response.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER method
  REST method (POST, GET, DELETE, or PUT)
.PARAMETER credential
  PSCredential object to use for authentication.
PARAMETER url
  URL to the api endpoint.
PARAMETER payload
  JSON payload to send.
.EXAMPLE
.\Invoke-PrismAPICall -credential $MyCredObject -url https://myprism.local/api/v3/vms/list -method 'POST' -payload $MyPayload
Makes a POST api call to the specified endpoint with the specified payload.
#>
param
(
    [parameter(mandatory = $true)]
    [ValidateSet("POST","GET","DELETE","PUT")]
    [string] 
    $method,
    
    [parameter(mandatory = $true)]
    [string] 
    $url,

    [parameter(mandatory = $false)]
    [string] 
    $payload,
    
    [parameter(mandatory = $true)]
    [System.Management.Automation.PSCredential]
    $credential
)

begin
{
    if (($PSVersionTable.PSVersion.Major -gt 5) -and (!$credential)) {
        throw "$(get-date) [ERROR] You must specify a credential object when using Powershell Core!"
    }
    if (($PSVersionTable.PSVersion.Major -le 5) -and (!$username) -and (!$password))  {
        throw "$(get-date) [ERROR] You must specify a username and password (as a secure string)!"
    }   
}
process
{
    Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
    try {
        #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12 as well as use basic authentication with a pscredential object
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json"
            }
            if ($payload) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
            }
        } else {
            $headers = @{
                "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrismSecurePassword))) ));
                "Content-Type"="application/json";
                "Accept"="application/json"
            }
            if ($payload) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
            }
        }
        Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan 
        if ($debugme) {Write-Host "$(Get-Date) [DEBUG] Response Metadata: $($resp.metadata | ConvertTo-Json)" -ForegroundColor White}
    }
    catch {
        $saved_error = $_.Exception.Message
        # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
        Write-Host "$(Get-Date) [INFO] Payload: $payload" -ForegroundColor Green
        Throw "$(get-date) [ERROR] $saved_error"
    }
    finally {
        #add any last words here; this gets processed no matter what
    }
}
end
{
    return $resp
}    
}

#this function is used to upload a file to AHV Prism Image Configuration library
function Send-FileToPrism
{
	#input: username, password, url, method, file
	#output: REST response
<#
.SYNOPSIS
  Uploads a file to AHV Prism Image Configuration library.
.DESCRIPTION
  This function is used to upload a file to the AHV image configuration library.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER username
  Specifies the Prism username.
.PARAMETER password
  Specifies the Prism password.
.PARAMETER url
  Specifies the Prism url.
.EXAMPLE
  .\Send-FileToPrism -username admin -password admin -url https://10.10.10.10:9440/api/nutanix/v0.8/images/$image_uuid/upload -method "PUT" -container_uuid $container_uuid -file /media/backup/vmdisk.qcow2
#>
	param
	(
		[string] 
        $username,
		
        [string] 
        $password,
        
        [string] 
        $url,
        
        [string] 
        [ValidateSet('PUT')]
        $method,
        
        [string]
        $container_uuid,

        $file
	)

    begin
    {
	 	#Setup authentication header for REST call
        $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}   
    }

    process
    {
        $myvarHeader += @{"Accept"="application/json"}
		$myvarHeader += @{"Content-Type"="application/octet-stream;charset=UTF-8"}
        #$myvarHeader += @{"X-Nutanix-Destination-Container"=$container_uuid}
            
        if ($IsLinux) 
        {
            try 
            {
			    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $file -SkipCertificateCheck -ErrorAction Stop
		    }
            catch 
            {
			    Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                try 
                {
                    $RESTError = Help-RESTError -ErrorAction Stop
                    $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                    if ($RESTErrorMessage) 
                    {
                        Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"
                    }
                }
                catch 
                {
                    Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                }
			    Exit
		    }
        }
        else 
        {
            try 
            {
			    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $file -ErrorAction Stop
		    }
            catch 
            {
			    Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                try 
                {
                    $RESTError = Help-RESTError -ErrorAction Stop
                    $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                    if ($RESTErrorMessage) 
                    {
                        Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"
                    }
                }
                catch 
                {
                    Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                }
			    Exit
		    }
        }
    }

    end
    {
        return $myvarRESTOutput
    }
}#end function Upload-FileToPrism

#this function is used to get a Prism task status
function Get-NTNXTask
{
<#
.SYNOPSIS
Gets status for a given Prism task uuid (replaces NTNX cmdlet)
.DESCRIPTION
Gets status for a given Prism task uuid
#>
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
        $TaskId,
        
        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $credential,

        [parameter(mandatory = $true)]
        [String]
        $cluster
    )

    Begin
    {
    }
    Process
    {
        $myvarUrl = "https://"+$cluster+":9440/PrismGateway/services/rest/v2.0/tasks/$($TaskId.task_uuid)"
        $result = Invoke-PrismAPICall -credential $credential -method "GET" -url $myvarUrl
    }
    End
    {
        return $result
    }
}#end function Get-NTNXTask

Function Get-PrismTaskStatus
{
    <#
.SYNOPSIS
Retrieves the status of a given task uuid from Prism and loops until it is completed.

.DESCRIPTION
Retrieves the status of a given task uuid from Prism and loops until it is completed.

.PARAMETER Task
Prism task uuid.

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Get-PrismTaskStatus -Task $task
Prints progress on task $task until successfull completion. If the task fails, print the status and error code and details and exits.

.LINK
https://github.com/sbourdeaud
#>
[CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

    param
    (
        [Parameter(Mandatory)]
        $task,
        
        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $credential,

        [parameter(mandatory = $true)]
        [String]
        $cluster
    )

    begin
    {}
    process 
    {
        #region get initial task details
            Write-Host "$(Get-Date) [INFO] Retrieving details of task $task..." -ForegroundColor Green
            $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
            $method = "GET"
            $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
            Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $task" -ForegroundColor Cyan
        #endregion

        if ($taskDetails.percentage_complete -ne "100") 
        {
            Do 
            {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Sleep 5
                $url = "https://$($cluster):9440/PrismGateway/services/rest/v2.0/tasks/$task"
                $method = "GET"
                $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
                
                if ($taskDetails.status -ne "running") 
                {
                    if ($taskDetails.status -ne "succeeded") 
                    {
                        Throw "$(Get-Date) [INFO] Task $($taskDetails.meta_request.method_name) failed with the following status and error code : $($taskDetails.progress_status) : $($taskDetails.meta_response.error_code)"
                    }
                }
            }
            While ($taskDetails.percentage_complete -ne "100")
            
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
        } 
        else 
        {
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.meta_request.method_name) completed successfully!" -ForegroundColor Cyan
        }
    }
    end
    {}
}

Function Get-PrismCentralTaskStatus
{
    <#
.SYNOPSIS
Retrieves the status of a given task uuid from Prism and loops until it is completed.

.DESCRIPTION
Retrieves the status of a given task uuid from Prism and loops until it is completed.

.PARAMETER Task
Prism task uuid.

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Get-PrismCentralTaskStatus -Task $task -cluster $cluster -credential $prismCredentials
Prints progress on task $task until successfull completion. If the task fails, print the status and error code and details and exits.

.LINK
https://github.com/sbourdeaud
#>
[CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

    param
    (
        [Parameter(Mandatory)]
        $task,
        
        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $credential,

        [parameter(mandatory = $true)]
        [String]
        $cluster
    )

    begin
    {
        $url = "https://$($cluster):9440/api/nutanix/v3/tasks/$task"
        $method = "GET"
    }
    process 
    {
        #region get initial task details
            Write-Host "$(Get-Date) [INFO] Retrieving details of task $task..." -ForegroundColor Green
            $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
            Write-Host "$(Get-Date) [SUCCESS] Retrieved details of task $task" -ForegroundColor Cyan
        #endregion

        if ($taskDetails.percentage_complete -ne "100") 
        {
            Do 
            {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Sleep 5
                $taskDetails = Invoke-PrismAPICall -method $method -url $url -credential $credential
                
                if ($taskDetails.status -ne "running") 
                {
                    if ($taskDetails.status -ne "succeeded") 
                    {
                        Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.operation_type) failed with the following status and error code : $($taskDetails.status) : $($taskDetails.progress_message)" -ForegroundColor Yellow
                    }
                }
            }
            While ($taskDetails.percentage_complete -ne "100")
            
            New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
            Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.operation_type) completed successfully!" -ForegroundColor Cyan
        } 
        else 
        {
            if ($taskDetails.status -ne "succeeded") {
                Write-Host "$(Get-Date) [WARNING] Task $($taskDetails.operation_type) status is $($taskDetails.status): $($taskDetails.progress_message)" -ForegroundColor Yellow
            } else {
                New-PercentageBar -Percent $taskDetails.percentage_complete -DrawBar -Length 100 -BarView AdvancedThin2; "`r"
                Write-Host "$(Get-Date) [SUCCESS] Task $($taskDetails.operation_type) completed successfully!" -ForegroundColor Cyan
            }
        }
    }
    end
    {
        return $taskDetails.status
    }
}
#endregion

#region credentials
#this function is used to create saved credentials for the current user
function Set-CustomCredentials 
{
#input: path, credname
	#output: saved credentials file
<#
.SYNOPSIS
  Creates a saved credential file using DAPI for the current user on the local machine.
.DESCRIPTION
  This function is used to create a saved credential file using DAPI for the current user on the local machine.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER path
  Specifies the custom path where to save the credential file. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
.PARAMETER credname
  Specifies the credential file name.
.EXAMPLE
.\Set-CustomCredentials -path c:\creds -credname prism-apiuser
Will prompt for user credentials and create a file called prism-apiuser.txt in c:\creds
#>
	param
	(
		[parameter(mandatory = $false)]
        [string] 
        $path,
		
        [parameter(mandatory = $true)]
        [string] 
        $credname
	)

    begin
    {
        if (!$path)
        {
            if ($IsLinux -or $IsMacOS) 
            {
                $path = $home
            }
            else 
            {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(get-date) [INFO] Set path to $path" -ForegroundColor Green
        } 
    }
    process
    {
        #prompt for credentials
        $credentialsFilePath = "$path\$credname.txt"
		$credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
		
		#put details in hashed format
		$user = $credentials.UserName
		$securePassword = $credentials.Password
        
        #convert secureString to text
        try 
        {
            $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
        }
        catch 
        {
            throw "$(get-date) [ERROR] Could not convert password : $($_.Exception.Message)"
        }

        #create directory to store creds if it does not already exist
        if(!(Test-Path $path))
		{
            try 
            {
                $result = New-Item -type Directory $path -ErrorAction Stop
            } 
            catch 
            {
                throw "$(get-date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
            }
		}

        #save creds to file
        try 
        {
            Set-Content $credentialsFilePath $user -ErrorAction Stop
        } 
        catch 
        {
            throw "$(get-date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
        }
        try 
        {
            Add-Content $credentialsFilePath $password -ErrorAction Stop
        } 
        catch 
        {
            throw "$(get-date) [ERROR] Could not write password to $credentialsFilePath : $($_.Exception.Message)"
        }

        Write-Host "$(get-date) [SUCCESS] Saved credentials to $credentialsFilePath" -ForegroundColor Cyan                
    }
    end
    {}
}

#this function is used to retrieve saved credentials for the current user
function Get-CustomCredentials 
{
#input: path, credname
	#output: credential object
<#
.SYNOPSIS
  Retrieves saved credential file using DAPI for the current user on the local machine.
.DESCRIPTION
  This function is used to retrieve a saved credential file using DAPI for the current user on the local machine.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER path
  Specifies the custom path where the credential file is. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
.PARAMETER credname
  Specifies the credential file name.
.EXAMPLE
.\Get-CustomCredentials -path c:\creds -credname prism-apiuser
Will retrieve credentials from the file called prism-apiuser.txt in c:\creds
#>
	param
	(
        [parameter(mandatory = $false)]
		[string] 
        $path,
		
        [parameter(mandatory = $true)]
        [string] 
        $credname
	)

    begin
    {
        if (!$path)
        {
            if ($IsLinux -or $IsMacOS) 
            {
                $path = $home
            }
            else 
            {
                $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            }
            Write-Host "$(get-date) [INFO] Retrieving credentials from $path" -ForegroundColor Green
        } 
    }
    process
    {
        $credentialsFilePath = "$path\$credname.txt"
        if(!(Test-Path $credentialsFilePath))
	    {
            throw "$(get-date) [ERROR] Could not access file $credentialsFilePath : $($_.Exception.Message)"
        }

        $credFile = Get-Content $credentialsFilePath
		$user = $credFile[0]
		$securePassword = $credFile[1] | ConvertTo-SecureString

        $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

        Write-Host "$(get-date) [SUCCESS] Returning credentials from $credentialsFilePath" -ForegroundColor Cyan 
    }
    end
    {
        return $customCredentials
    }
}

#endregion

#region misc
#this function is used to prompt the user for a yes/no/skip response in order to control the workflow of a script
function Write-CustomPrompt 
{
<#
.SYNOPSIS
Creates a user prompt with a yes/no/skip response. Returns the response.

.DESCRIPTION
Creates a user prompt with a yes/no/skip response. Returns the response in lowercase. Valid responses are "y" for yes, "n" for no, "s" for skip.

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Write-CustomPrompt
Creates the prompt.

.LINK
https://github.com/sbourdeaud
#>
[CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

param 
(
    [Switch]$skip
)

begin 
{
    [String]$userChoice = "" #initialize our returned variable
}
process 
{
    if ($skip)
    {
        do {$userChoice = Read-Host -Prompt "Do you want to continue? (Y[es]/N[o]/S[kip])"} #display the user prompt
        while ($userChoice -notmatch '[ynsYNS]') #loop until the user input is valid
    }
    else 
    {
        do {$userChoice = Read-Host -Prompt "Do you want to continue? (Y[es]/N[o])"} #display the user prompt
        while ($userChoice -notmatch '[ynYN]') #loop until the user input is valid
    }
    $userChoice = $userChoice.ToLower() #change to lowercase
}
end 
{
    return $userChoice
}

} #end Write-CustomPrompt function

Function Write-Menu
{
	
<#
.SYNOPSIS
	Display custom menu in the PowerShell console.
.DESCRIPTION
	The Write-Menu cmdlet creates numbered and colored menues
	in the PS console window and returns the choiced entry.
.PARAMETER Menu
	Menu entries.
.PARAMETER PropertyToShow
	If your menu entries are objects and not the strings
	this is property to show as entry.
.PARAMETER Prompt
	User prompt at the end of the menu.
.PARAMETER Header
	Menu title (optional).
.PARAMETER Shift
	Quantity of <TAB> keys to shift the menu items right.
.PARAMETER TextColor
	Menu text color.
.PARAMETER HeaderColor
	Menu title color.
.PARAMETER AddExit
	Add 'Exit' as very last entry.
.EXAMPLE
	PS C:\> Write-Menu -Menu "Open","Close","Save" -AddExit -Shift 1
	Simple manual menu with 'Exit' entry and 'one-tab' shift.
.EXAMPLE
	PS C:\> Write-Menu -Menu (Get-ChildItem 'C:\Windows\') -Header "`t`t-- File list --`n" -Prompt 'Select any file'
	Folder content dynamic menu with the header and custom prompt.
.EXAMPLE
	PS C:\> Write-Menu -Menu (Get-Service) -Header ":: Services list ::`n" -Prompt 'Select any service' -PropertyToShow DisplayName
	Display local services menu with custom property 'DisplayName'.
.EXAMPLE
	PS C:\> Write-Menu -Menu (Get-Process |select *) -PropertyToShow ProcessName |fl
	Display full info about choicen process.
.INPUTS
	Any type of data (object(s), string(s), number(s), etc).
.OUTPUTS
	[The same type as input object] Single menu item.
.NOTES
	Author      :: Roman Gelman @rgelman75
	Version 1.0 :: 21-Apr-2016 :: [Release] :: Publicly available
	Version 1.1 :: 03-Nov-2016 :: [Change] :: Supports a single item as menu entry
	Version 1.2 :: 22-Jun-2017 :: [Change] :: Throws an error if property, specified by -PropertyToShow does not exist. Code optimization
	Version 1.3 :: 27-Sep-2017 :: [Bugfix] :: Fixed throwing an error while menu entries are numeric values
.LINK
	https://ps1code.com/2016/04/21/write-menu-powershell
#>
	
	[CmdletBinding()]
	[Alias("menu")]
	Param (
		[Parameter(Mandatory, Position = 0)]
		[Alias("MenuEntry", "List")]
		$Menu
		 ,
		[Parameter(Mandatory = $false, Position = 1)]
		[string]$PropertyToShow = 'Name'
		 ,
		[Parameter(Mandatory = $false, Position = 2)]
		[ValidateNotNullorEmpty()]
		[string]$Prompt = 'Pick a choice'
		 ,
		[Parameter(Mandatory = $false, Position = 3)]
		[Alias("Title")]
		[string]$Header = ''
		 ,
		[Parameter(Mandatory = $false, Position = 4)]
		[ValidateRange(0, 5)]
		[Alias("Tab", "MenuShift")]
		[int]$Shift = 0
		 ,
		[Parameter(Mandatory = $false, Position = 5)]
		[Alias("Color", "MenuColor")]
		[System.ConsoleColor]$TextColor = 'White'
		 ,
		[Parameter(Mandatory = $false, Position = 6)]
		[System.ConsoleColor]$HeaderColor = 'Yellow'
		 ,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Alias("Exit", "AllowExit")]
		[switch]$AddExit
	)
	
	Begin
	{
		$ErrorActionPreference = 'Stop'
		if ($Menu -isnot [array]) { $Menu = @($Menu) }
		if ($Menu[0] -is [psobject] -and $Menu[0] -isnot [string])
		{
			if (!($Menu | Get-Member -MemberType Property, NoteProperty -Name $PropertyToShow)) { Throw "Property [$PropertyToShow] does not exist" }
		}
		$MaxLength = if ($AddExit) { 8 }
		else { 9 }
		$AddZero = if ($Menu.Length -gt $MaxLength) { $true }
		else { $false }
		[hashtable]$htMenu = @{ }
	}
	Process
	{
		### Write menu header ###
		if ($Header -ne '') { Write-Host $Header -ForegroundColor $HeaderColor }
		
		### Create shift prefix ###
		if ($Shift -gt 0) { $Prefix = [string]"`t" * $Shift }
		
		### Build menu hash table ###
		for ($i = 1; $i -le $Menu.Length; $i++)
		{
			$Key = if ($AddZero)
			{
				$lz = if ($AddExit) { ([string]($Menu.Length + 1)).Length - ([string]$i).Length }
				else { ([string]$Menu.Length).Length - ([string]$i).Length }
				"0" * $lz + "$i"
			}
			else
			{
				"$i"
			}
			
			$htMenu.Add($Key, $Menu[$i - 1])
			
			if ($Menu[$i] -isnot 'string' -and ($Menu[$i - 1].$PropertyToShow))
			{
				Write-Host "$Prefix[$Key] $($Menu[$i - 1].$PropertyToShow)" -ForegroundColor $TextColor
			}
			else
			{
				Write-Host "$Prefix[$Key] $($Menu[$i - 1])" -ForegroundColor $TextColor
			}
		}
		
		### Add 'Exit' row ###
		if ($AddExit)
		{
			[string]$Key = $Menu.Length + 1
			$htMenu.Add($Key, "Exit")
			Write-Host "$Prefix[$Key] Exit" -ForegroundColor $TextColor
		}
		
		### Pick a choice ###
		Do
		{
			$Choice = Read-Host -Prompt $Prompt
			$KeyChoice = if ($AddZero)
			{
				$lz = if ($AddExit) { ([string]($Menu.Length + 1)).Length - $Choice.Length }
				else { ([string]$Menu.Length).Length - $Choice.Length }
				if ($lz -gt 0) { "0" * $lz + "$Choice" }
				else { $Choice }
			}
			else
			{
				$Choice
			}
		}
		Until ($htMenu.ContainsKey($KeyChoice))
	}
	End
	{
		return $htMenu.get_Item($KeyChoice)
	}
	
} #EndFunction Write-Menu
#endregion

#region posh and dotnet configuration
#this function is used to make sure we use the proper Tls version (1.2 only required for connection to Prism)
function Set-PoshTls
{
<#
.SYNOPSIS
Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

.DESCRIPTION
Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Set-PoshTls
Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

.LINK
https://github.com/sbourdeaud
#>
[CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

    param 
    (
        
    )

    begin 
    {
    }

    process
    {
        Write-Host "$(Get-Date) [INFO] Adding Tls12 support" -ForegroundColor Green
        [Net.ServicePointManager]::SecurityProtocol = `
        ([Net.ServicePointManager]::SecurityProtocol -bor `
        [Net.SecurityProtocolType]::Tls12)
    }

    end
    {

    }
}

#this function is used to configure posh to ignore invalid ssl certificates
function Set-PoSHSSLCerts
{
<#
.SYNOPSIS
Configures PoSH to ignore invalid SSL certificates when doing Invoke-RestMethod
.DESCRIPTION
Configures PoSH to ignore invalid SSL certificates when doing Invoke-RestMethod
#>
    begin
    {

    }#endbegin
    process
    {
        Write-Host "$(Get-Date) [INFO] Ignoring invalid certificates" -ForegroundColor Green
        if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
            $certCallback = @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class ServerCertificateValidationCallback
{
    public static void Ignore()
    {
        if(ServicePointManager.ServerCertificateValidationCallback ==null)
        {
            ServicePointManager.ServerCertificateValidationCallback += 
                delegate
                (
                    Object obj, 
                    X509Certificate certificate, 
                    X509Chain chain, 
                    SslPolicyErrors errors
                )
                {
                    return true;
                };
        }
    }
}
"@
            Add-Type $certCallback
        }#endif
        [ServerCertificateValidationCallback]::Ignore()
    }#endprocess
    end
    {

    }#endend
}#end function Set-PoSHSSLCerts
#endregion

#region vmware
#this function is used to load PowerCLI
function Get-PowerCLIModule
{
<#
.SYNOPSIS
Makes sure we use the VMware.PowerCLI version 10 or above is installed and loaded.

.DESCRIPTION
Installs VMware.PowerCLI module and loads it. Configures PowerCLI to accept invalid SSL certificates.

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Get-PowerCLIModule
Installs VMware.PowerCLI module and loads it. Configures PowerCLI to accept invalid SSL certificates.

.LINK
https://github.com/sbourdeaud
#>
[CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

    param
    (

    )

    begin
    {

    }

    process
    {
        if (!(Get-Module VMware.PowerCLI)) 
        {#module isn't loaded
            try 
            {#load
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Loading VMware.PowerCLI module..."
                Import-Module VMware.VimAutomation.Core -ErrorAction Stop
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Loaded VMware.PowerCLI module"
            }
            catch 
            {#couldn't load
                Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Could not load VMware.PowerCLI module!"
                try 
                {#install
                    Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Installing VMware.PowerCLI module..."
                    Install-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Installed VMware.PowerCLI module"
                    try 
                    {#load
                        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Loading VMware.PowerCLI module..."
                        Import-Module VMware.VimAutomation.Core -ErrorAction Stop
                        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Loaded VMware.PowerCLI module"
                    }
                    catch 
                    {#couldn't load
                        Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not load the VMware.PowerCLI module : $($_.Exception.Message)"
                        Exit
                    }
                }
                catch 
                {#couldn't install
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not install the VMware.PowerCLI module. Install it manually from https://www.powershellgallery.com/items?q=powercli&x=0&y=0 : $($_.Exception.Message)"
                    Exit
                }
            }
        }

        #check PowerCLI version
        if ((Get-Module -Name VMware.VimAutomation.Core).Version.Major -lt 10) 
        {#check version
            try 
            {#update
                Update-Module -Name VMware.PowerCLI -Scope CurrentUser -ErrorAction Stop
            } 
            catch 
            {#couldn't update
                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not update the VMware.PowerCLI module : $($_.Exception.Message)"
                Exit
            }
        }
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Setting the PowerCLI configuration to ignore invalid certificates..."
        try 
        {#configure ssl
            $result = Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction Stop
        }
        catch 
        {#couldn't configure ssl
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not change the VMware.PowerCLI module configuration: $($_.Exception.Message)"
            exit
        }
        Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Successfully configured the PowerCLI configuration to ignore invalid certificates"
    }

    end
    {

    }
}

#this function is used to run an hv query
function Invoke-HvQuery
{
	#input: QueryType (see https://vdc-repo.vmware.com/vmwb-repository/dcr-public/f004a27f-6843-4efb-9177-fa2e04fda984/5db23088-04c6-41be-9f6d-c293201ceaa9/doc/index-queries.html), ViewAPI service object
	#output: query results
<#
.SYNOPSIS
  Runs a Horizon View query.
.DESCRIPTION
  Runs a Horizon View query. Processes all queries as a single page (with 1000 records max), except for ADUserOrGroupSummaryView which is paginated.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER QueryType
  Type of query (see https://vdc-repo.vmware.com/vmwb-repository/dcr-public/f004a27f-6843-4efb-9177-fa2e04fda984/5db23088-04c6-41be-9f6d-c293201ceaa9/doc/index-queries.html)
.PARAMETER ViewAPIObject
  View API service object.
.EXAMPLE
.\Invoke-HvQuery -QueryType PersistentDiskInfo -ViewAPIObject $ViewAPI
#>
	[CmdletBinding()]
	param
	(
        [string]
        [ValidateSet('ADUserOrGroupSummaryView','ApplicationIconInfo','ApplicationInfo','DesktopSummaryView','EntitledUserOrGroupGlobalSummaryView','EntitledUserOrGroupLocalSummaryView','FarmHealthInfo','FarmSummaryView','GlobalEntitlementSummaryView','MachineNamesView','MachineSummaryView','PersistentDiskInfo','PodAssignmentInfo','RDSServerInfo','RDSServerSummaryView','RegisteredPhysicalMachineInfo','SessionGlobalSummaryView','SessionLocalSummaryView','TaskInfo','UserHomeSiteInfo')]
        $QueryType,
        [VMware.Hv.Services]
        $ViewAPIObject
	)

    begin
    {

    }

    process
    {
	    $serviceQuery = New-Object "Vmware.Hv.QueryServiceService"
        $query = New-Object "Vmware.Hv.QueryDefinition"
        $query.queryEntityType = $QueryType
        $query.MaxPageSize = 5000
        if ($query.QueryEntityType -eq 'PersistentDiskInfo') 
        {#add filter for PersistentDiskInfo query
            $query.Filter = New-Object VMware.Hv.QueryFilterNotEquals -property @{'memberName'='storage.virtualCenter'; 'value' =$null}
        }
        if (($query.QueryEntityType -eq 'ADUserOrGroupSummaryView') -or ($query.QueryEntityType -eq 'MachineSummaryView')) 
        {#get AD or machine information in multiple pages
            $paginatedResults = @() #we use this variable to save all pages of results
            try 
            {#run the query and process the results using pagination
                $object = $serviceQuery.QueryService_Create($ViewAPIObject,$query)
                try 
                {#paginate
                    while ($object.results -ne $null)
                    {#we still have data in there
                        $paginatedResults += $object.results

                        if ($object.id -eq $null)
                        {#no more pages of results
                            break
                        }
                        #fetching the next page of results
                        $object = $serviceQuery.QueryService_GetNext($ViewAPIObject,$object.id)
                    }
                }
                Finally
                {#delete the paginated query on the server to save resources and avoid the 5 query limit
                    if ($object.id -ne $null)
                    {#make sure this was the last page
                        $serviceQuery.QueryService_Delete($ViewAPIObject,$object.id)
                    }
                }
            }
            catch 
            {#query failed
                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "$($_.Exception.Message)"
                exit
            }
        } 
        else 
        {#get all other type of information using a single list limited to $query.MaxPageSize (or related server setting)
            try 
            {#run the query
                $object = $serviceQuery.QueryService_Query($ViewAPIObject,$query)
            }
            catch 
            {#query failed
                Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "$($_.Exception.Message)"
                exit
            }
        }

        if (!$object) 
        {
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "The View API query did not return any data... Exiting!"
            Exit
        }
    }

    end
    {
        if (($query.QueryEntityType -eq 'ADUserOrGroupSummaryView') -or ($query.QueryEntityType -eq 'MachineSummaryView')) 
        {#we ran an AD query so we probably have paginated results to return
            return $paginatedResults
        }
        else
        {#we ran a single page query so let's return that
            return $object.results
        }
    }
}#end function Invoke-HvQuery
#endregion

#endregion

New-Alias -Name Get-PrismRESTCall -value Invoke-PrismAPICall -Description "Invoke Nutanix Prism REST call."
New-Alias -Name Invoke-PrismRESTCall -value Invoke-PrismAPICall -Description "Invoke Nutanix Prism REST API call."
