#region functions

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
        [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS')]
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
	    }

	    Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
	    if ($LogFile) #add the entry to the log file if -LogFile has been specified
        {
            Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
            Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
        }
    }

}#end function Write-LogOutput

#this function is used to connect to Prism REST API
function Invoke-PrismRESTCall
{
	#input: username, password, url, method, body
	#output: REST response
<#
.SYNOPSIS
  Connects to Nutanix Prism REST API.
.DESCRIPTION
  This function is used to connect to Prism REST API.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER username
  Specifies the Prism username.
.PARAMETER password
  Specifies the Prism password.
.PARAMETER url
  Specifies the Prism url.
.EXAMPLE
  PS> PrismRESTCall -username admin -password admin -url https://10.10.10.10:9440/PrismGateway/services/rest/v1/ 
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
        [ValidateSet('GET','PATCH','PUT','POST','DELETE')]
        $method,
        
        $body
	)

    begin
    {
	 	#Setup authentication header for REST call
        $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}   
    }

    process
    {
        if ($body) 
        {
            $myvarHeader += @{"Accept"="application/json"}
		    $myvarHeader += @{"Content-Type"="application/json"}
            
            if ($IsLinux) 
            {
                try 
                {
                    if ($PSVersionTable.PSVersion.Major -ge 6) 
                    {
			            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
                    } 
                    else 
                    {
                        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop
                    }
		        }
                catch 
                {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try 
                    {
                        $RESTError = Get-RESTError -ErrorAction Stop
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
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -ErrorAction Stop
		        }
                catch 
                {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try 
                    {
                        $RESTError = Get-RESTError -ErrorAction Stop
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
        else 
        {
            if ($IsLinux) 
            {
                try 
                {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -SkipCertificateCheck -ErrorAction Stop
		        }
                catch 
                {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try 
                    {
                        $RESTError = Get-RESTError -ErrorAction Stop
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
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
		        }
                catch 
                {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try 
                    {
                        $RESTError = Get-RESTError -ErrorAction Stop
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
    }

    end
    {
        return $myvarRESTOutput
    }
}#end function Get-PrismRESTCall

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
                    $RESTError = Get-RESTError -ErrorAction Stop
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
                    $RESTError = Get-RESTError -ErrorAction Stop
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

#function Get-RESTError
function Get-RESTError 
{
    $global:helpme = $body
    $global:helpmoref = $moref
    $global:result = $_.Exception.Response.GetResponseStream()
    $global:reader = New-Object System.IO.StreamReader($global:result)
    $global:responseBody = $global:reader.ReadToEnd();

    return $global:responsebody

    break
}#end function Get-RESTError

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
            $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
            Write-Host "$(get-date) [INFO] Set path to $path" -ForegroundColor Green
        } 
    }
    process
    {
        #prompt for credentials
        $credentialsFilePath = "$path\$credname.txt"
		$credentials = Get-Credential -Message "Enter the credentials to save in $Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials\$credname.txt"
		
		#put details in hashed format
		$user = $credentials.UserName
		$securePassword = $credentials.Password
        
        #convert secureString to text
        $password = $securePassword | ConvertFrom-SecureString

        #create directory to store creds if it does not already exist
        if(!(Test-Path $path))
		{
            try 
            {
                $result = New-Item -type Directory $path
            } 
            catch 
            {
                throw "$(get-date) [ERROR] Could not create directory $path : $($_.Exception.Message)"
            }
		}

        #save creds to file
        try 
        {
            Set-Content $credentialsFilePath $user
        } 
        catch 
        {
            throw "$(get-date) [ERROR] Could not write username to $credentialsFilePath : $($_.Exception.Message)"
        }
        try 
        {
            Add-Content $credentialsFilePath $password
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
            $path = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
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

#this function is used to make sure we use the proper Tls version (1.2 only required for connection to Prism)
function Set-PoshTls
{
<#
.SYNOPSIS
Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

.DESCRIPTION
Installs BetterTls module and loads it. Disables Tls and enables Tls 1.2.

.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

.EXAMPLE
.\Set-PoshTls
Installs BetterTls module and loads it. Disables Tls and enables Tls 1.2.

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
        if (!(Get-Module -Name BetterTls)) 
        {#module isn't laoded
            Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Importing module 'BetterTls'..."
            try
            {#let's try to load it
                Import-Module -Name BetterTls -ErrorAction Stop
                Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Imported module 'BetterTls'!"
            }
            catch 
            {#we couldn't import the module, so let's install it
                Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Installing module 'BetterTls' from the Powershell Gallery..."
                try 
                {#install
                    Install-Module -Name BetterTls -Scope CurrentUser -ErrorAction Stop
                }
                catch 
                {#couldn't install
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not install module 'BetterTls': $($_.Exception.Message)"
                    exit
                }

                try
                {#import module
                    Import-Module -Name BetterTls -ErrorAction Stop
                    Write-LogOutput -Category "SUCCESS" -LogFile $myvarOutputLogFile -Message "Imported module 'BetterTls'!"
                }
                catch 
                {#we couldn't import the module
                    Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Unable to import the module BetterTls : $($_.Exception.Message)"
                    Write-LogOutput -Category "WARNING" -LogFile $myvarOutputLogFile -Message "Please download and install from https://www.powershellgallery.com/packages/BetterTls/0.1.0.0"
                    Exit
                }
            }#end catch
        }
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Disabling Tls..."
        try 
        {#disable old tls protocol
            Disable-Tls -Tls -Confirm:$false -ErrorAction Stop
        } 
        catch 
        {#couldn't disable old tls protocol
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not disable Tls : $($_.Exception.Message)"
            Exit
        }
        Write-LogOutput -Category "INFO" -LogFile $myvarOutputLogFile -Message "Enabling Tls 1.2..."
        try 
        {#enable tls12
            Enable-Tls -Tls12 -Confirm:$false -ErrorAction Stop
        } 
        catch 
        {#couldn't enable tls12
            Write-LogOutput -Category "ERROR" -LogFile $myvarOutputLogFile -Message "Could not enable Tls 1.2 : $($_.Exception.Message)"
            Exit
        }
    }

    end
    {

    }
}

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

#endregion

New-Alias -Name Get-PrismRESTCall -value Invoke-PrismRESTCall -Description "Invoke Nutanix Prism REST call."
