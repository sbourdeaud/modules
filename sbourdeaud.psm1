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
PS> Write-LogOutput -category "ERROR" -message "You must be kidding!"

Displays an error message.

.LINK
https://github.com/sbourdeaud
#>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

	param
	(
		[Parameter(Mandatory)]
        [ValidateSet('INFO','WARNING','ERROR','SUM')]
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
function Get-PrismRESTCall
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
        if (!$IsLinux) {
            add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
    ServicePoint srvPoint, X509Certificate certificate,
    WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy -ErrorAction SilentlyContinue
        }#endif not Linux

	 	#Setup authentication header for REST call
        $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}   
    }

    process
    {
        if ($body) {
            $myvarHeader += @{"Accept"="application/json"}
		    $myvarHeader += @{"Content-Type"="application/json"}
            
            if ($IsLinux) {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                    }
			        Exit
		        }
            }else {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                    }
			        Exit
		        }
            }
        } else {
            if ($IsLinux) {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -SkipCertificateCheck -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                    }
			        Exit
		        }
            }else {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
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
function Upload-FileToPrism
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
  .\Upload-FileToPrism -username admin -password admin -url https://10.10.10.10:9440/api/nutanix/v0.8/images/$image_uuid/upload -method "PUT" -container_uuid $container_uuid -file /media/backup/vmdisk.qcow2
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
        if (!$IsLinux) {
            add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
    ServicePoint srvPoint, X509Certificate certificate,
    WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy -ErrorAction SilentlyContinue
        }#endif not Linux

	 	#Setup authentication header for REST call
        $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}   
    }

    process
    {
        $myvarHeader += @{"Accept"="*/*"}
		$myvarHeader += @{"Content-Type"="application/octet-stream;charset=UTF-8"}
        $myvarHeader += @{"X-Nutanix-Destination-Container"=$container_uuid}
            
        if ($IsLinux) {
            try {
			    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $file -SkipCertificateCheck -ErrorAction Stop
		    }
		    catch {
			    Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                try {
                    $RESTError = Get-RESTError -ErrorAction Stop
                    $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                    if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                }
                catch {
                    Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                }
			    Exit
		    }
        }else {
            try {
			    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $file -ErrorAction Stop
		    }
		    catch {
			    Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                try {
                    $RESTError = Get-RESTError -ErrorAction Stop
                    $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                    if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                }
                catch {
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
function Get-RESTError {
$global:helpme = $body
$global:helpmoref = $moref
$global:result = $_.Exception.Response.GetResponseStream()
$global:reader = New-Object System.IO.StreamReader($global:result)
$global:responseBody = $global:reader.ReadToEnd();

return $global:responsebody

break
}#end function Get-RESTError

#endregion