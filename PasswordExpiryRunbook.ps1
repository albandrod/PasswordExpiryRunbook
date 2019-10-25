#Requires -Modules AzureRm
#Requires -Modules MSOnline
<#
.SYNOPSIS 
    Check Password Expiry for Users in AzureAD.

.DESCRIPTION
    This runbook checks the Password Expiry Date for user accounts in AzureAD and produces a CSV file indicating which users
    will need to reset their password within:
     - 7 Days
     - 3 Days 
     - 1 Day

    In addition to this runbook, you will need an OrgID credential with access to your Azure subscription
    (http://azure.microsoft.com/blog/2014/08/27/azure-automation-authenticating-to-azure-using-azure-active-directory/)
    stored in a credential asset.

	When using this runbook, be aware that the memory and disk space size of the processes running your
	runbooks is limited. Because of this, we recommened only using runbooks to transfer small files.
	All Automation Integration Module assets in your account are loaded into your processes,
	so be aware that the more Integration Modules you have in your system, the smaller the free space in
	your processes will be. To ensure maximum disk space in your processes, make sure to clean up any local
	files a runbook transfers or creates in the process before the runbook completes.

.PARAMETER AzureConnectionName 
    Name of the Azure Automation Connection asset configured on the Automation Account
     
.PARAMETER StorageAccountName 
    The name of a Storage Account to store or retrieve data 
 
.PARAMETER BlobName 
    The name of a Blob (Filename) to containing data 

.PARAMETER ExportContainer 
    The name of a Container in a Storage Account to export the Blob too.

.PARAMETER ExportContainer 
    The name of a Container in a Storage Account to export the Blob too. Default is export

.PARAMETER PathToPlaceBlob 
    The path within the Automation Account to temporarily store the Blob prior to import export to a Storage Account.

.Example
    $params = @{
        AzureConnectionName = "conn_spn_passwordexpiry"
        StorageAccountName = "stppasswordexpiry1"
        BlobName = "password_expiry.txt"
    }

    Test-PasswordExpirty @params
#>
param
(
    [Parameter(Mandatory = $true)]
    [String]$AzureConnectionName,
    
    [Parameter(Mandatory = $true)]
    [String]$AzureADGroup,

    [parameter(Mandatory=$true)]
    [String] $StorageAccountName,

    [parameter(Mandatory=$true)]
    [String] $BlobName,

    [parameter(Mandatory=$false)]
    [String] $ExportContainer = "export",

    [parameter(Mandatory=$false)]
    [String] $PathToPlaceBlob = "$($env:TEMP)"
)

#region Functions
Function Test-SelfService
{
	Param
	(
		[object]$User,
		[bool]$Default = $false
	)
	
	If ($User.StrongAuthenticationUserDetails.email -or $User.StrongAuthenticationUserDetails.PhoneNumber)
	{
        # Transforming Phone number (mobile) to send email via SMS gateway
        $phone = $User.StrongAuthenticationUserDetails.PhoneNumber

        if (-Not [string]::IsNullOrEmpty($phone))
        {
            $phone = $phone.replace('+', '')
            $phone = $phone.replace(' ', '')
            $phone = $phone + "@marketing.sms.whispir.it"
        }
        
        Switch ($Default)
		{
			$true 
            { 
                $result = @{
                    message = "SSPR Registered - do nothing"
                    email = $User.StrongAuthenticationUserDetails.email
                    phone = $phone
                } 
            }
			$false 
            { 
                $result = @{
                    message = "SSPR Registered - goto https://aka.ms/sspr"
                    email = $User.StrongAuthenticationUserDetails.email
                    phone = $phone
                }
            }
		}
	} else
	{
		$result = @{
            message = "SSPR Not Registered - do nothing"
            email = ""
            phone =""
        }
	}

    return $result
}
#endregion

#region Variables and Setup
$expiryDays = 90
$ErrorActionPreference =  "Continue"
$version = "0.01.24102019";
Write-Output " Script Version: $($version)"
#endregion

#region Main Code
try
{  
    Write-Output '', " Getting the connection 'AzureRunAsConnection'..."
    $servicePrincipalConnection = Get-AutomationConnection -Name $AzureConnectionName
    $environment = Get-AzureRmEnvironment -Name AzureCloud
    
    Write-Output '', " Logging in to Azure AD..."
    Import-Module -Name MSOnline
    $creds = Get-AutomationPSCredential -Name 'AzureADConnectSyncAccount'
    Connect-MsolService -Credential $creds

    Write-Output '', " Logging in to Azure..."
    $Context = Login-AzureRmAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint `
        -Environment $environment

    Write-Output '', " Getting the Storage Account Context..."
    $StorageAccount = Get-AzureRmStorageAccount | Where-Object StorageAccountName -eq $StorageAccountName
    $AccessKey = (Get-AzureRmStorageAccountKey -Name $StorageAccount.StorageAccountName -ResourceGroupName $StorageAccount.ResourceGroupName | Select -First 1).Value 
    $StorageContext = New-AzureStorageContext -StorageAccountName $StorageAccount.StorageAccountName -StorageAccountKey $AccessKey
    Write-Output " SUCCESS! Got Storage Account Context!"

    Write-output "`r`n Getting Users from Azure AD....."    
    $Group = Get-MsolGroup -SearchString $AzureADGroup
    $Results = @()

    foreach ($member in Get-MsolGroupMember -GroupObjectId $Group.ObjectId -All)
    {
        $user = Get-MsolUser -ObjectId $member.ObjectId
        $pwdLastSet = Get-Date $user.LastPasswordChangeTimestamp
        $expiry = $pwdLastSet.AddDays($expiryDays)
        $dateNow = Get-Date
        $sevenDayWarnDate = $dateNow.AddDays(7)
        $threeDayWarnDate = $dateNow.AddDays(3)
        $oneDayWarnDate = $dateNow.AddDays(1)
        
        Switch ($Expiry)
        {
            {$_ -le $dateNow} {$result = "has expired"; $test = Test-SelfService -User $user; Break }
            {$_ -le $oneDayWarnDate} { $result = "will expire in 1 Day!"; $test = Test-SelfService -User $user; Break }
            {$_ -le $threeDayWarnDate} { $result = "will expire in 3 Days!"; $test = Test-SelfService -User $user; Break }
            {$_ -le $sevenDayWarnDate} { $result = "will expire in 7 Days!"; $test = Test-SelfService -User $user; Break}
            Default { $result = "is OK"; $test = Test-SelfService -User $user -Default $true; Break }
        }
        
        if ($result -like "*expire*")
        {
            Write-Output " User: $($User.UserPrincipalName)"
            Write-Output " Result: $($result)"
            Write-Output " Message: $($test.message)"
            If ($test.email) {Write-Output " Email: $($test.email)"; $email = $test.email } else { $email = "" }
            If ($test.phone) {Write-Output " Phone: $($test.phone)"; $phone = $test.phone } else { $phone = "" }
            Write-Output ""
            
            if ($email -or $phone)
            {
                $tmp = New-Object PSObject -Property @{
                    user = $user.UserPrincipalName
                    displayName = $user.displayName
                    firstName = $user.firstName
                    lastName = $user.lastName
                    result = $result
                    email = $email
                    phone = $phone
                }

                $Results += $tmp
            }
        }        
    }

    if ($Results)
    {
        $Results | ConvertTo-Json | Out-File -FilePath "$($PathToPlaceBlob)\$($BlobName)" -Force
            
        Write-Output '', " Writing '$($BlobName)' to Azure Blob Storage..."
        $Blob = Set-AzureStorageBlobContent `
            -Blob $BlobName `
            -Container $ExportContainer `
            -File "$($PathToPlaceBlob)\$($BlobName)" `
            -Context $StorageContext `
            -Force
        Write-Output " SUCCESS! Wrote '$($BlobName)' to Azure Blob Storage!"
    } else 
    {
        Write-Output " WARNING! Nothing to Export!"
    }
} catch
{
    if($_.Exception.Message)
    { Write-Error -Message "$($_.Exception.Message)" -ErrorAction Continue } else
    { Write-Error -Message "$($_.Exception)" -ErrorAction Continue }
        
	throw "$($_.Exception)"
} finally
{ Write-Output '', " Runbook ended at time: $(get-Date -format r)" }
#endregion
