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

.PARAMETER AzureCredentialName 
    Name of the Service Account Credentials asset configured on the Automation Account
     
.PARAMETER StorageAccountName 
    The name of a Storage Account to store or retrieve data 
 
.PARAMETER ExportBlobName 
    The name of a Blob (Filename) to containing data to Export

.PARAMETER ImportBlobName 
    The name of a Blob (Filename) to containing data to Import

.PARAMETER ExportContainer 
    The name of a Container in a Storage Account to export the Blob too.

.PARAMETER ImportContainer 
    The name of a Container in a Storage Account to import a Blob. Default is import

.Example
    $params = @{
        AzureConnectionName = "conn_spn_passwordexpiry"
        StorageAccountName = "stppasswordexpiry1"
        ImportBlobName = "data.json"
        ExportBlobName = "password_expiry.txt"
    }

    Test-PasswordExpirty @params
#>
param
(
    [Parameter(Mandatory = $true)]
    [String]$AzureCredentialName,

    [parameter(Mandatory=$true)]
    [String] $StorageAccountName,

    [parameter(Mandatory=$true)]
    [String] $ExportBlobName,

    [parameter(Mandatory=$true)]
    [String] $ImportBlobName,

    [parameter(Mandatory=$false)]
    [String] $ExportContainer = "export",
    
    [parameter(Mandatory=$false)]
    [String] $ImportContainer = "import"
)

#region Variables and Setup
$ErrorActionPreference =  "Continue"
$dateNow = Get-Date
$maxPwdAge = 90
[int32]$In7days= ($dateNow-($dateNow.AddDays(7-$maxPwdAge))).TotalDays
[int32]$30DaysAgo = ($dateNow-($dateNow.AddDays(-$maxPwdAge-30))).TotalDays
$PathToPlaceBlob = $env:TEMP
$regex = "^[a-zA-Z0-9.!£#$%&'^_`{}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$"
$version = "0.01.24102019";
Write-Output " Script Version: $($version)"
#endregion

#region Main Code
try
{     
    Write-Output '', " Logging in to Azure AD..."
    Import-Module -Name MSOnline
    $creds = Get-AutomationPSCredential -Name $AzureCredentialName
    Connect-MsolService -Credential $creds

    Write-Output '', " Logging in to Azure..."
    Add-AzureRmAccount -Identity
    $Context = Get-AzureRmContext

    Write-Output '', " Getting the Storage Account Context..."
    $StorageAccount = Get-AzureRmStorageAccount | Where-Object StorageAccountName -eq $StorageAccountName
    $AccessKey = (Get-AzureRmStorageAccountKey -Name $StorageAccount.StorageAccountName -ResourceGroupName $StorageAccount.ResourceGroupName | Select-Object -First 1).Value 
    $StorageContext = New-AzureStorageContext -StorageAccountName $StorageAccount.StorageAccountName -StorageAccountKey $AccessKey
    Write-Output " SUCCESS! Got Storage Account Context!"

    Write-Output '', " Getting the Storage Account Blob Content..."
    $Blob = Get-AzureStorageBlobContent `
        -Blob $ImportBlobName `
        -Container $ImportContainer `
        -Destination $PathToPlaceBlob `
        -Context $StorageContext `
        -Force
    Write-Output " SUCCESS! Storage Account Blob Content written to '$($PathToPlaceBlob)\$($ImportBlobName)'"

    Write-Output '', " Checking '$($PathToPlaceBlob)\$($ImportBlobName)'..."
    $Item = Get-Item -Path "$($PathToPlaceBlob)\$($ImportBlobName)" -ErrorAction Stop
    Write-Output " SUCCESS! '$($PathToPlaceBlob)\$($ImportBlobName)' exists!"

    Write-output "`r`n Importing Data from Blob....."
    $tmpData1 = $Item | Get-Content
    $tmpData2 = $tmpData1 | ConvertFrom-Json
    $Data = $tmpData2.ResultSets.Table1

    Write-output "`r`n Check Users in Azure AD....."
    $Users = Get-MsolUser -All | Where-Object {$_.LastPasswordChangeTimestamp -and ($_.StrongAuthenticationUserDetails.email -or $_.StrongAuthenticationUserDetails.PhoneNumber)} | Where-Object {[int32]($dateNow-($_.LastPasswordChangeTimestamp)).TotalDays -in $30DaysAgo..$In7days}
    
    $Results = @()
    $count = 0

    foreach ($user in $Users)
    {     
        $count ++

        if ($user.UserPrincipalName -in $Data.InstituteEmailAddress)
        {
            if ($user.StrongAuthenticationUserDetails.PhoneNumber)
            {
                $user.StrongAuthenticationUserDetails.PhoneNumber = $user.StrongAuthenticationUserDetails.PhoneNumber.replace('+', '')
                $user.StrongAuthenticationUserDetails.PhoneNumber = $user.StrongAuthenticationUserDetails.PhoneNumber.replace(' ', '')
                $user.StrongAuthenticationUserDetails.PhoneNumber = $user.StrongAuthenticationUserDetails.PhoneNumber + "@marketing.sms.whispir.it"
            }

            $tmp = New-Object PSObject -Property @{
                user = $user.UserPrincipalName
                displayName = $user.displayName
                firstName = $user.firstName
                lastName = $user.lastName
                result = "has expired or will expire within 7 days!"
                email = $user.StrongAuthenticationUserDetails.email
                phone = $user.StrongAuthenticationUserDetails.PhoneNumber
            }
            
            Write-Output " User: $($tmp.user)"
            Write-Output " Result: $($tmp.result)"
            Write-Output " Email: $($tmp.email)"
            Write-Output " Phone: $($tmp.phone)"
            Write-Output " Count: $($count)"
            Write-Output ""

            $Results += $tmp
        }
    }

    if ($Results)
    {
        $Results | ConvertTo-Json | Out-File -FilePath "$($PathToPlaceBlob)\$($ExportBlobName)" -Force
            
        Write-Output '', " Writing '$($ExportBlobName)' to Azure Blob Storage..."
        $Blob = Set-AzureStorageBlobContent `
            -Blob $ExportBlobName `
            -Container $ExportContainer `
            -File "$($PathToPlaceBlob)\$($ExportBlobName)" `
            -Context $StorageContext `
            -Force
        Write-Output " SUCCESS! Wrote '$($ExportBlobName)' to Azure Blob Storage!"
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
