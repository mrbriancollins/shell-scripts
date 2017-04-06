###############################################
# Copyright Infor (c). All rights reserved.
###############################################

#=============================================================================
#
# PARAMETERS
#

param(
	[switch] $saas = $false,
	[switch] $noConfirm = $false,

	[parameter(mandatory = $true,
		helpmessage = "Connection string for User Management database")]
	[string] $connect_string,
	[switch] $ignoreExtractRule = $false
)


#=============================================================================
#
# GENERAL SET-UP
#

Set-PSDebug -Strict # -Trace 1

trap {
	break
}


#
# Configure the host so it does not wrap at 80 characters.
# Source: http://weblogs.asp.net/soever/archive/2008/12/09/powershell-output-capturing-and-text-wrapping-strange-quirks-solved.aspx
#
$host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(512,200)

#
# Load the ADFS PowerShell snapin.
#
Add-PSSnapin Microsoft.Adfs.Powershell -ErrorAction:SilentlyContinue



##############
# Section for the Infor defined Claim types.
#

function RemoveClaimType ( [string] $c_type)
{
   $cd = Get-ADFSClaimDescription -ClaimType $c_type
   if ( $cd )
   {
      echo "Removing Claim Type: ${c_type}"
      Remove-ADFSClaimDescription -TargetClaimType $c_type
   }
}


function CreateClaimType ( [string] $c_type, [string] $c_name, [string] $c_notes, [boolean] $is_accepted, [boolean] $is_offered)
{
   RemoveClaimType $c_type

   echo "Creating Claim Type: ${c_type}"
   Add-ADFSClaimDescription -ClaimType $c_type -IsAccepted $is_accepted -IsOffered $is_offered -IsRequired $false -Name $c_name -Notes $c_notes
}


function CreateInternalClaimType ( [string] $c_type, [string] $c_name, [string] $c_notes)
{
   CreateClaimType $c_type $c_name $c_notes $false $false
}


function CreateExternalClaimType ( [string] $c_type, [string] $c_name, [string] $c_notes)
{
   CreateClaimType $c_type $c_name $c_notes $true $true
}


function RemoveInforClaimTypes ()
{
   echo "Removing the Infor 'internal' claim types"
   RemoveClaimType "http://schemas.infor.com/claims/customerid"
   RemoveClaimType "http://schemas.infor.com/claims/customername"
   RemoveClaimType "http://schemas.infor.com/claims/userid"
   RemoveClaimType "http://schemas.infor.com/claims/tenantid"
   RemoveClaimType "http://schemas.infor.com/claims/tenantuserid"
   RemoveClaimType "http://schemas.infor.com/claims/securityroleid"
   RemoveClaimType "http://schemas.infor.com/claims/tenantapplicationid"
   RemoveClaimType "http://schemas.infor.com/claims/isifsapplicationadmin"
   RemoveClaimType "http://schemas.infor.com/claims/customerstatus"

   echo "Removing the Infor 'external' claim types"
   RemoveClaimType "http://schemas.infor.com/claims/Customer"
   RemoveClaimType "http://schemas.infor.com/claims/EnvironmentType"
   RemoveClaimType "http://schemas.infor.com/claims/Tenant"
   RemoveClaimType "http://schemas.infor.com/claims/Identity"
   # The '2011/06/Identity' has existed on the trunk for about a week. We leave the remove in to get rid of this incorrect claim.
   #   This remove statement can be dropped in the October 2011 release.
   RemoveClaimType "http://schemas.infor.com/claims/2011/06/Identity"
   RemoveClaimType "http://schemas.infor.com/claims/Identity2"
   RemoveClaimType "http://schemas.infor.com/claims/SecurityRole"
   RemoveClaimType "http://schemas.infor.com/claims/AccountingEntity"
   RemoveClaimType "http://schemas.infor.com/claims/Location"
   RemoveClaimType "http://schemas.infor.com/claims/ApplicationInstance"
   RemoveClaimType "http://schemas.infor.com/claims/EAMTemplate"
   RemoveClaimType "http://schemas.infor.com/claims/HMSTemplate"
   RemoveClaimType "http://schemas.infor.com/claims/IFSAuthenticationMode"

   RemoveClaimType "http://schemas.infor.com/claims/IFSUserLookupValue"

   RemoveClaimType "http://schemas.infor.com/claims/ClientPrincipalName"

   # Claims for Mingle Mobile

   RemoveClaimType "http://schemas.infor.com/claims/MingleUserAccessKey"
   RemoveClaimType "http://schemas.infor.com/claims/MingleUserPrivateKey"

   RemoveClaimType "http://schemas.infor.com/claims/MingleMobileAccessKey"
   RemoveClaimType "http://schemas.infor.com/claims/MingleMobilePrivateKey"
   RemoveClaimType "http://schemas.infor.com/claims/MingleUserGuid"

   RemoveClaimType "http://schemas.infor.com/claims/ExternalUserId"

   RemoveClaimType "http://schemas.infor.com/claims/UserProfilePicture"
   RemoveClaimType "http://schemas.infor.com/claims/CommunityIdentifier"
   RemoveClaimType "http://schemas.infor.com/claims/CommunitiesProfilePage"

   RemoveClaimType "http://schemas.infor.com/claims/ErpPersonId";
}


function CreateInforClaimTypes ()
{
   echo "Creating the Infor internal claim types"
   CreateInternalClaimType "http://schemas.infor.com/claims/customerid" "InforInternalCustomerId" "Intermediate Infor claim to reduce the number of required joins."
   CreateInternalClaimType "http://schemas.infor.com/claims/customername" "InforInternalCustomerName" "Intermediate Infor claim to emit uppercase customer claim."
   CreateInternalClaimType "http://schemas.infor.com/claims/userid" "InforInternalUserId" "Intermediate Infor claim to reduce the number of required joins."
   CreateInternalClaimType "http://schemas.infor.com/claims/tenantid" "InforInternalTenantId" "Intermediate Infor claim to reduce the number of required joins."
   CreateInternalClaimType "http://schemas.infor.com/claims/tenantuserid" "InforInternalTenantUserId" "Intermediate Infor claim to reduce the number of required joins."
   CreateInternalClaimType "http://schemas.infor.com/claims/securityroleid" "InforInternalSecurityRoleId" "Intermediate Infor claim to reduce the number of required joins."
   CreateInternalClaimType "http://schemas.infor.com/claims/tenantapplicationid" "InforInternalTenantApplicationId" "Intermediate Infor claim to reduce the number of required joins."
   CreateInternalClaimType "http://schemas.infor.com/claims/isifsapplicationadmin" "InforInternalIsIFSApplicationAdmin" "Intermediate Infor claim to reduce the number of required joins."
   CreateInternalClaimType "http://schemas.infor.com/claims/customerstatus" "InforInternalCustomerStatus" "Intermediate Infor claim for authorization claim."
   CreateInternalClaimType "http://schemas.infor.com/claims/PreferredLanguage" "PreferredLanguage" "The Preferred Language."

   echo "Creating the Infor external claim types"
   CreateExternalClaimType "http://schemas.infor.com/claims/Customer" "Customer" "The Customer name."
   CreateExternalClaimType "http://schemas.infor.com/claims/EnvironmentType" "EnvironmentType" "Type of environment like PRD, TRN or TST."
   CreateExternalClaimType "http://schemas.infor.com/claims/Tenant" "Tenant" "A tenant a user is entitled for. Contatenation of 'Customer' and 'Environment'."
   CreateExternalClaimType "http://schemas.infor.com/claims/Identity" "Identity" "Claim representing a user identity in the context of an Infor application."
   CreateExternalClaimType "http://schemas.infor.com/claims/Identity2" "Identity2" "Claim representing a user identity (UPN value, multi domain aware) in the context of an Infor application."
   CreateExternalClaimType "http://schemas.infor.com/claims/SecurityRole" "Security Role" "Claim representing a Security Role for an Infor Application."
   CreateExternalClaimType "http://schemas.infor.com/claims/AccountingEntity" "Accounting Entity" "Claim representing an Accounting Entity a user is authorized for."
   CreateExternalClaimType "http://schemas.infor.com/claims/Location" "Location" "Claim representing a Location a user is authorized for."
   CreateExternalClaimType "http://schemas.infor.com/claims/ApplicationInstance" "Authorized Application" "Claim representing an Application Instance a user is authorized for."
   CreateExternalClaimType "http://schemas.infor.com/claims/EAMTemplate" "EAM Template" "The EAM Template is used to auto-provision a user when entering EAM for the very first time."
   CreateExternalClaimType "http://schemas.infor.com/claims/HMSTemplate" "HMS Template" "The HMS Template is used to auto-provision a user when entering HMS for the very first time."
   CreateExternalClaimType "http://schemas.infor.com/claims/IFSAuthenticationMode" "IFS Authentication Mode" "The way the IFS application was authenticated. Via AD FS this value is always 'SAMLToken'."

   CreateExternalClaimType "http://schemas.infor.com/claims/IFSUserLookupValue" "IFS User Lookup Value" "The value being used to lookup an IFS user."

   CreateExternalClaimType "http://schemas.infor.com/claims/ClientPrincipalName" "Client Principal Name" "Client Principal Name as presented in a kerberos ticket."

   echo "Creating the Mingle Mobile App claim types"
   CreateExternalClaimType "http://schemas.infor.com/claims/MingleUserAccessKey" "MingleUserAccessKey" "Mingle User Access Key"
   CreateExternalClaimType "http://schemas.infor.com/claims/MingleUserPrivateKey" "MingleUserPrivateKey" "Mingle User Private Key"

   CreateExternalClaimType "http://schemas.infor.com/claims/MingleMobileAccessKey" "MingleMobileAccessKey" "Mingle Mobile Access Key"
   CreateExternalClaimType "http://schemas.infor.com/claims/MingleMobilePrivateKey" "MingleMobilePrivateKey" "Mingle Mobile Private Key"
   CreateExternalClaimType "http://schemas.infor.com/claims/MingleUserGuid" "MingleUserGuid" "Mingle User Guid"

   CreateExternalClaimType "http://schemas.infor.com/claims/ExternalUserId" "ExternalUserId" "User Identity for External Users"

   CreateExternalClaimType "http://schemas.infor.com/claims/UserProfilePicture" "UserProfilePicture" "User Profile Picture"
   CreateExternalClaimType "http://schemas.infor.com/claims/CommunityIdentifier" "CommunityIdentifier" "Mingle Community Identifier"
   CreateExternalClaimType "http://schemas.infor.com/claims/CommunitiesProfilePage" "CommunitiesProfilePage" "Infor Communities Profile Page"

   CreateExternalClaimType "http://schemas.infor.com/claims/ErpPersonId" "PersonId" "Person Id"
}



##############
# Section for the IFS data store.
#

function RemoveIFSAttributeStore ( [string] $as_name)
{
   $as = Get-ADFSAttributeStore -Name $as_name
   if ( $as )
   {
      echo "Removing attribute store: ${as_name}"
      Remove-ADFSAttributeStore -TargetName $as_name
   }
}

function CreateIFSAttributeStore ( [string] $con_string)
{
   $as_name = "InforFS data store"

   RemoveIFSAttributeStore $as_name

   echo "Creating attribute store: ${as_name}"
   Add-ADFSAttributeStore -Name $as_name -StoreType 'SQL' -Configuration @{"Connection" = "${con_string}"}
}



##############
# Section for the Claims Provider Trust.
#

# Acceptance Transform Rules (ATR) for both OnPremise and OnSaaS
function AddExtractFromAD_ATR ()
{
   $rule = '
@RuleTemplate = "LdapClaims"
@RuleName = "INFOR-GENERATED: Attribute extractions from Active Directory"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
   => issue(store = "Active Directory",
      types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"),
      query = ";userPrincipalName;{0}", param = c.Value);
'

   echo "${rule}"
}

################
# Rule to extract the upn from the IFS data source.
# This rule should mainly be used when there is unidirectional trust between the domain 
# that host the application and another domain to give access.
# In this case this rule should replace AddExtractFromAD_ATR.
# This rule can only be use onPremise where only 1 tenant exists as it does not take into consideration the tenant!!
function AddExtractUPNFromDB_ATR ()
{
   $rule = '
	@RuleName="INFOR-GENERATED: Attribute extractions from IFS database"

c1:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]
 => issue(store = "InforFS data store",
	types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"),
	query = "SELECT Value FROM Users inner join Properties on Users.Id = Properties.UserId inner join PropertyTypes on Properties.PropertyTypeId = PropertyTypes.Id WHERE Users.UserIdentifier = {0} and PropertyTypes.Name = ''UPN''",
	param = c1.Value
 );
'

   echo "${rule}"
}

# The OnPremise Acceptance Transform Rules (ATR)
function AddOnPremiseEmitUserLookupValue_ATR ()
{
   $rule = '
@RuleName = "INFOR-GENERATED: Emit IFSUserLookupValue (copy name)"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]
   => issue(Type = "http://schemas.infor.com/claims/IFSUserLookupValue",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            Value = c.Value,
            ValueType = c.ValueType);
'

   echo "${rule}"
}

function AddOnPremiseEmitCustomer_ATR ()
{
   $rule = '
@RuleName = "INFOR-GENERATED: Emit Customer"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]
   => issue(Type = "http://schemas.infor.com/claims/Customer",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            Value = "DEFAULT",
            ValueType = c.ValueType);
'

   echo "${rule}"
}

function AddOnPremiseEmitIdentity_ATR ()
{
   $rule = '
@RuleName = "INFOR-GENERATED: Emit Identity (strip off domain prefix from Name claim)"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", Value =~ "^[^\\]+\\.+$"]
   => issue(Type = "http://schemas.infor.com/claims/Identity",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            Value = regexreplace(c.Value, "^(?<customer_domain>[^\\]+)\\(?<user>.+)$", "${user}"),
            ValueType = c.ValueType);
'

   echo "${rule}"
}


function AddOnPremiseEmitIdentity2_ATR ()
{
   $rule = '
@RuleName = "INFOR-GENERATED: Emit Identity2 (copy UPN)"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]
   => issue(Type = "http://schemas.infor.com/claims/Identity2",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            Value = c.Value,
            ValueType = c.ValueType);
'

   echo "${rule}"
}

function AddOnPremiseEmitClientPrincipal_ATR ()
{
	   $rule = '
	@RuleName = "INFOR-GENERATED: Emit ClientPrincipalName (extract from IFS)"
	c:[Type == "http://schemas.infor.com/claims/IFSUserLookupValue"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/ClientPrincipalName"),
    query = "SELECT ClientPrincipal FROM Users WHERE Users.UserIdentifier = {0}",
    param = c.Value);
'

   echo "${rule}"

}

# The OnSaaS Acceptance Transform Rules (ATR)
function AddOnSaasEmitUserLookupValue_ATR ()
{
   $rule = '
@RuleName = "INFOR-GENERATED: Emit IFSUserLookupValue (copy name)"
c:[Type == "http://schemas.infor.com/claims/Identity"]
   => issue(Type = "http://schemas.infor.com/claims/IFSUserLookupValue",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            Value = c.Value,
            ValueType = c.ValueType);
'

   echo "${rule}"
}
function AddOnSaaSEmitCustomer_ATR ()
{
   $rule = '
@RuleName = "INFOR-GENERATED: Emit Customer (strip off Identity and domain from UPN claim)"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", Value =~ "^[^_]+_[^\@]+\@.+$"]
   => issue(Type = "http://schemas.infor.com/claims/Customer", Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            Value = regexreplace(c.Value, "^(?<customer>[^_]+)_(?<user>[^\@]+)\@(?<saas_domain>.+)$", "${customer}"),
            ValueType = c.ValueType);
'

   echo "${rule}"
}

function AddOnSaaSEmitIdentity_ATR ()
{
   $rule = '
@RuleName = "INFOR-GENERATED: Emit Identity (strip off customer and domain from UPN claim)"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", Value =~ "^[^_]+_[^\@]+\@.+$"]
   => issue(Type = "http://schemas.infor.com/claims/Identity",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            Value = regexreplace(c.Value, "^(?<customer>[^_]+)_(?<user>[^\@]+)\@(?<saas_domain>.+)$", "${user}"),
            ValueType = c.ValueType);
'

   echo "${rule}"
}

function AddOnSaaSEmitIdentity2_ATR ()
{
   $rule = '
@RuleName = "INFOR-GENERATED: Emit Identity2 (copy Identity)"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", Value =~ "^[^_]+_[^\@]+\@.+$"]
   => issue(Type = "http://schemas.infor.com/claims/Identity2",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            Value = regexreplace(c.Value, "^(?<customer>[^_]+)_(?<user>[^\@]+)\@(?<saas_domain>.+)$", "${user}"),
            ValueType = c.ValueType);
'

   echo "${rule}"
}

function AddOnSaasEmitClientPrincipal_ATR ()
{
      $rule = '
		@RuleName = "INFOR-GENERATED: Emit ClientPrincipalName (copy IFSUserLookupValue)"
		c:[Type == "http://schemas.infor.com/claims/IFSUserLookupValue"]
		=> issue(Type = "http://schemas.infor.com/claims/ClientPrincipalName",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            Value = c.Value,
            ValueType = c.ValueType);
	'

   echo "${rule}"
}

function AddClaimsProviderTrustADRules ( [switch] $saas)
{
   # Get existing Claims Provider Trust for 'Active Directory'
   #    Resulting variable is of type Microsoft.IdentityServer.PowerShell.Resources.ClaimsProviderTrust
   $ad_cpt = Get-ADFSClaimsProviderTrust -Name "Active Directory"

   # Get the existing Claim Rules for it
   #    Resulting variable is of type String
   $eRules = $ad_cpt.AcceptanceTransformRules

   $totalSet = ""
   if ($eRules) {
      # Convert the string with rules into a new set
      $eSet = New-ADFSClaimRuleSet -ClaimRule $eRules

      # Construct the new, total set
      foreach ($rule in $eSet.ClaimRules) {
         if ($rule -notmatch "INFOR-GENERATED:") {
            $totalSet += $rule
         }
      }
   }

   # Construct the additional set of Claim Rules needed by IFS
   # On AD FS 3.0 it already adds a upn claim by default. See MINGLEDEV-5515
   if (!$ignoreExtractRule) 
   {
		$totalSet += AddExtractFromAD_ATR
   }
   if ( $saas )
   {
      $totalSet += AddOnSaaSEmitCustomer_ATR
      $totalSet += AddOnSaaSEmitIdentity_ATR
      $totalSet += AddOnSaaSEmitIdentity2_ATR

	  $totalSet += AddOnSaasEmitUserLookupValue_ATR

	  $totalSet += AddOnSaasEmitClientPrincipal_ATR
  } else {
      $totalSet += AddOnPremiseEmitCustomer_ATR
      $totalSet += AddOnPremiseEmitIdentity_ATR
      $totalSet += AddOnPremiseEmitIdentity2_ATR

	  $totalSet += AddOnPremiseEmitUserLookupValue_ATR

	  $totalSet += AddOnPremiseEmitClientPrincipal_ATR
   }

   

   # TAKE CARE: executing this REPLACES all existing claim rules with the new ones. It is not an addition, the 'old' ones get lost!!
   echo "Adding IFS claim rules to Claims Provider Trust on Active Directory"
   Set-ADFSClaimsProviderTrust -TargetName "Active Directory" -AcceptanceTransformRules $totalSet
}



##############
# Main section
#  No deployment specific data above this point! Everything must be parameterized!
#

if ( -not $noConfirm) {
	Write-Host ""
	Write-Host "Summary:"
	if ( $saas )
	{
	   Write-Host "  OnSaas installation : true"
	}
	Write-Host "  DB connection string: ${connect_string}."
	
	$cont = Read-Host "Start ADFS configuration?"
	
	if ( $cont -ne "y" -and $cont -ne "Y")
	{
	   Write-Host ""
	   Write-Host "ADFS configuration cancelled by user."
	   exit
	}
}

# Set the current directory to a correct value
#   See: http://huddledmasses.org/powershell-power-user-tips-current-directory/
[Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath

CreateInforClaimTypes

CreateIFSAttributeStore $connect_string

AddClaimsProviderTrustADRules -saas:$saas

# SIG # Begin signature block
# MIIY9wYJKoZIhvcNAQcCoIIY6DCCGOQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdJvK40yzF50ruaFOqlkkaK2q
# hUKgghPMMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggVLMIIEM6ADAgECAhAnpxzzIMMNidNePWpXGzkYMA0GCSqGSIb3DQEBCwUAMH0x
# CzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNV
# BAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSMwIQYDVQQD
# ExpDT01PRE8gUlNBIENvZGUgU2lnbmluZyBDQTAeFw0xNTA0MTUwMDAwMDBaFw0x
# ODA0MTQyMzU5NTlaMIGUMQswCQYDVQQGEwJVUzEOMAwGA1UEEQwFMTAwMTExETAP
# BgNVBAgMCE5ldyBZb3JrMREwDwYDVQQHDAhOZXcgWW9yazEjMCEGA1UECQwaNjQx
# IEF2ZW51ZSBvZiB0aGUgQW1lcmljYXMxFDASBgNVBAoMC0luZm9yLCBJbmMuMRQw
# EgYDVQQDDAtJbmZvciwgSW5jLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAJ1OnBbQsueqtVW57w1gGl+b4CEDR30jdpA8DrW7azmx7kvzhoOKncTIG5Du
# ZvepNiZKFxCLZT2qtjGYHm/h+DgO49NhenshBt4Oz0AELFdnKfKEnnv/lz/8/W26
# I4cFHaSdhLqbxOaTqdC+Eh3R7Tyee6Yo5rOP/seqgKpsxe/vKnzbbIXDPK7N8jGZ
# jsm3aEV5CO0/F84wI2+OEisucf2Nk01Z5MyllRXSIiIcvMTXcXD9tgdZVUzFrT98
# sw4QdRtBPyjffahwbfachw6xS1CEkvjXBgJzsZRY3AafMCj+V5s1sv3oakc3Stku
# JKCRIOPsAaluXJ5v9nOD0+4R9I0CAwEAAaOCAa0wggGpMB8GA1UdIwQYMBaAFCmR
# YP+KTfrr+aZquM/55ku9Sc4SMB0GA1UdDgQWBBTG6TZxBr1SX/GaKlgNO1QLLB9K
# ITAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEF
# BQcDAzARBglghkgBhvhCAQEEBAMCBBAwRgYDVR0gBD8wPTA7BgwrBgEEAbIxAQIB
# AwIwKzApBggrBgEFBQcCARYdaHR0cHM6Ly9zZWN1cmUuY29tb2RvLm5ldC9DUFMw
# QwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQ09NT0RP
# UlNBQ29kZVNpZ25pbmdDQS5jcmwwdAYIKwYBBQUHAQEEaDBmMD4GCCsGAQUFBzAC
# hjJodHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9DT01PRE9SU0FDb2RlU2lnbmluZ0NB
# LmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMB4GA1Ud
# EQQXMBWBE2RvbWFpbnJlZ0BpbmZvci5jb20wDQYJKoZIhvcNAQELBQADggEBAFsH
# jucFTQ8e6LNuo5RdawTmketngJhqnRcZ3kJD4Uq9CkJji+2DfimUopmAEFWHomg9
# VLLfM+Abe3yFFtjv2sWHH0G0nxSn7DH3VoY//7haif+hSFtlqYjbkL4Lcvhu7szR
# ffXTK0Hu4nS/t0R08ndpRRGCWNkBvLI3SGgS4GT+dEJSn7/92AH8V3CdZG5b+WeP
# Lm07mc6iuZK/1qXmzeknM8x7DKmH3gq5+BebYEsCeu8q4ea46geiQhuexmvCnlHA
# ab2GibYTfGN5C7gD4zgQABvbtC7y9KGyTEH8zQI0gGh6Fuyr5/9kCU0RaU3qgySd
# eusmFgkzArxPPLR+/qowggXgMIIDyKADAgECAhAufIfMDpNKUv6U/Ry3zTSvMA0G
# CSqGSIb3DQEBDAUAMIGFMQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBN
# YW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0Eg
# TGltaXRlZDErMCkGA1UEAxMiQ09NT0RPIFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhv
# cml0eTAeFw0xMzA1MDkwMDAwMDBaFw0yODA1MDgyMzU5NTlaMH0xCzAJBgNVBAYT
# AkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZv
# cmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSMwIQYDVQQDExpDT01PRE8g
# UlNBIENvZGUgU2lnbmluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKaYkGN3kTR/itHd6WcxEevMHv0xHbO5Ylc/k7xb458eJDIRJ2u8UZGnz56e
# JbNfgagYDx0eIDAO+2F7hgmz4/2iaJ0cLJ2/cuPkdaDlNSOOyYruGgxkx9hCoXu1
# UgNLOrCOI0tLY+AilDd71XmQChQYUSzm/sES8Bw/YWEKjKLc9sMwqs0oGHVIwXla
# CM27jFWM99R2kDozRlBzmFz0hUprD4DdXta9/akvwCX1+XjXjV8QwkRVPJA8MUbL
# cK4HqQrjr8EBb5AaI+JfONvGCF1Hs4NB8C4ANxS5Eqp5klLNhw972GIppH4wvRu1
# jHK0SPLj6CH5XkxieYsCBp9/1QsCAwEAAaOCAVEwggFNMB8GA1UdIwQYMBaAFLuv
# fgI9+qbxPISOre44mOzZMjLUMB0GA1UdDgQWBBQpkWD/ik366/mmarjP+eZLvUnO
# EjAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAK
# BggrBgEFBQcDAzARBgNVHSAECjAIMAYGBFUdIAAwTAYDVR0fBEUwQzBBoD+gPYY7
# aHR0cDovL2NybC5jb21vZG9jYS5jb20vQ09NT0RPUlNBQ2VydGlmaWNhdGlvbkF1
# dGhvcml0eS5jcmwwcQYIKwYBBQUHAQEEZTBjMDsGCCsGAQUFBzAChi9odHRwOi8v
# Y3J0LmNvbW9kb2NhLmNvbS9DT01PRE9SU0FBZGRUcnVzdENBLmNydDAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IC
# AQACPwI5w+74yjuJ3gxtTbHxTpJPr8I4LATMxWMRqwljr6ui1wI/zG8Zwz3WGgiU
# /yXYqYinKxAa4JuxByIaURw61OHpCb/mJHSvHnsWMW4j71RRLVIC4nUIBUzxt1Hh
# UQDGh/Zs7hBEdldq8d9YayGqSdR8N069/7Z1VEAYNldnEc1PAuT+89r8dRfb7Lf3
# ZQkjSR9DV4PqfiB3YchN8rtlTaj3hUUHr3ppJ2WQKUCL33s6UTmMqB9wea1tQiCi
# zwxsA4xMzXMHlOdajjoEuqKhfB/LYzoVp9QVG6dSRzKp9L9kR9GqH1NOMjBzwm+3
# eIKdXP9Gu2siHYgL+BuqNKb8jPXdf2WMjDFXMdA27Eehz8uLqO8cGFjFBnfKS5tR
# r0wISnqP4qNS4o6OzCbkstjlOMKo7caBnDVrqVhhSgqXtEtCtlWdvpnncG1Z+G0q
# DH8ZYF8MmohsMKxSCZAWG/8rndvQIMqJ6ih+Mo4Z33tIMx7XZfiuyfiDFJN2fWTQ
# js6+NX3/cjFNn569HmwvqI8MBlD7jCezdsn05tfDNOKMhyGGYf6/VXThIXcDCmhs
# u+TJqebPWSXrfOxFDnlmaOgizbjvmIVNlhE8CYrQf7woKBP7aspUjZJczcJlmAae
# zkhb1LU3k0ZBfAfdz/pD77pnYf99SeC7MH1cgOPmFjlLpzGCBJUwggSRAgEBMIGR
# MH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
# BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSMwIQYD
# VQQDExpDT01PRE8gUlNBIENvZGUgU2lnbmluZyBDQQIQJ6cc8yDDDYnTXj1qVxs5
# GDAJBgUrDgMCGgUAoIHKMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBS6fsU/AofN
# p753VqbpOJ/h3Usv6zBqBgorBgEEAYI3AgEMMVwwWqBYgFYASQBuAGYAbwByACAA
# RgBlAGQAZQByAGEAdABpAG8AbgAgAFMAZQByAHYAaQBjAGUAcwAgAFAAbwB3AGUA
# cgBTAGgAZQBsAGwAIABzAGMAcgBpAHAAdDANBgkqhkiG9w0BAQEFAASCAQA8XEo9
# q4Z0yyry9MZ+jnzECT2elo6mrYcfoe1KY/b594lNOggMgVuIlyP7vjsA0tHhN78h
# FSdDdZQDC0BLof4hIOH5Yy+Gw6blzGv3cya+7yBURwPAm/Eaxp+qETTetc8WMqbH
# ho40584kfqOdigAG8czN8W5RaJT6ocWkKKeQ/iJVtxdqTKtL3JWvMcUdQXRpHdYP
# 7jzA6YJyVt26EQUE1indlvLrrRkhCceQvTBoPtMjD7Sa401c3jqUxPInbCb8iVqw
# 3FveMAdVcmqOGbkNhbAqhrFYXtB4dmNt9a1mm7TtEvMjnWDrXcaJCVfE/u2o8VSQ
# nV5gbj55ZCrbt7wpoYICCzCCAgcGCSqGSIb3DQEJBjGCAfgwggH0AgEBMHIwXjEL
# MAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYD
# VQQDEydTeW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzICEA7P
# 9DjI/r81bgTYapgbGlAwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG
# 9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MDYxNjE5NDkzNlowIwYJKoZIhvcNAQkE
# MRYEFD3GbuxT/mQdyJsu+JaHaXoNNKVaMA0GCSqGSIb3DQEBAQUABIIBAHaDflGM
# kQ2lZCug/6/UtsGgF5kz0V8CtMPLTpfpOEUcsd2ImEEbScb83q6p07d6T3ue4cPW
# LocXtYfVbUYNr8M7RiWDlctrvKcm8KJDw1llOV/9mDt5mLxY+1Gs7LcaIH4IR9d9
# eh8O0yz/3pbP7PlwEMlU0xI27R6osy18iZcVMW1/fI8dF+LS16o+mLREIF3ezcUG
# i70DP4YJqis6df2al86of7A4bdtiejcp4bex3MMsU5tJ4iVIwCJfRYKRXHKbcwVq
# G4t13Z7ZqwoajJmYzsms9Apewskx7HNw5/ftqHBPgztBDcSPdAyN33sNI9Y7d1zb
# XGs1gjpwR+sJF+o=
# SIG # End signature block
