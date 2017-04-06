###############################################
# Copyright Infor (c). All rights reserved.
###############################################

#=============================================================================
#
# PARAMETERS
#

param(
	[switch] $noConfirm = $false,

	[parameter(mandatory = $true, HelpMessage = "The Claims provider name.")]
	[string] $cpt_name,

	[parameter(mandatory = $true, HelpMessage = "The Claims provider metadata.")]
	[string] $cpt_metadata_file,
	
	[parameter(mandatory = $false, HelpMessage = "The Claims provider notes.")]
	[string] $cpt_notes_file
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

##########
# Functions to add a set of Acceptance Transform Rules (ATRs) to an CPT.
#

# Note copied from ADFS_IFS_Base_Config and modified to accommodate users from ping

function AddOnPremiseEmitCustomer_ATR ()
{
   $rule = '
@RuleName = "INFOR-GENERATED: Emit Customer"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/EmailAddress"]
   => issue(Type = "http://schemas.infor.com/claims/Customer",
            Issuer = c.Issuer,
            OriginalIssuer = c.OriginalIssuer,
            Value = "DEFAULT",
            ValueType = c.ValueType);
'

   echo "${rule}"
}

function AddDefaultPicture_ATR ()
{
	$rule = '
	@RuleName = "INFOR-GENERATED: Add Default Picture"
	NOT EXISTS([Type == "http://schemas.infor.com/claims/UserProfilePicture"])
		=> ADD(
		type = "http://schemas.infor.com/claims/UserProfilePicture", value = "");
	'
	echo "${rule}"
}

function AddDefaultGivenName_ATR ()
{
	$rule = '
	@RuleName = "INFOR-GENERATED: Add Default GivenName"
	NOT EXISTS([Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"])
		=> ADD(
		type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", value = "");
	'
	echo "${rule}"
}

function AddDefaultSurname_ATR ()
{
	$rule = '
	@RuleName = "INFOR-GENERATED: Add Default Surname"
	NOT EXISTS([Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/Surname"])
		=> ADD(
		type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/Surname", value = "");
	'
	echo "${rule}"
}


function AddEmitExternalUserId_ATR()
{
   $rule = '
	@RuleName="INFOR-GENERATED: Emit ExternalUserId"
c1:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"]
 && c2:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/Surname"]
 && c3:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/EmailAddress"]
 && c4:[Type == "http://schemas.infor.com/claims/CommunityIdentifier"]
 && c5:[Type == "http://schemas.infor.com/claims/UserProfilePicture"]
 => issue(store = "InforFS data store", types = ("http://schemas.infor.com/claims/ExternalUserId"), query = "EXEC [dbo].[ExternalUserLogin] @Email = {0}, @IdentityProviderId = {1}, @FirstName = {2}, @LastName = {3}, @Picture = {4}", param = c3.Value, param = c4.Value, param = c1.Value, param = c2.Value, param = c5.Value);

'

   echo "${rule}"
}

function AddPassThroughInforCommunitiesProfile_ATR()
{
	   $rule = '
@RuleName="INFOR-GENERATED: Pass Through Infor Communities Profile claim"
@RuleTemplate="PassThroughClaims"
 c:[Type == "http://schemas.infor.com/claims/CommunitiesProfilePage"]
 => issue(claim = c);
'
   echo "${rule}"
}

function AddAll_MingleCommunity_ATRs ( [string] $param_cpt_name)
{
   $totalSet = @()

   $totalSet += AddOnPremiseEmitCustomer_ATR
   $totalSet += AddDefaultGivenName_ATR
   $totalSet += AddDefaultSurname_ATR
   $totalSet += AddDefaultPicture_ATR
   $totalSet += AddEmitExternalUserId_ATR
   $totalSet += AddPassThroughInforCommunitiesProfile_ATR

   $totalSet_string = [string] $totalSet

   Set-ADFSClaimsProviderTrust -TargetName $param_cpt_name -AcceptanceTransformRules $totalSet_string
}


##############
# Section with functions to remove and create a Claim Provider Trust.
#

# Remove an CPT.
#
function RemoveClaimsProvider ( [string] $param_cpt_name)
{
  $cpt = Get-ADFSClaimsProviderTrust -Name "${param_cpt_name}"
  if ( "$cpt" -ne "")
  {
	 echo "Removing CPT with name: ${param_cpt_name}"
	 Remove-ADFSClaimsProviderTrust -targetName "${param_cpt_name}"
  }

}

function CreateMingleCommunityClaimsProvider ([string] $param_cpt_name, [string] $param_metadata_file, [string] $param_cpt_notes)
{
	echo "Creating CPT for ${param_cpt_name}"

   Add-ADFSClaimsProviderTrust -Name "${param_cpt_name}" -MetadataFile "${param_metadata_file}"

   if ( "${param_cpt_notes}" -ne "" )
   {
      Set-ADFSClaimsProviderTrust -TargetName "${param_cpt_name}" -Notes "${param_cpt_notes}"
   }
	
   AddAll_MingleCommunity_ATRs "${param_cpt_name}" 
}

#########################
# Main section

if ( "${cpt_notes_file}" -ne "")
{
   # Get-Content reads an array of objects (one per line of input), so join them.
   ${file_content} = Get-Content "${cpt_notes_file}"
   ${cpt_notes_content} = ":`r`n" + [string]::join([environment]::newline, ${file_content})
}

${cpt_notes_content} = "INFOR-GENERATED Claims Provider Trust" + "${cpt_notes_content}"

# Set the current directory to a correct value
#   See: http://huddledmasses.org/powershell-power-user-tips-current-directory/
[Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath


RemoveClaimsProvider "${cpt_name}" 

CreateMingleCommunityClaimsProvider "${cpt_name}" "${cpt_metadata_file}" "${cpt_notes_content}"

# SIG # Begin signature block
# MIIY9wYJKoZIhvcNAQcCoIIY6DCCGOQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2Oz9kwAVrYOVrYzYNfjcfP+G
# juKgghPMMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSUuXrzmII4
# nHyoIe/NX/n4VXtUdTBqBgorBgEEAYI3AgEMMVwwWqBYgFYASQBuAGYAbwByACAA
# RgBlAGQAZQByAGEAdABpAG8AbgAgAFMAZQByAHYAaQBjAGUAcwAgAFAAbwB3AGUA
# cgBTAGgAZQBsAGwAIABzAGMAcgBpAHAAdDANBgkqhkiG9w0BAQEFAASCAQBwoD7L
# z6p7MQ/mGmWnp/b5U9LqaK5v5g5AGGw5Xx0q+LrgL+55bb6+ZDt9cE1TTlTS8mYW
# Buxbkq2dUnzlgUkyPWnEKG353mZxln1V6hz/7DaDIbbgl8bzgspv2Ij+U19exugv
# Dr4flVAFLy6NZCoeokbLg4hK77Y0/Xkv//a9mX5VtXtK/jIdEYaijlDQICXuZ2BX
# tF3sgsN8ZvXUzTy0+t1tD4R2iKIWcOHWS+Han36LDR0/NJdvodvc/sMED6uqOAKK
# 95NKKe7vQZDgG0YkY/pRGTNX3eR8c6xdnwsKE0Lz/Qa+AMLASmGFuNax9peRMOS3
# pF8O/BzI6fssve/YoYICCzCCAgcGCSqGSIb3DQEJBjGCAfgwggH0AgEBMHIwXjEL
# MAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYD
# VQQDEydTeW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzICEA7P
# 9DjI/r81bgTYapgbGlAwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG
# 9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MDYxNjE5NDkzNVowIwYJKoZIhvcNAQkE
# MRYEFLa1vH/OLXPRefoHRxJEbT7Jrl+RMA0GCSqGSIb3DQEBAQUABIIBAGAZSe/6
# /TtvNCZSk6lgfzXBbagMTM0FkgLmIQAYnWkIBTkoetCHEKoGtpkjrS45oar+d2Og
# zE92mIxAyykokKnt4/LuimeLbFOGPaTanQiMfpcSJziNG5zARz1vHji4sh8BsXCk
# R5vrjzCpat/NngljLvr4+IGPzMq/SjUfWBGTRaLQH2ZofZVrzZeRurcDKc3EK1vN
# toj42kgrAtS2yZu5xqfeR+3oBUszv6Xq3pfyTbsTDI+19Xo/k6ZnYIEBYdDWUq9q
# 7OvuCjZfmNv7VFSJMto7pi5joWyhb4TXAOs1FRymEFkzdjAD0HrrFmPEZbsAARjr
# 3Zrxw2RgYL1FEaU=
# SIG # End signature block
