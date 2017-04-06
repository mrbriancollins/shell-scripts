###############################################
# Copyright Infor (c). All rights reserved.
###############################################

# This script generates a self-signed certificate
# [TODO: More details, e.g.: never expires]
# This script was inspired by the blog post at
# http://blogs.technet.com/b/vishalagarwal/archive/2009/08/22/generating-a-certificate-self-signed-using-powershell-and-certenroll-interfaces.aspx
#
# This script uses the CertEnroll library
# (http://msdn.microsoft.com/en-us/library/aa374850%28VS.85%29.aspx)
# to create a self-signed certificate.
#
# The only place to find the class names apparently is
# http://msdn.microsoft.com/en-us/library/aa965817%28VS.85%29.aspx




#=============================================================================
#
# PARAMETERS
#

param(
	[parameter(
		Mandatory = $true,
		HelpMessage = "The distinguished name of the generated certificate, e.g., 'CN=IFSUserServices'",
		Position = 0 # NOTE: The installer depends on this position.
	)]
	[string] $distinguishedName,

	[parameter(
		Mandatory = $true,
		HelpMessage = "A description for the generated certificate, e.g., 'IFS User Services'",
		Position = 1 # NOTE: The installer depends on this position.
	)]
	[string] $description

	# NOTE.  The installer calls this script with only the two parameters above.  Make sure to consider
	# backward compatibility when adding parameters.
)


#=============================================================================
#
# GENERAL SET-UP
#

#
# Configure the host so it does not wrap at 80 characters.
# Source: http://weblogs.asp.net/soever/archive/2008/12/09/powershell-output-capturing-and-text-wrapping-strange-quirks-solved.aspx
#
$host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(512,200)

Set-PSDebug -Strict # -Trace 1

trap {
	break;
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



#=============================================================================
#
# CONSTANTS
#

# http://msdn.microsoft.com/en-us/library/aa378137%28VS.85%29.aspx
set-variable S_OK -option Constant -value 0
# http://msdn.microsoft.com/en-us/library/aa379409(VS.85).aspx#XCN_AT_KEYEXCHANGE
set-variable X509KeySpec_XCN_AT_KEYEXCHANGE -option Constant -value 1
# http://msdn.microsoft.com/en-us/library/aa376782(VS.85).aspx#AllowUntrustedCertificate
set-variable InstallResponseRestrictionFlags_AllowUntrustedCertificate -option Constant -value 2
# http://msdn.microsoft.com/en-us/library/aa374936(VS.85).aspx#XCN_CRYPT_STRING_BASE64HEADER
set-variable EncodingType_XCN_CRYPT_STRING_BASE64HEADER -option Constant -value 0
# http://msdn.microsoft.com/en-us/library/aa374960(VS.85).aspx#Enrolled
set-variable EnrollmentEnrollStatus_Enrolled -option Constant -value 1
# http://support.microsoft.com/kb/287547
set-variable szOID_KP_DOCUMENT_SIGNING -option Constant -value "1.3.6.1.4.1.311.10.3.12"
# http://msdn.microsoft.com/en-us/library/aa379399(VS.85).aspx#ContextMachine
set-variable X509CertificateEnrollmentContext_ContextMachine -option Constant -value 2


#=============================================================================
#
# HELPERS
#

$ipProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
$hostname = "{0}.{1}" -f $ipProperties.HostName, $ipProperties.DomainName


#=============================================================================
#
# REUSE EXISTING CERTIFICATE, IF POSSIBLE
#

$existingCertificates = (get-childitem -Recurse cert:\LocalMachine\ | ? { $_.Subject -eq $distinguishedName } )
if ($existingCertificates) {
	$cert = (get-childitem -Recurse cert:\LocalMachine\My | ? { $_.Subject -eq $distinguishedName })
	if ($cert `
		-and $cert.GetType() -eq [System.Security.Cryptography.X509Certificates.X509Certificate2] `
		-and $cert.HasPrivateKey `
	) {
		# We have just one 'Local Computer\Personal' certificate of the requested name,
		# so we reuse the existing certificate
		return $cert.Thumbprint
	}
	# The certificate name exists, but none of them is usable.
	throw [Exception] "Certificate(s) with name $($distinguishedName) already exist(s).  Location(s): $($existingCertificates | % { $_.PSParentPath })"
}


#=============================================================================
#
# CREATE REQUEST
#

#"Creating cert request."

$name = new-object -com "X509Enrollment.CX500DistinguishedName.1"
$name.Encode($distinguishedName)

$key = new-object -com "X509Enrollment.CX509PrivateKey.1"
$key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
$key.KeySpec = $X509KeySpec_XCN_AT_KEYEXCHANGE
$key.Length = 2048
$key.MachineContext = [int]$true
$key.ExportPolicy = 1
# TODO: Explicitly set more options?
$key.Create()

$serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
$serverauthoid.InitializeFromValue($szOID_KP_DOCUMENT_SIGNING)
$ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
$ekuoids.add($serverauthoid)
$ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
$ekuext.InitializeEncode($ekuoids)

$certreq = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
$certreq.InitializeFromPrivateKey(
	$X509CertificateEnrollmentContext_ContextMachine,
	$key,
	"" # no template
)
$certreq.Subject = $name
$certreq.Issuer = $certreq.Subject
$certreq.NotAfter = (get-date).AddDays(100000) # a couple of centuries...
$certreq.X509Extensions.Add($ekuext)
$certreq.Encode()

#"Created cert request"


#=============================================================================
#
# ENROLL REQUEST
#

#"Enrolling."

$enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
$enrollment.InitializeFromRequest($certreq)
$enrollment.CertificateFriendlyName =
	"{0} on {1}" -f $description, $hostname
$enrollment.CertificateDescription =
	"{0} on {1} certificate, generated on {2}" -f $description, $hostname, (get-date)
$certresp = $enrollment.CreateRequest($EncodingType_XCN_CRYPT_STRING_BASE64HEADER)


#=============================================================================
#
# CREATE CERTIFICATE FROM RESPONSE
#

$enrollment.InstallResponse(
	$InstallResponseRestrictionFlags_AllowUntrustedCertificate,
	$certresp,
	$EncodingType_XCN_CRYPT_STRING_BASE64HEADER,
	"" # no password
)

if ([int] $enrollment.Status.Error -ne $S_OK) {
	throw [Exception] @"
Enrollment failed.
Enrollment status code: $([int] $enrollment.Status.Status)
Enrollment status text: $($enrollment.Status.Text)
Enrollment error code: $([int] $enrollment.Status.Error)
Enrollment error text: $($enrollment.Status.ErrorText)
"@
}


#=============================================================================
#
# RETURN THUMBPRINT
#

#"Enrolling done, retrieving cert"

[Byte[]] $certdata = $([Convert]::FromBase64String($enrollment.Certificate()))
$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($certdata)

return $cert.Thumbprint

# SIG # Begin signature block
# MIIY9wYJKoZIhvcNAQcCoIIY6DCCGOQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUaWX/1pb9kDAgpxEIJCiIj7vS
# zFegghPMMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSrR9bIJE3+
# zS7k/Uq5w6XAuAZBwTBqBgorBgEEAYI3AgEMMVwwWqBYgFYASQBuAGYAbwByACAA
# RgBlAGQAZQByAGEAdABpAG8AbgAgAFMAZQByAHYAaQBjAGUAcwAgAFAAbwB3AGUA
# cgBTAGgAZQBsAGwAIABzAGMAcgBpAHAAdDANBgkqhkiG9w0BAQEFAASCAQAt4U3R
# BxEd/+shIi4v+DOdgf4+mx7SAyrKdp8peCZqxpjnaNyxbnJ+9QgnLhjALEskDzld
# 7DZmn+/3WGza9rGXJ7uURNo7ZCiRg2BwQBI9xEisIh1WGuOkGyLGFv0/4xRN+dz1
# 8ZQ5ecANNa7XRqzquaAt+vdajqQOyfisVdMtTKEAVjYr0PHJGeLWrEVZIczzHGPN
# ErvbpYELFOrZxkyjrWPvryGoTaB8JYYYiW7In/pJb7b3/1BUkC0HPZK7/DXQer3o
# 05AAF1Ye7/sJm/q2sIMUnN7F9vOl77iZc/jSDKx3kQ990xCNpwpBD/gVSBMgzKDO
# Ib87ng+HzxA3MaP9oYICCzCCAgcGCSqGSIb3DQEJBjGCAfgwggH0AgEBMHIwXjEL
# MAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYD
# VQQDEydTeW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzICEA7P
# 9DjI/r81bgTYapgbGlAwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG
# 9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MDYxNjE5NDk0MFowIwYJKoZIhvcNAQkE
# MRYEFIad19hD8xikQ7rZEMH3XPvEsAXxMA0GCSqGSIb3DQEBAQUABIIBACYRwBdC
# pvhzk2oQHr2kvcO19If5iAqBB7Xl4SK1SVoHbfXfsGSCs4LNxJYNi8NFD/UrJbof
# 6u1Mdgg343DBw96mukOheZJhgmf99DJWJXIe+/aihhNXhleLxLn85UF0/pakvM50
# e7qDgRUTdg2VksFcxWFPwgPQ4PvJgPZxUWx53u3G//k3dKsgTYUQRTkVIntfKRT+
# WmpRdHuAMZ/QA3Pvz3ObCglielNah713JQrqgUjv1Z43CHZ1e4w2sLfjbHHBehuQ
# 1lLnho54OFrJ79UiD+kmr55Oye4OJ6DoRvhCkZ+D9CC39eXxsPcxy+FWxLaNIedk
# R9NSFaynA3hPFvs=
# SIG # End signature block
