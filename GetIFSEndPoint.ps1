###############################################
# Copyright Infor (c). All rights reserved.
###############################################

#=============================================================================
#
# Find IFS Endpoint (leave out default ssl port and default http port)
# Condition in case of SSL: exactly one SSL binding in 'Default Web Site'.
# For HTTP bindings it doesn't matter. This script prefers 80, otherwise
# just picks one of the http bindings (first match in appcmd.exe output).
#
# An error is returned when multiple SSL bindings are present.
# Nothing is returned when the requested binding is absent.
#

param(
	[parameter(
		Mandatory = $false,
		HelpMessage = "Use this flag to use the HTTP binding."
	)] 
	[switch] $nossl = $false
)

#=============================================================================
#
# GENERAL SET-UP
#

Set-PSDebug -Strict # -Trace 1
$host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(512,200)

trap {
	break;
}

$appcmd = $env:SystemRoot + "\system32\inetsrv\APPCMD.exe"
$defaultwebsiteinfo = & $appcmd "list" "sites" "/name:Default` Web` Site"

# Get the computer object for the computer and domain names
$computer = Get-WmiObject -Class Win32_ComputerSystem

$result = "";

if ($nossl) {
	# match https binding. First see if there is a binding on port 80
	if ($defaultwebsiteinfo -match "[:,]http/\*:")
	{
		if ($defaultwebsiteinfo -match "[:,]http/\*:80:") {
			$nosslport = "80"
		} else {
			$nosslport = [regex]::Replace($defaultwebsiteinfo, ".*?[:,]http/\*:(\d+).*", '$1')
		}

		$nosslstring = (":" + $nosslport)
		if ($nosslport -eq "80") {
			$nosslstring = "" 
		}

		$result = "http://" + $computer.name + "." + $computer.domain + $nosslstring + "/IFS/"
	}
} else {
	# the ErrorVariable is filled with an array of errors, regardless of the ErrorAction. This code tries to
	# follow the SSL port number choice that was made for ADFS, even if the target SecurityMode is Windows.
	# This ensures that the SSL URL won't change if IFS is switched to SecurityMode SAMLToken later.
	$dummy = Get-PSSnapin -Registered -name Microsoft.Adfs.Powershell -ErrorVariable snapinerror -ErrorAction SilentlyContinue
	if ($snapinerror.count -eq 0)
	{
		Add-PSSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue
		$properties = Get-ADFSProperties
		$sslport = $properties.HttpsPort

		Write-Output ("# AD FS property 'HttpsPort' = " + $sslport)
		$sslstring = (":" + $sslport)
		if ($sslport -eq "443") {
			$sslstring = "" 
		}

		#
		# Check if the SSL port that ADFS is configured for is an existing SSL port in IIS.
		#
		$pattern = ("[:,]https/\*:" + $sslport + ":")
		if ($defaultwebsiteinfo -match $pattern)
		{
			$result = "https://" + $computer.name + "." + $computer.domain + $sslstring + "/IFS/"
		}
		else
		{
			Write-Output "# but there is no 'https' binding with that port in IIS. There is a configuration error."
		}
	}
	else
	{
		Write-Output "# The ADFS powershell snapin is not found, the SSL port will be taken from the IIS configuration."
	}

	if ($result -eq "")
	{
		Write-Output "# Trying to find the first SSL binding from 'APPCMD' output..."
		if ($defaultwebsiteinfo -match "[:,]https/\*:")
		{
			if ($defaultwebsiteinfo -match "[:,]https/\*:443:") {
				$sslport = "443"
			} else {
				$sslport = [regex]::Replace($defaultwebsiteinfo, ".*?[:,]https/\*:(\d+).*", '$1')
			}

			$sslstring = (":" + $sslport)
			if ($sslport -eq "443") {
				$sslstring = "" 
			}
			$result = "https://" + $computer.name + "." + $computer.domain + $sslstring + "/IFS/"
		}
		else
		{
			Write-Output "# no HTTPS bindings found"
		}
	}
}

return $result
# SIG # Begin signature block
# MIIY9wYJKoZIhvcNAQcCoIIY6DCCGOQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOrANlb3EO8d1h04/l407SpaZ
# mwegghPMMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRfDw3dKXQJ
# 9BpKpOirEChR8mOmFTBqBgorBgEEAYI3AgEMMVwwWqBYgFYASQBuAGYAbwByACAA
# RgBlAGQAZQByAGEAdABpAG8AbgAgAFMAZQByAHYAaQBjAGUAcwAgAFAAbwB3AGUA
# cgBTAGgAZQBsAGwAIABzAGMAcgBpAHAAdDANBgkqhkiG9w0BAQEFAASCAQALEUzb
# QzRyolKhrsrWtFHy12FW2re+QbE4/4qvt7azcnrzBXkbxwYBgjFUtGfaagj3AaMH
# c8PIY2qnJYo1RRLQEbyjOX49N/Io3BMg9XDP48PT6XIBRZ8btsWRj5jCaTfAadwF
# IOeIXcvz3xa7aKw9Z1OeNOAnZGAoQDN+kai9bforL6ftj9wjzt/5kM+kq5XjYLcp
# fPDptn3VjtUeiFl7jVmqqIkVzKAYREQCxA4f8Agfm+nk16ro9q0RRn7ov85e/P6b
# 2i7eVqMwp/hZUWR59J32DSdKXdv/s7fW/x3+GxOzSdFOY79chcxWiu2zBuGo6C+f
# yvUAtnDaAqlzaQJQoYICCzCCAgcGCSqGSIb3DQEJBjGCAfgwggH0AgEBMHIwXjEL
# MAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYD
# VQQDEydTeW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzICEA7P
# 9DjI/r81bgTYapgbGlAwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG
# 9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MDYxNjE5NDk0MVowIwYJKoZIhvcNAQkE
# MRYEFMuU/Yu4Rxe7jrheeZMbSUBEAXKrMA0GCSqGSIb3DQEBAQUABIIBAC+lytof
# P0RqiG8/UGDvyCyiW8qB0rgH1uFy8b++obq2phaX0S19YlmLLjBJ75ZmycLMQdtx
# OBud44gpMt0n/qzS9zwaUwpMDwp6GeQRuQ/dOEiIOp7Qb2hXoJ5BhE4H1948MInB
# sFnvlJeFPvLgQTxCVbDvaedSLedlmJXB2Lao9DcfV9noeFCnmET39Y0uJTCuh8GN
# +1MkLtpLiuvnzO+jWFvZDJyxocrs2SwDO7EOEpOAlAwiTwhejBJUo6YQy44fP2Gy
# 5V8OkDaxtLMfKJOpULolDusmpQwp76LTKUgCpVH1BarXswuvLS0CdUBBVg+HXNjy
# QV6MUufgbvvrxtI=
# SIG # End signature block
