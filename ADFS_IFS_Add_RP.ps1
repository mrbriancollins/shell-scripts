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

	[parameter(mandatory = $true, HelpMessage = "One of the known application types: EAM, IACM, MONGOOSE, ISM, LN, SYTELINE, XM, COMPANION, ION, IONGRID, IFS, SUNSYSTEMS, SMARTSTREAM, PAYMENT, AUTOCONNECT, BI, HMS, STOREROOM, SCE, WIF, SAMLP, ENTERPRISESEARCH, SNOP, LX, XA, INFINIUM, SYSTEM21, CPM, SHCM, ADAGE, PLMPROCESS, COLLABORATIONENGINE, SUPPLYWEB, GRID, IR, IRN, OPTIVA, BV, MCC.")]
	[ValidateSet("EAM", "IACM", "MONGOOSE", "ISM", "LN", "SYTELINE", "XM", "COMPANION", "ION", "IONGRID", "IFS", "SUNSYSTEMS", "SMARTSTREAM", "PAYMENT", "AUTOCONNECT", "BI", "HMS", "STOREROOM", "SCE", "WIF", "SAMLP", "ENTERPRISESEARCH", "SNOP", "LX", "XA", "INFINIUM", "SYSTEM21", "CPM", "SHCM", "ADAGE", "PLMPROCESS", "COLLABORATIONENGINE", "SUPPLYWEB", "GRID", "IR", "IRN", "OPTIVA", "BV", "MCC")]
	[string] $app_type,


	[parameter(mandatory = $true, HelpMessage = "The name of the application.")]
	[string] $app_name,

	[parameter(mandatory = $true, HelpMessage = "Relying Party ID")]
	[string] $app_rpid,

	[parameter(mandatory = $true, HelpMessage = "The application endpoint URL.")]
	[string] $app_endpoint,

	[parameter(HelpMessage = "The thumbprint of the token encryption certificate.")]
	[string] $enc_certificate_thumbprint,

	[parameter(HelpMessage = "The token encryption certificate.")]
	[string] $enc_certificate_file,

	[parameter(HelpMessage = "Notes about the application.")]
	[string] $app_notes_file
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


#
# "Constants"
#

$DefaultTokenLifetime = 750 # 12.5 hours


##########
# Section with functions to add one Issuance Transform Rule (ITR)
#

function AddEnvironmentTypeClaimRule ( [string] $env_type)
{
   $rule = '@RuleName="Emit Environment Type" => issue(Type = "http://schemas.infor.com/claims/EnvironmentType", Value = "' + "${env_type}" + '");'

   echo "${rule}"
}

function AddUPNClaim_ITR ()
{
   $rule = '
@RuleName="Pass Through UPN claim"
@RuleTemplate="PassThroughClaims"
 c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]
 => issue(claim = c);
'

   echo "${rule}"
}

function AddNameClaim_ITR ()
{
   $rule = '
@RuleName="Pass Through Name claim"
@RuleTemplate="PassThroughClaims"
 c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]
 => issue(claim = c);
'

   echo "${rule}"
}

function AddCustomerClaim_ITR ()
{
   $rule = '
@RuleTemplate = "MapClaims"
@RuleName = "Emit Customer claim"
c:[Type == "http://schemas.infor.com/claims/customername"]
 => issue(Type = "http://schemas.infor.com/claims/Customer",
     Issuer = c.Issuer,
	 OriginalIssuer = c.OriginalIssuer,
	 Value = c.Value,
	 ValueType = c.ValueType);
'

   echo "${rule}"
}

function AddIdentityClaim_ITR ()
{
   $rule = '
@RuleName="Pass Through Identity claim"
@RuleTemplate="PassThroughClaims"
 c:[Type == "http://schemas.infor.com/claims/Identity"]
 => issue(claim = c);
'

   echo "${rule}"
}

function AddIdentity2Claim_ITR ()
{
   $rule = '
@RuleName="Pass Through Identity2 claim"
@RuleTemplate="PassThroughClaims"
 c:[Type == "http://schemas.infor.com/claims/Identity2"]
 => issue(claim = c);
'

   echo "${rule}"
}

function AddClientPrincipalClaim_ITR ()
{
	   $rule = '
		@RuleName="Pass Through Client Principal claim"
		@RuleTemplate="PassThroughClaims"
		c:[Type == "http://schemas.infor.com/claims/ClientPrincipalName"]
		=> issue(claim = c);
		'
		echo "${rule}"
}

function AddExternalUserIdClaim_ITR ()
{
	   $rule = '
		@RuleName="Pass Through External UserId claim"
		@RuleTemplate="PassThroughClaims"
		c:[Type == "http://schemas.infor.com/claims/ExternalUserId"]
		=> issue(claim = c);
		'
		echo "${rule}"
}

function AddInforCommunitiesProfileClaim_ITR ()
{
	   $rule = '
		@RuleName="Pass Through Infor Communities Profile claim"
		@RuleTemplate="PassThroughClaims"
		c:[Type == "http://schemas.infor.com/claims/CommunitiesProfilePage"]
		=> issue(claim = c);
		'
		echo "${rule}"
}

function AddERPPersonIdClaim_ITR ()
{
   $rule = '
@RuleName="Emit ERP Person ID claim"
c1:[Type == "http://schemas.infor.com/claims/userid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/ErpPersonId"),
    query = "WITH XMLNAMESPACES (''http://schemas.infor.com/claimvalues'' as ins) select Xml=(select BOD.PersonID as ''ins:PersonID'', BOD.AccountingEntity as ''ins:AccountingEntity'', BOD.Lid as ''ins:LogicalId'' for xml path(''ins:ErpPerson''),elements) FROM dbo.Users USR JOIN dbo.Properties P on USR.Id = P.UserId JOIN dbo.PropertyTypes PT on P.PropertyTypeId = PT.Id JOIN dbo.PersonBODs BOD on BOD.DistinguishedName = P.Value where PT.Name = ''UPN'' AND USR.Id = {0}",
    param = c1.Value);
'

   echo "${rule}"
}

function AddCustomerTenantTempClaimRule ()
{
   $rule = '
@RuleName="Emit temporary IDs for customer and tenant"
c1:[Type == "http://schemas.infor.com/claims/Customer"] &&
c2:[Type == "http://schemas.infor.com/claims/EnvironmentType"]
 => add(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/customerid",
             "http://schemas.infor.com/claims/customername",
             "http://schemas.infor.com/claims/customerstatus",
             "http://schemas.infor.com/claims/tenantid",
             "http://schemas.infor.com/claims/Tenant"),
    query = "SELECT CAST(Customers.Id as VARCHAR), Customers.Name, CAST(Customers.Status as VARCHAR), CAST(Tenants.Id as VARCHAR), Tenants.Name FROM Customers inner join Tenants on Customers.Id = Tenants.CustomerId inner join EnvironmentTypes on Tenants.EnvironmentTypeId = EnvironmentTypes.Id WHERE Customers.Name = {0} and EnvironmentTypes.Name = {1}",
    param = c1.Value, param = c2.Value);
'

   echo "${rule}"
}

function AddCustomerTenantTempClaimRuleForIFSAuthorization ()
{
   $rule = '
@RuleName="Emit temporary IDs for customer and tenant"
c1:[Type == "http://schemas.infor.com/claims/Customer", Value != "INFOR24"] &&
c2:[Type == "http://schemas.infor.com/claims/EnvironmentType"]
 => add(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/customerid",
             "http://schemas.infor.com/claims/customerstatus",
             "http://schemas.infor.com/claims/tenantid"),
    query = "SELECT CAST(Customers.Id as VARCHAR), CAST(Customers.Status as VARCHAR), CAST(Tenants.Id as VARCHAR) FROM Customers inner join Tenants on Customers.Id = Tenants.CustomerId inner join EnvironmentTypes on Tenants.EnvironmentTypeId = EnvironmentTypes.Id WHERE Customers.Name = {0} and EnvironmentTypes.Name = {1}",
    param = c1.Value, param = c2.Value);
'

   echo "${rule}"
}

function AddUserTempClaimRule ()
{
   $rule = '
@RuleName="Emit temporary IDs for user"
c1:[Type == "http://schemas.infor.com/claims/customerid"] &&
c2:[Type == "http://schemas.infor.com/claims/tenantid"] &&
c3:[Type == "http://schemas.infor.com/claims/IFSUserLookupValue"]
 => add(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/userid",
             "http://schemas.infor.com/claims/tenantuserid",
             "http://schemas.infor.com/claims/isifsapplicationadmin"),
    query = "SELECT CAST(Users.Id as VARCHAR), CAST(TenantUsers.Id as VARCHAR), CAST(Users.isIFSApplicationAdmin as VARCHAR) FROM Users inner join TenantUsers on Users.Id = TenantUsers.UserId WHERE Users.CustomerId = {0} and Users.UserIdentifier = {2} and TenantUsers.TenantId = {1}",
    param = c1.Value, param = c2.Value, param = c3.Value);
'

   echo "${rule}"
}

function AddSecurityRoleTempClaim_ITR ()
{
   $md_type = "'Security Role'"
   $rule = '
@RuleName="Emit temporary ID for security role"
c1:[Type == "http://schemas.infor.com/claims/tenantuserid"]
 => add(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/securityroleid",
             "http://schemas.infor.com/claims/SecurityRole"),
    query = "SELECT CAST(MasterDataNodes.Id as VARCHAR), MasterDataNodes.Name FROM MasterDataTypes inner join MasterDataNodes on MasterDataTypes.Id = MasterDataNodes.MasterDataTypeId inner join TenantUserMasterDataNodes on MasterDataNodes.Id = TenantUserMasterDataNodes.MasterDataNodes_Id inner join TenantUsers on TenantUsers.Id = TenantUserMasterDataNodes.TenantUsers_Id WHERE TenantUsers.Id = {0} and MasterDataTypes.Name = ' + "${md_type}" + '",
    param = c1.Value);
'

   echo "${rule}"
}

function AddTenantClaim_ITR ()
{
   $rule = '
@RuleName="Emit Tenant claim"
c1:[Type == "http://schemas.infor.com/claims/Tenant"]
 => issue(Type = "http://schemas.infor.com/claims/Tenant",
    Issuer = c1.Issuer,
    OriginalIssuer = c1.OriginalIssuer,
    Value = c1.Value,
    ValueType = c1.ValueType);
'

   echo "${rule}"
}

function AddSecurityRoleClaim_ITR ()
{
   $rule = '
@RuleName="Emit Security Role claim"
c1:[Type == "http://schemas.infor.com/claims/SecurityRole"]
 => issue(Type = "http://schemas.infor.com/claims/SecurityRole",
    Issuer = c1.Issuer,
    OriginalIssuer = c1.OriginalIssuer,
    Value = c1.Value,
    ValueType = c1.ValueType);
'

   echo "${rule}"
}

# For OnSaas, for the IFS RPT a modification is done to the Security Role UserAdmin:
#    UserAdmin will be transformed into UserAdmin_I
# This new role has less authorizations in the IFS application
# This transformation is done in two separate rules:
#     1. Emit all SecurityRole claims that are not UserAdmin
#     2. If a UserAdmin claim is found, issue a claim with the new name
function AddSecurityRoleClaimOnSaaS_ITR ()
{
   $rule = '
@RuleName="Emit Security Role claim if not UserAdmin"
c1:[Type == "http://schemas.infor.com/claims/SecurityRole", Value !~ "^(?i)UserAdmin$"]
 => issue(Type = "http://schemas.infor.com/claims/SecurityRole",
    Issuer = c1.Issuer,
    OriginalIssuer = c1.OriginalIssuer,
    Value = c1.Value,
    ValueType = c1.ValueType);
'

   echo "${rule}"
}

function AddTransformUserAdminSecurityRoleClaimOnSaaS_ITR ()
{
   $rule = '
@RuleName="Transform and emit UserAdmin Security Role claim"
c1:[Type == "http://schemas.infor.com/claims/SecurityRole", Value =~ "^(?i)UserAdmin$"]
 => issue(Type = "http://schemas.infor.com/claims/SecurityRole",
    Issuer = c1.Issuer,
    OriginalIssuer = c1.OriginalIssuer,
    Value = "UserAdmin_I",
    ValueType = c1.ValueType);
'

   echo "${rule}"
}

function AddIFSApplicationAdminSecurityRoleClaimOnPrem_ITR ()
{
   $rule = '
@RuleName="Emit IFSApplicationAdmin Security Role claim"
c1:[Type == "http://schemas.infor.com/claims/isifsapplicationadmin", Value == "1"]
 => issue(Type = "http://schemas.infor.com/claims/SecurityRole",
    Issuer = c1.Issuer,
    OriginalIssuer = c1.OriginalIssuer,
    Value = "IFSApplicationAdmin",
    ValueType = c1.ValueType);
'

   echo "${rule}"
}

function AddIFSApplicationAdminSecurityRoleClaimOnSaaS_ITR ()
{
   $rule = '
@RuleName="Emit IFSApplicationAdmin Security Role claim"
c1:[Type == "http://schemas.infor.com/claims/isifsapplicationadmin", Value == "1"]
 => issue(Type = "http://schemas.infor.com/claims/SecurityRole",
    Issuer = c1.Issuer,
    OriginalIssuer = c1.OriginalIssuer,
    Value = "IFSApplicationAdmin_I",
    ValueType = c1.ValueType);
'

   echo "${rule}"
}

# Presence of this claim (for an application type) means that the user has at least one of the security roles that
# are linked to the application type. In the IFS application the presence of this claim is used to secure methods.
function AddApplicationInstanceClaim_ITR ()
{
   $rule = '
@RuleName="Emit Application Instance claim"
c1:[Type == "http://schemas.infor.com/claims/securityroleid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/ApplicationInstance"),
    query = "SELECT ApplicationTypes.Name FROM Applications inner join ApplicationTypes on ApplicationTypes.Id = Applications.ApplicationTypeId inner join ApplicationMasterDataNodes on Applications.Id = ApplicationMasterDataNodes.Applications_Id inner join MasterDataNodes on MasterDataNodes.Id = ApplicationMasterDataNodes.MasterDataNodes_Id WHERE MasterDataNodes.Id = {0}",
    param = c1.Value);
'

   echo "${rule}"
}

function AddIFSApplicationInstanceClaim_ITR ()
{
   $rule = '
@RuleName="Emit IFSApplicationAdmin Security Role claim"
c1:[Type == "http://schemas.infor.com/claims/isifsapplicationadmin", Value == "1"]
 => issue(Type = "http://schemas.infor.com/claims/ApplicationInstance",
    Issuer = c1.Issuer,
    OriginalIssuer = c1.OriginalIssuer,
    Value = "IFS",
    ValueType = c1.ValueType);
'

   echo "${rule}"
}

function AddAccountingEntityClaim_ITR ()
{
   $md_type = "'Accounting Entity'"
   $rule = '
@RuleName="Emit Accounting Entity claim"
c1:[Type == "http://schemas.infor.com/claims/tenantuserid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/AccountingEntity"),
    query = "SELECT MasterDataNodes.Name FROM MasterDataTypes inner join MasterDataNodes on MasterDataTypes.Id = MasterDataNodes.MasterDataTypeId inner join TenantUserMasterDataNodes on MasterDataNodes.Id = TenantUserMasterDataNodes.MasterDataNodes_Id inner join TenantUsers on TenantUsers.Id = TenantUserMasterDataNodes.TenantUsers_Id WHERE TenantUsers.Id = {0} and MasterDataTypes.Name = ' + "${md_type}" + '",
    param = c1.Value);
'

   echo "${rule}"
}

function AddLocationClaim_ITR ()
{
   $md_type = "'Location'"
   $rule = '
@RuleName="Emit Location claim"
c1:[Type == "http://schemas.infor.com/claims/tenantuserid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/Location"),
    query = "SELECT MasterDataNodes.Name FROM MasterDataTypes inner join MasterDataNodes on MasterDataTypes.Id = MasterDataNodes.MasterDataTypeId inner join TenantUserMasterDataNodes on MasterDataNodes.Id = TenantUserMasterDataNodes.MasterDataNodes_Id inner join TenantUsers on TenantUsers.Id = TenantUserMasterDataNodes.TenantUsers_Id WHERE TenantUsers.Id = {0} and MasterDataTypes.Name = ' + "${md_type}" + '",
    param = c1.Value);
'

   echo "${rule}"
}

function AddEAMTemplateClaim_ITR ()
{
   $md_type = "'EAM Template'"
   $rule = '
@RuleName="Emit EAM Template claim"
c1:[Type == "http://schemas.infor.com/claims/tenantuserid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/EAMTemplate"),
    query = "SELECT MasterDataNodes.Name FROM MasterDataTypes inner join MasterDataNodes on MasterDataTypes.Id = MasterDataNodes.MasterDataTypeId inner join TenantUserMasterDataNodes on MasterDataNodes.Id = TenantUserMasterDataNodes.MasterDataNodes_Id inner join TenantUsers on TenantUsers.Id = TenantUserMasterDataNodes.TenantUsers_Id WHERE TenantUsers.Id = {0} and MasterDataTypes.Name = ' + "${md_type}" + '",
    param = c1.Value);
'

   echo "${rule}"
}

function AddHMSTemplateClaim_ITR ()
{
   $md_type = "'HMS Template'"
   $rule = '
@RuleName="Emit HMS Template claim"
c1:[Type == "http://schemas.infor.com/claims/tenantuserid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/HMSTemplate"),
    query = "SELECT MasterDataNodes.Name FROM MasterDataTypes inner join MasterDataNodes on MasterDataTypes.Id = MasterDataNodes.MasterDataTypeId inner join TenantUserMasterDataNodes on MasterDataNodes.Id = TenantUserMasterDataNodes.MasterDataNodes_Id inner join TenantUsers on TenantUsers.Id = TenantUserMasterDataNodes.TenantUsers_Id WHERE TenantUsers.Id = {0} and MasterDataTypes.Name = ' + "${md_type}" + '",
    param = c1.Value);
'

   echo "${rule}"
}

function AddGivenNameClaim_ITR ()
{
   $md_type = "'Given Name'"
   $rule = '
@RuleName="Emit Given Name claim"
c1:[Type == "http://schemas.infor.com/claims/customerid"] &&
c2:[Type == "http://schemas.infor.com/claims/userid"] &&
c3:[Type == "http://schemas.infor.com/claims/tenantid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"),
    query = "SELECT Value FROM Users inner join Properties on Users.Id = Properties.UserId inner join (select Id, Name from PropertyTypes where TenantId = {2} or CustomerId = {0}) TempPT on Properties.PropertyTypeId = TempPT.Id WHERE Users.Id = {1} and TempPT.Name = ' + "${md_type}" + '",
    param = c1.Value, param = c2.Value, param = c3.Value);
'

   echo "${rule}"
}

function AddSurnameClaim_ITR ()
{
   $md_type = "'Surname'"
   $rule = '
@RuleName="Emit Surname claim"
c1:[Type == "http://schemas.infor.com/claims/customerid"] &&
c2:[Type == "http://schemas.infor.com/claims/userid"] &&
c3:[Type == "http://schemas.infor.com/claims/tenantid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"),
    query = "SELECT Value FROM Users inner join Properties on Users.Id = Properties.UserId inner join (select Id, Name from PropertyTypes where TenantId = {2} or CustomerId = {0}) TempPT on Properties.PropertyTypeId = TempPT.Id WHERE Users.Id = {1} and TempPT.Name = ' + "${md_type}" + '",
    param = c1.Value, param = c2.Value, param = c3.Value);
'

   echo "${rule}"
}

function AddCommonNameClaim_ITR ()
{
   $md_type = "'Common Name'"
   $rule = '
@RuleName="Emit Common Name claim"
c1:[Type == "http://schemas.infor.com/claims/customerid"] &&
c2:[Type == "http://schemas.infor.com/claims/userid"] &&
c3:[Type == "http://schemas.infor.com/claims/tenantid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.xmlsoap.org/claims/CommonName"),
    query = "SELECT Value FROM Users inner join Properties on Users.Id = Properties.UserId inner join (select Id, Name from PropertyTypes where TenantId = {2} or CustomerId = {0}) TempPT on Properties.PropertyTypeId = TempPT.Id WHERE Users.Id = {1} and TempPT.Name = ' + "${md_type}" + '",
    param = c1.Value, param = c2.Value, param = c3.Value);
'

   echo "${rule}"
}

function AddEmailAddressClaim_ITR ()
{
   $md_type = "'Email Address'"
   $rule = '
@RuleName="Emit Email Address claim"
c1:[Type == "http://schemas.infor.com/claims/customerid"] &&
c2:[Type == "http://schemas.infor.com/claims/userid"] &&
c3:[Type == "http://schemas.infor.com/claims/tenantid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
    query = "SELECT Value FROM Users inner join Properties on Users.Id = Properties.UserId inner join (select Id, Name from PropertyTypes where TenantId = {2} or CustomerId = {0}) TempPT on Properties.PropertyTypeId = TempPT.Id WHERE Users.Id = {1} and TempPT.Name = ' + "${md_type}" + '",
    param = c1.Value, param = c2.Value, param = c3.Value);
'

   echo "${rule}"
}

function AddTitleClaim_ITR ()
{
   $md_type = "'Title'"
   $rule = '
@RuleName="Emit Title claim"
c1:[Type == "http://schemas.infor.com/claims/customerid"] &&
c2:[Type == "http://schemas.infor.com/claims/userid"] &&
c3:[Type == "http://schemas.infor.com/claims/tenantid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"),
    query = "SELECT Value FROM Users inner join Properties on Users.Id = Properties.UserId inner join (select Id, Name from PropertyTypes where TenantId = {2} or CustomerId = {0}) TempPT on Properties.PropertyTypeId = TempPT.Id WHERE Users.Id = {1} and TempPT.Name = ' + "${md_type}" + '",
    param = c1.Value, param = c2.Value, param = c3.Value);
'

   echo "${rule}"
}

function AddPreferredLanguageClaim_ITR ()
{
   $md_type = "'PreferredLanguage'"
   $rule = '
@RuleName="Emit PreferredLanguage claim"
c1:[Type == "http://schemas.infor.com/claims/customerid"] &&
c2:[Type == "http://schemas.infor.com/claims/userid"] &&
c3:[Type == "http://schemas.infor.com/claims/tenantid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/preferredlanguage"),
    query = "SELECT Value FROM Users inner join Properties on Users.Id = Properties.UserId inner join (select Id, Name from PropertyTypes where TenantId = {2} or CustomerId = {0}) TempPT on Properties.PropertyTypeId = TempPT.Id WHERE Users.Id = {1} and TempPT.Name = ' + "${md_type}" + '",
    param = c1.Value, param = c2.Value, param = c3.Value);
'

   echo "${rule}"
}

function AddGroupSIDClaim_ITR ()
{
   $rule = '
@RuleName="Pass Through Group SID claim"
@RuleTemplate="PassThroughClaims"
 c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid"]
 => issue(claim = c);
'

   echo "${rule}"
}

function AddGroupWithDomainNameClaim_ITR()
{
	$rule = '
	@RuleTemplate = "LdapClaims"
	@RuleName="Extract Group with domain claim"
	c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
	=> issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/claims/Group"), query = ";tokenGroups(domainQualifiedName);{0}", param = c.Value);
	'

   echo "${rule}"
}

function AddIFSAuthenticationMode_ITR ()
{
   $rule = '@RuleName="Emit IFS Authentication Mode" => issue(Type = "http://schemas.infor.com/claims/IFSAuthenticationMode", Value = "SAMLToken");'

   echo "${rule}"
}

function AddInternalTransientIdClaim_ITR ()
{
   $rule = '
@RuleName="Custom rule for internal Transient ID"
c1:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"] &&
c2:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant"]
 => add(store = "_OpaqueIdStore", 
        types = ("http://infor/internal/sessionid"),
        query = "{0};{1};{2};{3};{4}",
        param = "useEntropy",
        param = c1.Value,
        param = c1.OriginalIssuer,
        param = "",
        param = c2.Value);
'

   echo "${rule}"
}

function AddTransientNameIdClaim_ITR ( [string] $spn)
{
   $rule = '
@RuleName="Custom rule to emit a transient NameID"
c:[Type == "http://infor/internal/sessionid"]
 => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
          Issuer = c.Issuer,
          OriginalIssuer = c.OriginalIssuer,
          Value = c.Value,
          ValueType = c.ValueType,
          Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/spnamequalifier"] = "' + "${spn}" + '");
'

   echo "${rule}"
}

function AddMingleKeysClaims_ITR()
{
   $rule = '
	@RuleName="Emit Mingle Mobile App claim"
c1:[Type == "http://schemas.infor.com/claims/customerid"]
 && c2:[Type == "http://schemas.infor.com/claims/userid"]
 && c3:[Type == "http://schemas.infor.com/claims/tenantid"]
 => issue(store = "InforFS data store", types = ("http://schemas.infor.com/claims/MingleMobileAccessKey", "http://schemas.infor.com/claims/MingleMobilePrivateKey", "http://schemas.infor.com/claims/MingleUserGuid", "http://schemas.infor.com/claims/MingleUserAccessKey", "http://schemas.infor.com/claims/MingleUserPrivateKey"), query = "EXEC [dbo].[GetCreateApiKeys] @UserId = {0}", param = c2.Value);

'

   echo "${rule}"
}

##########
# Functions to add a set of Issuance Transform Rules (ITRs) to an RP.
#

function AddAll_WIF_ITRs ( [string] $rp_name, [string] $env_type, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddUPNClaim_ITR
   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddApplicationInstanceClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddEAMTemplateClaim_ITR
   $totalSet += AddGivenNameClaim_ITR
   $totalSet += AddSurnameClaim_ITR
   $totalSet += AddCommonNameClaim_ITR
   $totalSet += AddEmailAddressClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_IFS_ITRs ( [string] $rp_name, [string] $env_type, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddUPNClaim_ITR
   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   if ($isOnSaas)
   {
      $totalSet += AddSecurityRoleClaimOnSaaS_ITR
      $totalSet += AddTransformUserAdminSecurityRoleClaimOnSaaS_ITR
      $totalSet += AddIFSApplicationAdminSecurityRoleClaimOnSaaS_ITR
   }
   else
   {
      $totalSet += AddSecurityRoleClaim_ITR
      $totalSet += AddIFSApplicationAdminSecurityRoleClaimOnPrem_ITR
   }
   $totalSet += AddApplicationInstanceClaim_ITR
   $totalSet += AddIFSApplicationInstanceClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddEAMTemplateClaim_ITR
   $totalSet += AddGivenNameClaim_ITR
   $totalSet += AddSurnameClaim_ITR
   $totalSet += AddCommonNameClaim_ITR
   $totalSet += AddEmailAddressClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR
   $totalSet += AddERPPersonIdClaim_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_ION_ITRs ( [string] $rp_name, [string] $env_type, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddCommonNameClaim_ITR
   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_IONGRID_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
	$totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddCommonNameClaim_ITR
   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_MCC_ITRs ( [string] $rp_name, [string] $env_type, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddUPNClaim_ITR
   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_Companion_ITRs ( [string] $rp_name, [string] $env_type, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddUPNClaim_ITR
   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddApplicationInstanceClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddEAMTemplateClaim_ITR
   $totalSet += AddGivenNameClaim_ITR
   $totalSet += AddSurnameClaim_ITR
   $totalSet += AddCommonNameClaim_ITR
   $totalSet += AddEmailAddressClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR
   $totalSet += AddGroupWithDomainNameClaim_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_SunSystems_ITRs ( [string] $rp_name, [string] $env_type, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddUserTempClaimRule
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddPreferredLanguageClaim_ITR
   $totalSet += AddCommonNameClaim_ITR   
   $totalSet += AddGivenNameClaim_ITR 
   $totalSet += AddTitleClaim_ITR 
   $totalSet += AddEmailAddressClaim_ITR 
   $totalSet += AddUPNClaim_ITR 

   if (! $isOnSaas)
   {
      $totalSet += AddGroupSIDClaim_ITR
   }
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_SmartStream_ITRs ( [string] $rp_name, [string] $env_type, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_BI_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddCommonNameClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_ES_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_Collaboration_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddGivenNameClaim_ITR
   $totalSet += AddSurnameClaim_ITR
   $totalSet += AddEmailAddressClaim_ITR
   $totalSet += AddTitleClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR
   $totalSet += AddMingleKeysClaims_ITR
   $totalSet += AddExternalUserIdClaim_ITR
   $totalSet += AddInforCommunitiesProfileClaim_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_IR_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddGivenNameClaim_ITR
   $totalSet += AddSurnameClaim_ITR
   $totalSet += AddEmailAddressClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_IRN_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
	
   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddGivenNameClaim_ITR
   $totalSet += AddSurnameClaim_ITR
   $totalSet += AddEmailAddressClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_WIF_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function AddAll_Fedlet_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddUPNClaim_ITR
   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddApplicationInstanceClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddEAMTemplateClaim_ITR
   $totalSet += AddGivenNameClaim_ITR
   $totalSet += AddSurnameClaim_ITR
   $totalSet += AddCommonNameClaim_ITR
   $totalSet += AddEmailAddressClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_OPTIVA_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddGivenNameClaim_ITR
   $totalSet += AddSurnameClaim_ITR
   $totalSet += AddEmailAddressClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}


function Add_LN_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddUPNClaim_ITR
   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_XM_ITRs  ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
    $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddUPNClaim_ITR
   if (! $isOnSaas)
   {
      $totalSet += AddNameClaim_ITR
   }
   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddApplicationInstanceClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddEAMTemplateClaim_ITR
   $totalSet += AddGivenNameClaim_ITR
   $totalSet += AddSurnameClaim_ITR
   $totalSet += AddCommonNameClaim_ITR
   $totalSet += AddEmailAddressClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR
   $totalSet += AddERPPersonIdClaim_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_PaymentProcessing_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddApplicationInstanceClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_AutoConnect_ITRs ( [string] $rp_name, [string] $env_type, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddUPNClaim_ITR
   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_HMS_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddHMSTemplateClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_StoreRoom_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_SCE_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_Grid_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR
   $totalSet += AddERPPersonIdClaim_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_BV_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR 
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddSecurityRoleClaim_ITR
   $totalSet += AddAccountingEntityClaim_ITR
   $totalSet += AddLocationClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}

function Add_SAMLP_ITRs ( [string] $rp_name, [string] $env_type, [string] $spn, [bool] $isOnSaas)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddInternalTransientIdClaim_ITR
   $totalSet += AddTransientNameIdClaim_ITR "${spn}"

   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddCustomerClaim_ITR
   $totalSet += AddTenantClaim_ITR
   $totalSet += AddIdentityClaim_ITR
   $totalSet += AddIdentity2Claim_ITR
   $totalSet += AddClientPrincipalClaim_ITR
   $totalSet += AddIFSAuthenticationMode_ITR

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceTransformRules $totalSet_string
}



##############
# Section with functions to add Issuance Authorization Rules (IARs).
#

function AddCustomerApplicationEnabledRule ()
{
   $at = "'" + "${app_type}" + "'"
   $rule = '
@RuleName="Create intermediate claim for entitlement of an ApplicationType for a Customer"
c:[Type == "http://schemas.infor.com/claims/Customer", Value !~ "^(?i)INFOR24$"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/entitlementenabled"),
    query = "SELECT CAST(CustomerApplicationTypes.isEnabled as VARCHAR) FROM Customers inner join CustomerApplicationTypes on Customers.Id = CustomerApplicationTypes.Customers_Id inner join ApplicationTypes on CustomerApplicationTypes.ApplicationTypes_Id = ApplicationTypes.Id WHERE Customers.Name = {0} and ApplicationTypes.Name = ' + "${at}" + '",
    param = c.Value);
'

   echo "${rule}"
}

function AddTenantApplicationRule ()
{
   $at = "'" + "${app_type}" + "'"
   $rule = '
@RuleName="Emit temporary TenantApplication"
c:[Type == "http://schemas.infor.com/claims/tenantid"]
 => issue(store = "InforFS data store",
    types = ("http://schemas.infor.com/claims/tenantapplicationid"),
    query = "SELECT CAST(Applications.Id as VARCHAR) FROM Applications inner join TenantApplications on Applications.Id = TenantApplications.Applications_Id inner join Tenants on Tenants.Id = TenantApplications.Tenants_Id inner join ApplicationTypes on ApplicationTypes.Id = Applications.ApplicationTypeId WHERE ApplicationTypes.Name = ' + "${at}" + ' and Tenants.Id = {0}",
    param = c.Value);
'

   echo "${rule}"
}

function AddPermitTenantUserApplicationRule ()
{
   if (${isOnSaas})
   {
      $rule = '
@RuleName="Permit for TenantUsers and TenantApplications"
c1:[Type == "http://schemas.infor.com/claims/entitlementenabled", Value == "1"] &&
c2:[Type == "http://schemas.infor.com/claims/tenantuserid"] &&
c3:[Type == "http://schemas.infor.com/claims/tenantapplicationid"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit",
          Value = "PermitUsersWithClaim");
'
   }
   else
   {
      $rule = '
@RuleName="Permit for TenantUsers and TenantApplications"
c1:[Type == "http://schemas.infor.com/claims/tenantuserid"] &&
c2:[Type == "http://schemas.infor.com/claims/tenantapplicationid"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit",
          Value = "PermitUsersWithClaim");
'
   }

   echo "${rule}"
}

function AddDenyDisabledCustomerRule ()
{
   $rule = '
@RuleName="Deny users of disabled customer"
c:[Type == "http://schemas.infor.com/claims/customerstatus", Value == "2"] 
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny",
          Value ="DenyUsersWithClaim");
'

   echo "${rule}"
}

function AddDenyNonInfor24SaaSAdminsRule ()
{
   $rule = '
@RuleName="Deny for SaaSAdmin from non-INFOR24"
c1:[Type == "http://schemas.infor.com/claims/SecurityRole", Value == "SaaSAdmin"] &&
c2:[Type == "http://schemas.infor.com/claims/Customer", Value !~ "^(?i)INFOR24$"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny",
          Value ="DenyUsersWithClaim");
'

   echo "${rule}"
}

function AddPermitExternalUsers()
{
	$rule = '
	@RuleName="Permit for External Users"
	c1:[Type == "http://schemas.infor.com/claims/ExternalUserId"]
	=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "PermitUsersWithClaim");
	'
	echo "${rule}"
}

function AddPermitAllRule ()
{
   $rule = '
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit",
          Value = "true");
'

   echo "${rule}"
}

function AddPermitTenantUser_IAR ( [string] $rp_name, [string] $env_type, [bool] $includeExternalUsers = $false)
{
   $totalSet = @()

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   if (${isOnSaas})
   {
      $totalSet += AddCustomerApplicationEnabledRule
   }
   $totalSet += AddCustomerTenantTempClaimRule
   $totalSet += AddDenyDisabledCustomerRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddTenantApplicationRule
   $totalSet += AddPermitTenantUserApplicationRule

   if (${includeExternalUsers}) 
   {
		$totalSet += AddPermitExternalUsers
   }

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceAuthorizationRules $totalSet_string
}

function AddPermitSaaSIFS_IAR ( [string] $rp_name, [string] $env_type)
{
   $totalSet = @()

   $totalSet += AddPermitAllRule

   $totalSet += AddEnvironmentTypeClaimRule "${env_type}"

   $totalSet += AddCustomerTenantTempClaimRuleForIFSAuthorization
   $totalSet += AddDenyDisabledCustomerRule
   $totalSet += AddUserTempClaimRule
   $totalSet += AddSecurityRoleTempClaim_ITR
   $totalSet += AddDenyNonInfor24SaaSAdminsRule

   $totalSet_string = [string] $totalSet

   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -IssuanceAuthorizationRules $totalSet_string
}

function AddPermitAll_IAR ( [string] $rp_name)
{
   Set-ADFSRelyingPartyTrust -TargetName "${rp_name}"    `
                             -IssuanceAuthorizationRules '=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'
}



##############
# Section with functions to remove and create a Relying Party.
#

# Remove an RP.
#
function RemoveRelyingParty ( [string] $rp_name, [string] $rp_id)
{
   $rpt = Get-ADFSRelyingPartyTrust -Identifier "${rp_id}"
   if ( "$rpt" -ne "")
   {
      echo "Removing RP with RP-Identifier: ${rp_id}"
      Remove-ADFSRelyingPartyTrust -targetIdentifier "${rp_id}"
   }
   else
   {
      $rpt = Get-ADFSRelyingPartyTrust -Name "${rp_name}"
      if ( "$rpt" -ne "")
      {
         echo "Removing RP with name: ${rp_name}"
         Remove-ADFSRelyingPartyTrust -targetName "${rp_name}"
      }
   }
}


# Create WIF-based RP.
#
function CreateBaseWIFRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint)
{
   echo "Creating RP for ${rp_name}"

   Add-ADFSRelyingPartyTrust -Name "${rp_name}"           `
                             -Identifier "${rp_id}"       `
                             -WsFedEndpoint "${endpoint}" `
                             -ProtocolProfile  WSFederation	`
                             -TokenLifetime $DefaultTokenLifetime

   if ( "${rp_notes}" -ne "" )
   {
      Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -Notes "${rp_notes}"
   }
   if ($enc_certificate_thumbprint) {
      $crt=get-childitem -path cert:\LocalMachine\My\$enc_certificate_thumbprint
      Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -EncryptionCertificate $crt
   }
   if ($enc_certificate_file) {
      $crt = New-Object System.Security.Cryptography.X509Certificates.X509Certificate "${enc_certificate_file}"
	  Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -EncryptionCertificate $crt
   }
}

function CreateFullWIFRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   AddAll_WIF_ITRs "${rp_name}" "${env_type}" $isOnSaas
}

function CreateSyteLineRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateFullWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}" $isOnSaas
}

function CreateCompanionRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_Companion_ITRs "${rp_name}" "${env_type}" $isOnSaas
}

function CreateMCCRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
	CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_MCC_ITRs "${rp_name}" "${env_type}" $isOnSaas
}

function CreateIONRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_ION_ITRs "${rp_name}" "${env_type}" $isOnSaas
}

function CreateIONGRIDRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_IONGRID_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateSunSystemsRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_SunSystems_ITRs "${rp_name}" "${env_type}" $isOnSaas
}

function CreateSmartStreamRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_SmartStream_ITRs "${rp_name}" "${env_type}" $isOnSaas
}

function CreateBIRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_BI_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateESRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_ES_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateCollaborationRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}" $true

   # Add Issuance Transform Rules
   Add_Collaboration_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateIRRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_IR_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateIRNRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_IRN_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateWIFRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_WIF_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateOPTIVARelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_OPTIVA_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateIFSRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseWIFRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"
   
   if (! $isOnSaas)
   {
      # Need additional RP-Identifier for the IFS Web Services that run at IIS application '/IFSServices'
      $ws_rp_id = [regex]::replace(${rp_id}, "/IFS/$", "/IFSServices/")
      Set-ADFSRelyingPartyTrust -TargetName "${rp_name}"  -Identifier "${rp_id}", "${ws_rp_id}"
   }

   # Add Issuance Authorization Rules
   if ($isOnSaas)
   {
      AddPermitSaaSIFS_IAR "${rp_name}" "${env_type}"
   } else
   {
      AddPermitAll_IAR "${rp_name}"
   }
   # Add Issuance Transform Rules
   Add_IFS_ITRs "${rp_name}" "${env_type}" $isOnSaas
}


# Create Fedlet-based RP.
#
function CreateBaseFedletRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint)
{
   echo "Creating RP for ${rp_name}"

   $ep = New-ADFSSamlEndpoint -Binding "POST" -Protocol "SAMLAssertionConsumer" -Uri "${endpoint}"
   Add-ADFSRelyingPartyTrust -Name "${rp_name}"      `
                             -Identifier "${rp_id}"  `
                             -SamlEndpoint ${ep}       `
                             -ProtocolProfile  SAML	`
                             -TokenLifetime $DefaultTokenLifetime

   if ( "${rp_notes}" -ne "" )
   {
      Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -Notes "${rp_notes}"
   }
   if ($enc_certificate_thumbprint) {
      $crt=get-childitem -path cert:\LocalMachine\My\$enc_certificate_thumbprint
      Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -EncryptionCertificate $crt
   }
   if ($enc_certificate_file) {
      $crt = New-Object System.Security.Cryptography.X509Certificates.X509Certificate "${enc_certificate_file}"
	  Set-ADFSRelyingPartyTrust -TargetName "${rp_name}" -EncryptionCertificate $crt
   }
}

function CreateFullFedletRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   AddAll_Fedlet_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateXMRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
  CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

  # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_XM_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateEAMRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateFullFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}" $isOnSaas
}

function CreateLNRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_LN_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreatePaymentProcessingRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_PaymentProcessing_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateAutoConnectRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_AutoConnect_ITRs "${rp_name}" "${env_type}" $isOnSaas
}

function CreateHMSRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_HMS_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateStoreRoomRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_StoreRoom_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateSCERelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_SCE_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateGridRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_Grid_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateBVRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_BV_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}

function CreateSAMLPRelyingParty ( [string] $rp_name, [string] $rp_notes, [string] $env_type, [string] $rp_id, [string] $endpoint, [bool] $isOnSaas)
{
   CreateBaseFedletRelyingParty "${rp_name}" "${rp_notes}" "${env_type}" "${rp_id}" "${endpoint}"

   # Add Issuance Authorization Rules
   AddPermitTenantUser_IAR "${rp_name}" "${env_type}"

   # Add Issuance Transform Rules
   Add_SAMLP_ITRs "${rp_name}" "${env_type}" "${rp_id}" $isOnSaas
}


####
# Construct SaaS formats for Relying Party IDs
#

function PostFixWithEnvironmentType (  [string] $rp_id, [string] $env_type, [string] $separator)
{
   if (${rp_id}.EndsWith("${separator}"))
   { 
      return "${rp_id}${env_type}${separator}"
   }
   else
   {
      return "${rp_id}${separator}${env_type}"
   }
}

function ConstructSaaSRelyingPartyID (  [string] $rp_id, [string] $env_type)
{
   $urn = New-Object System.Uri( "${rp_id}")
   $urn_scheme = ${urn}.scheme
   switch -wildcard (${urn_scheme})
   {
      "http*" {  $loc_rp_id = PostFixWithEnvironmentType "${app_rpid}" "${env_type}" "/" }
      "urn" {  $loc_rp_id = PostFixWithEnvironmentType "${app_rpid}" "${env_type}" ":" }
      default { echo "Warning: unknown scheme ${urn_scheme} for RP-ID ${rp_id}"
                $loc_rp_id = PostFixWithEnvironmentType "${app_rpid}" "${env_type}" ":" }
   }

   return "${loc_rp_id}"
}


##############
##############
# Main section
#  No deployment specific data above this point! Everything must be parameterized!
#

if ( $saas )
{
   $env_types = @("PRD", "TRN", "TST", "DEV", "DEM", "AX1", "AX2", "AX3")
   $isOnSaas = $true
} else
{
   $env_types = @("PRD")
   $isOnSaas = $false
}

if ( "${app_notes_file}" -ne "")
{
   # Get-Content reads an array of objects (one per line of input), so join them.
   ${file_content} = Get-Content "${app_notes_file}"
   ${app_notes} = ":`r`n" + [string]::join([environment]::newline, ${file_content})
}
${app_notes} = "INFOR-GENERATED Relying Party Trust" + "${app_notes}"

if ( -not $noConfirm) {
	Write-Host ""
	Write-Host "Summary:"
	if ( $saas )
	{
	   Write-Host "  OnSaas installation  : true"
	}
	Write-Host "  Application type     : ${app_type}."
	Write-Host "  Application name     : ${app_name}."
	Write-Host "  Application notes    : ${app_notes}."
	Write-Host "  Relying Party ID     : ${app_rpid}."
	Write-Host "  Application endpoint : ${app_endpoint}."
	
	$cont = Read-Host "Start adding this Relying Party to the ADFS configuration?"
	
	if ( "$cont" -ne "y" -and "$cont" -ne "Y")
	{
	   Write-Host ""
	   Write-Host "ADFS configuration cancelled by user."
	
	   exit
	}
}

# Set the current directory to a correct value
#   See: http://huddledmasses.org/powershell-power-user-tips-current-directory/
[Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath

foreach ($env_type in $env_types)
{
   if ( $saas )
   {
      $rp_name = "${app_name} - ${env_type}"
      $rp_id = ConstructSaaSRelyingPartyID "${app_rpid}" "${env_type}"
      $endpoint = PostFixWithEnvironmentType "${app_endpoint}" "${env_type}" "/"
   } else
   {
      $rp_name = "${app_name}"
      $rp_id = "${app_rpid}"
      $endpoint = "${app_endpoint}"
   }

   RemoveRelyingParty "${rp_name}" "${rp_id}"

   switch (${app_type})
   {
      "SYTELINE"            { CreateSyteLineRelyingParty    "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "COMPANION"           { CreateCompanionRelyingParty   "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "ION"                 { CreateIONRelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "IONGRID"				{ CreateIONGRIDRelyingParty     "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "IFS"                 { CreateIFSRelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "SUNSYSTEMS"          { CreateSunSystemsRelyingParty  "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "SMARTSTREAM"         { CreateSmartStreamRelyingParty "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "BI"                  { CreateBIRelyingParty          "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "ENTERPRISESEARCH"    { CreateESRelyingParty          "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "CPM"                 { CreateWIFRelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "PLMPROCESS"          { CreateWIFRelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "IR"                  { CreateIRRelyingParty          "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
	  "IRN"                 { CreateIRNRelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
	  "OPTIVA"              { CreateOPTIVARelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
	  "MCC"                 { CreateMCCRelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
	  "WIF"                 { CreateWIFRelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }

      "EAM"                 { CreateEAMRelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "XM"                  { CreateXMRelyingParty          "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "LN"                  { CreateLNRelyingParty          "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "PAYMENT"             { CreatePaymentProcessingRelyingParty          "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "AUTOCONNECT"         { CreateAutoConnectRelyingParty "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "HMS"                 { CreateHMSRelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "STOREROOM"           { CreateStoreRoomRelyingParty   "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "SCE"                 { CreateSCERelyingParty         "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "GRID"                { CreateGridRelyingParty        "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
	  "BV"					{ CreateBVRelyingParty			"${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "SAMLP"               { CreateSAMLPRelyingParty       "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }

      "SNOP"                { CreateSAMLPRelyingParty       "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "LX"                  { CreateSAMLPRelyingParty       "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "XA"                  { CreateSAMLPRelyingParty       "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "INFINIUM"            { CreateSAMLPRelyingParty       "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "SYSTEM21"            { CreateSAMLPRelyingParty       "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "SHCM"                { CreateSAMLPRelyingParty       "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "ADAGE"               { CreateSAMLPRelyingParty       "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "COLLABORATIONENGINE" { CreateCollaborationRelyingParty       "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
      "SUPPLYWEB"           { CreateSAMLPRelyingParty       "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
	  "ISM"					{ CreateSyteLineRelyingParty    "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
	  "MONGOOSE"			{ CreateSyteLineRelyingParty    "${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
	  "IACM"				{ CreateWIFRelyingParty			"${rp_name}" "${app_notes}" "${env_type}" "${rp_id}" "${endpoint}" ${isOnSaas} }
   }
}

# SIG # Begin signature block
# MIIY9wYJKoZIhvcNAQcCoIIY6DCCGOQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUfgzqJDRCBm38LD3Y3HbtGQJ3
# ZA6gghPMMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQlGwNKXIHv
# YRQKrWSefUnmlSsEtjBqBgorBgEEAYI3AgEMMVwwWqBYgFYASQBuAGYAbwByACAA
# RgBlAGQAZQByAGEAdABpAG8AbgAgAFMAZQByAHYAaQBjAGUAcwAgAFAAbwB3AGUA
# cgBTAGgAZQBsAGwAIABzAGMAcgBpAHAAdDANBgkqhkiG9w0BAQEFAASCAQBvrlUL
# aK+KcFa1zYxQ1owNr/TH1avFNyegWSp6Yv3YXPIkl8LQGUx0xL+dlrGbdw9j2VKl
# cqZK3EmIbm4Q9bvj+Oi9g0YVNok/slidp79IFwiAFWNhJ0NGLwFfEAryqRwoACLf
# 0ajjHKistW4ynpmrLdJawLajg6K4gBmX6wdO+ZJr/DlqBJLtAI330npKWWfrUBfH
# bkv8rusFqMNvzf8BShK02lLpGMpVu/oSyshvimo1yeDntjgj5WFGBPVETXjDBpCQ
# M5OccDW0oamDScTeoHJZcI1ZwTPwNdMUuqPSaIh7TIirwviXSqZW3Ng0uUAhxZVk
# 5VBSwkOYFrJ6SjR0oYICCzCCAgcGCSqGSIb3DQEJBjGCAfgwggH0AgEBMHIwXjEL
# MAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYD
# VQQDEydTeW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzICEA7P
# 9DjI/r81bgTYapgbGlAwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG
# 9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MDYxNjE5NDkzNlowIwYJKoZIhvcNAQkE
# MRYEFBlVzXKgilI98gZRkFBIZcvCBkqkMA0GCSqGSIb3DQEBAQUABIIBAH6+IH8A
# pjVHRtAA2MpfTvoWuPkoJ10cwMp1Q741X9K/ww7Rpe7AbujNQaq8QycLudXWOgtj
# jUg81CEei3DAltSSXaeL4GJmDOfQy9fpd+TJVWSXF7ASfA2YqRr7gNfEFjYuezRr
# 7LXat/AZCqm5V0bGw1m5mCEtSR38CFBKTVN4N9NWu3Qu9/e7rVOpcOrB0cpLdPMs
# 7ymgptGIVxFqXXDM20cdK7IM2CxsRoOCPsP3H3UP+r6jqsoBOtGYfpdU4E8KQ4o1
# fV51L1b6ccvHSJ4rfPvm+9WfoamTvcd2kA5DQJHKL1fIEjIDM00lpDWsodB/b8uD
# mqV1mfgeZAPwhUA=
# SIG # End signature block
