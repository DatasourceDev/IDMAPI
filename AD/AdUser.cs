using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.DirectoryServices;
using IDMAPI;

namespace IDMAPI.Identity
{
    public class AdUser
    {
        public object accountExpires { get; set; }
        public object badPasswordTime { get; set; }
        public int? badPwdCount { get; set; }
        public string cn { get; set; }
        public int? codePage { get; set; }
        public int? countryCode { get; set; }
        public string displayName { get; set; }
        public string distinguishedName { get; set; }
        public Object[] dSCorePropagationData { get; set; }
        public string employeeID { get; set; }
        public string givenName { get; set; }
        public string homeMDB { get; set; }
        public int? instanceType { get; set; }
        public int? internetaccess { get; set; }
        public object lastLogoff { get; set; }
        public object lastLogon { get; set; }
        public object lastLogonTimestamp { get; set; }
        public string legacyExchangeDN { get; set; }
        public object lockoutTime { get; set; }
        public int? logonCount { get; set; }
        public string mail { get; set; }
        public string mailNickname { get; set; }
        public int? mDBOverHardQuotaLimit { get; set; }
        public int? mDBOverQuotaLimit { get; set; }
        public int? mDBStorageQuota { get; set; }
        public bool mDBUseDefaults { get; set; }
        public Object[] memberOf { get; set; }
        public byte[] mS_DS_ConsistencyGuid { get; set; }
        public object msExchArchiveQuota { get; set; }
        public object msExchArchiveWarnQuota { get; set; }
        public int? msExchCalendarLoggingQuota { get; set; }
        public int? msExchDumpsterQuota { get; set; }
        public int? msExchDumpsterWarningQuota { get; set; }
        public string msExchHomeServerName { get; set; }
        public byte[] msExchMailboxGuid { get; set; }
        public object msExchMailboxSecurityDescriptor { get; set; }
        public int? msExchOmaAdminWirelessEnable { get; set; }
        public Object[] msExchPoliciesIncluded { get; set; }
        public object msExchPreviousRecipientTypeDetails { get; set; }
        public string msExchRBACPolicyLink { get; set; }
        public int? msExchRecipientDisplayType { get; set; }
        public int? msExchRecipientSoftDeletedStatus { get; set; }
        public object msExchRecipientTypeDetails { get; set; }
        public Object[] msExchTextMessagingState { get; set; }
        public Object[] msExchUMDtmfMap { get; set; }
        public int? msExchUserAccountControl { get; set; }
        public string msExchUserCulture { get; set; }
        public object msExchVersion { get; set; }
        public DateTime? msExchWhenMailboxCreated { get; set; }
        public string name { get; set; }
        public int? netcastaccess { get; set; }
        public object nTSecurityDescriptor { get; set; }
        public string objectCategory { get; set; }
        public Object[] objectClass { get; set; }
        public byte[] objectGUID { get; set; }
        public byte[] objectSid { get; set; }
        public string pplid { get; set; }
        public int? primaryGroupID { get; set; }
        public Object[] protocolSettings { get; set; }
        public Object[] proxyAddresses { get; set; }
        public object pwdLastSet { get; set; }
        public string sAMAccountName { get; set; }
        public int? sAMAccountType { get; set; }
        public Object[] showInAddressBook { get; set; }
        public string sn { get; set; }
        public string telephoneNumber { get; set; }
        public int? userAccountControl { get; set; }
        public string userPrincipalName { get; set; }
        public object uSNChanged { get; set; }
        public object uSNCreated { get; set; }
        public DateTime? whenChanged { get; set; }
        public DateTime? whenCreated { get; set; }

        private static string getpropertyvalue(PropertyCollection Properties, string PropertyName)
        {
            if (Properties.Contains(PropertyName))
            {
                if (Properties[PropertyName].Value != null)
                    return Properties[PropertyName].Value.ToString();
            }
            return "";
        }

        public static AdUser CastToAdUser(UserPrincipal user)
        {
            DirectoryEntry d = user.GetUnderlyingObject() as DirectoryEntry;

            return new AdUser
            {
                //description = user.Description,
                displayName = user.DisplayName,
                distinguishedName = user.DistinguishedName,
                mail = user.EmailAddress,
                givenName = user.GivenName,
                lastLogon = user.LastLogon,
                name = user.Name,
                sAMAccountName = user.SamAccountName,
                sn = user.Surname,
                userPrincipalName = user.UserPrincipalName,
                telephoneNumber = user.VoiceTelephoneNumber,
                //department = getpropertyvalue(d.Properties, "department"),
            };
        }

    }

    public class AdUser4 : BaseDTO
    {
        public string objectClass { get; set; }
        public string uid { get; set; }
        public string cn { get; set; }
        public string sn { get; set; }
        public string description { get; set; }
        public string givenName { get; set; }
        public string distinguishedName { get; set; }
        public string instanceType { get; set; }
        public string whenCreated { get; set; }
        public string whenChanged { get; set; }
        public string displayName { get; set; }
        public DateTime? uSNCreated { get; set; }
        public DateTime? uSNChanged { get; set; }
        public string department { get; set; }
        public string nTSecurityDescriptor { get; set; }
        public string name { get; set; }
        //public string objectGUID { get; set; }
        public string userAccountControl { get; set; }
        public string codePage { get; set; }
        public string countryCode { get; set; }
        public DateTime? pwdLastSet { get; set; }
        public string primaryGroupID { get; set; }
        //public string objectSid { get; set; }
        public string accountExpires { get; set; }
        public string sAMAccountName { get; set; }
        public string division { get; set; }
        public string sAMAccountType { get; set; }
        public string userPrincipalName { get; set; }
        public string objectCategory { get; set; }
        public string dSCorePropagationData { get; set; }
        public string mail { get; set; }
        public string jobcode { get; set; }
        public string pplid { get; set; }
        public string CUexpire { get; set; }
        public string pwdchangedloc { get; set; }
        public string pwdchangedby { get; set; }
        public string internetaccess { get; set; }
        public string thaidescription { get; set; }

        public string title { get; set; }
        public string postalCode { get; set; }
        public string physicalDeliveryOfficeName { get; set; }
        public string telephoneNumber { get; set; }
        public string company { get; set; }
        public string postOfficeBox { get; set; }
        public string memberOf { get; set; }
        //public string employeeID { get; set; }
        //public string flags { get; set; }
        public string comment { get; set; }
        public string lastLogonTimestamp { get; set; }

        public DateTime? lastLogon { get; set; }
        public string logonCount { get; set; }

        private static string getpropertyvalue(PropertyCollection Properties, string PropertyName)
        {
            if (Properties.Contains(PropertyName))
            {
                if (Properties[PropertyName].Value != null)
                    return Properties[PropertyName].Value.ToString();
            }
            return "";
        }

        public static AdUser4 CastToAdUser(UserPrincipal user)
        {
            DirectoryEntry d = user.GetUnderlyingObject() as DirectoryEntry;

            return new AdUser4
            {
                description = user.Description,
                displayName = user.DisplayName,
                distinguishedName = user.DistinguishedName,
                mail = user.EmailAddress,
                givenName = user.GivenName,
                lastLogon = user.LastLogon,
                name = user.Name,
                sAMAccountName = user.SamAccountName,
                sn = user.Surname,
                userPrincipalName = user.UserPrincipalName,
                telephoneNumber = user.VoiceTelephoneNumber,
                department = getpropertyvalue(d.Properties, "department"),
                title = getpropertyvalue(d.Properties, "title"),
                jobcode = user.EmployeeId,
                uid = getpropertyvalue(d.Properties, "uid"),
                pplid = getpropertyvalue(d.Properties, "pplid"),
                pwdchangedloc = getpropertyvalue(d.Properties, "pwdchangedloc"),
                pwdchangedby = getpropertyvalue(d.Properties, "pwdchangedby"),
                internetaccess = getpropertyvalue(d.Properties, "internetaccess"),
                thaidescription = getpropertyvalue(d.Properties, "thaidescription"),
                CUexpire = getpropertyvalue(d.Properties, "CUexpire"),
            };
        }
    }
    public class AdUser2
    {
        public DateTime? AccountExpirationDate { get; set; }
        public DateTime? AccountLockoutTime { get; set; }
        public int BadLogonCount { get; set; }
        public string Description { get; set; }
        public string DisplayName { get; set; }
        public string DistinguishedName { get; set; }
        public string Domain { get; set; }
        public string EmailAddress { get; set; }
        public string EmployeeId { get; set; }
        public bool? Enabled { get; set; }
        public string GivenName { get; set; }
        public Guid? Guid { get; set; }
        public string HomeDirectory { get; set; }
        public string HomeDrive { get; set; }
        public DateTime? LastBadPasswordAttempt { get; set; }
        public DateTime? LastLogon { get; set; }
        public DateTime? LastPasswordSet { get; set; }
        public string MiddleName { get; set; }
        public string Name { get; set; }
        public bool PasswordNeverExpires { get; set; }
        public bool PasswordNotRequired { get; set; }
        public string SamAccountName { get; set; }
        public string ScriptPath { get; set; }
        public SecurityIdentifier Sid { get; set; }
        public string Surname { get; set; }
        public bool UserCannotChangePassword { get; set; }
        public string UserPrincipalName { get; set; }
        public string VoiceTelephoneNumber { get; set; }

        public static AdUser2 CastToAdUser(UserPrincipal user)
        {
            return new AdUser2
            {
                AccountExpirationDate = user.AccountExpirationDate,
                AccountLockoutTime = user.AccountLockoutTime,
                BadLogonCount = user.BadLogonCount,
                Description = user.Description,
                DisplayName = user.DisplayName,
                DistinguishedName = user.DistinguishedName,
                EmailAddress = user.EmailAddress,
                EmployeeId = user.EmployeeId,
                Enabled = user.Enabled,
                GivenName = user.GivenName,
                Guid = user.Guid,
                HomeDirectory = user.HomeDirectory,
                HomeDrive = user.HomeDrive,
                LastBadPasswordAttempt = user.LastBadPasswordAttempt,
                LastLogon = user.LastLogon,
                LastPasswordSet = user.LastPasswordSet,
                MiddleName = user.MiddleName,
                Name = user.Name,
                PasswordNeverExpires = user.PasswordNeverExpires,
                PasswordNotRequired = user.PasswordNotRequired,
                SamAccountName = user.SamAccountName,
                ScriptPath = user.ScriptPath,
                Sid = user.Sid,
                Surname = user.Surname,
                UserCannotChangePassword = user.UserCannotChangePassword,
                UserPrincipalName = user.UserPrincipalName,
                VoiceTelephoneNumber = user.VoiceTelephoneNumber
            };
        }

        public string GetDomainPrefix() => DistinguishedName
            .Split(',')
            .FirstOrDefault(x => x.ToLower().Contains("dc"))
            .Split('=')
            .LastOrDefault()
            .ToUpper();
    }

}