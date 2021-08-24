using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.DirectoryServices;
using IDMAPI;
using System.Reflection;
using IDMAPI.Extensions;

namespace IDMAPI.Identity
{
    public class LdapUser
    {
        public string cn { get; set; }
        public string cVPN3000_Access_Hours { get; set; }
        public string cVPN3000_Simultaneous_Logins { get; set; }
        public string displayName { get; set; }
        public string gecos { get; set; }
        public int? gidNumber { get; set; }
        public string givenName { get; set; }
        public string homeDirectory { get; set; }
        public string inetCOS { get; set; }
        public int? internetaccess { get; set; }
        public string jobcode { get; set; }
        public string loginShell { get; set; }
        public string mail { get; set; }
        public string mailacceptinggeneralid { get; set; }
        public string maildrop { get; set; }
        public string mailHost { get; set; }
        public string mailRoutingAddress { get; set; }
        public string miDefaultJunkmailFilter { get; set; }
        public string miMailExpirePolicy { get; set; }
        public string miMailQuota { get; set; }
        public Object[] miService { get; set; }
        public string miWmprefCharset { get; set; }
        public string miWmprefEmailAddress { get; set; }
        public string miWmprefFullName { get; set; }
        public string miWmprefReplyOption { get; set; }
        public string miWmprefTimezone { get; set; }
        public int? netcastaccess { get; set; }
        public Object[] objectClass { get; set; }
        public string pplid { get; set; }
        public string pwdchangedby { get; set; }
        public string pwdchangedloc { get; set; }
        public string sn { get; set; }
        public string telephoneNumber { get; set; }
        public string thaidescription { get; set; }
        public string thcn { get; set; }
        public string thsn { get; set; }
        public string uid { get; set; }
        public int? uidNumber { get; set; }
        public byte[] userPassword { get; set; }
        public string userprincipalname { get; set; }

        public string mobile { get; set; }
        public string nsaccountlock { get; set; }
        public string CUexpire { get; set; }
        public string dn { get; set; }
        public string suntype { get; set; }
        public string SCE_Package { get; set; }

        public static object getpropertyvalue(PropertyCollection Properties, string PropertyName)
        {
            if (Properties.Contains(PropertyName))
            {
                if (Properties[PropertyName].Value != null)
                {
                    try
                    {
                        //PropertyValueCollection ValueCollection = Properties[PropertyName];
                        //for (int i = 0; i < ValueCollection.Count; i++)
                        //{
                        //    if (i == 0)
                        //    {
                        //        result[count] = ValueCollection[i].ToString();
                        //    }
                        //    else
                        //    {
                        //        result[count] += "|" + ValueCollection[i].ToString();
                        //    }
                        //}
                        return Properties[PropertyName].Value;
                    }
                    catch(Exception ex)
                    {

                    }
                }
            }
            return null;
        }

        public static LdapUser CastToUser(PropertyCollection Properties)
        {
            var ldapuser = new LdapUser();
            var properties = typeof(LdapUser).GetProperties(BindingFlags.Public | BindingFlags.Instance);
            foreach (var property in properties)
            {
                property.SetValue(ldapuser, getpropertyvalue(Properties, property.Name));
            }
            return ldapuser;
        }

    }
}