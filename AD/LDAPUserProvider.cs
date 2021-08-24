using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using IDMAPI.Identity.Extensions;
using IDMAPI.DAL;
using IDMAPI.Models;
using System.DirectoryServices;
using System.Text;
using System.Reflection;
using IDMAPI.Extensions;

namespace IDMAPI.Identity
{

    public interface ILDAPUserProvider
    {
        LdapUser GetUser(string samAccountName, SpuContext spucontext);
        Task<List<Organization>> GetOrganization(SpuContext spucontext, SystemConf conf, string oulvl1, string oulvl2 = null, string oulvl3 = null);
        Task<List<Organization>> GetOrganizationLvl1(SpuContext spucontext, SystemConf conf);
        Task<List<Organization>> GetOrganizationLvl2(SpuContext spucontext, SystemConf conf, string oulvl1);
        Task<List<Organization>> GetOrganizationLvl3(SpuContext spucontext, SystemConf conf, string oulvl1, string oulvl2);
        Result CreateUser(visual_fim_user model, SpuContext spucontext);
        Result UpdateUser(visual_fim_user model, SpuContext spucontext);
        Result MoveOU(visual_fim_user model, SpuContext spucontext);
        Result DeleteUser(visual_fim_user model, SpuContext spucontext);
        Result ChangePwd(visual_fim_user model, string pwd, SpuContext spucontext);

        Result NsLockUser(visual_fim_user model, SpuContext spucontext);
    }


    public class LDAPUserProvider : ILDAPUserProvider
    {
        public LdapUser GetUser(string uid, SpuContext spucontext)
        {
            try
            {
                var setup = spucontext.table_setup.FirstOrDefault();
                using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))
                {
                    var username = uid;
                    string filter = "(&(|(objectClass=inetOrgPerson))(&(uid=" + username + ")))";

                    DirectorySearcher nDS = new DirectorySearcher(entry);
                    nDS.SearchScope = SearchScope.Subtree;
                    nDS.Filter = filter;
                    SearchResult src = nDS.FindOne();
                    if (src != null)
                    {
                        DirectoryEntry de = src.GetDirectoryEntry();
                        return LdapUser.CastToUser(de.Properties);
                    }
                }
                return null;
            }
            catch (Exception ex)
            {
                throw new Exception("Error retrieving LDAP User", ex);
            }

        }
        public Result DeleteUser(visual_fim_user model, SpuContext spucontext)
        {
            try
            {
                var setup = spucontext.table_setup.FirstOrDefault();
                using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))
                {
                    string filter = "(&(|(objectClass=inetOrgPerson))(&(uid=" + model.basic_uid + ")))";

                    SearchResult src = null;
                    DirectorySearcher nDS = new DirectorySearcher(entry);
                    nDS.SearchScope = SearchScope.Subtree;
                    nDS.Filter = filter;
                    try
                    {
                        src = nDS.FindOne();
                        if (src != null)
                        {
                            DirectoryEntry removeEntry = src.GetDirectoryEntry();
                            DirectoryEntry parentEntry = removeEntry.Parent;
                            parentEntry.Children.Remove(removeEntry);
                            parentEntry.CommitChanges();
                            parentEntry.Close();
                            removeEntry.Close();
                        }
                        entry.Close();
                        return new Result() {result = true };
                    }
                    catch (Exception ex)
                    {
                        return new Result() { result = false, Message = ex.Message };
                    }

                }
            }
            catch (Exception ex)
            {
                return new Result() { result = false, Message = ex.Message };
            }

        }
        public Result CreateUser(visual_fim_user model, SpuContext spucontext)
        {
            try
            {
                var setup = spucontext.table_setup.FirstOrDefault();
                using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))
                {
                    string filter = "(&(|(objectClass=inetOrgPerson))(&(uid=" + model.basic_uid + ")))";

                    DirectorySearcher nDS = new DirectorySearcher(entry);
                    nDS.SearchScope = SearchScope.Subtree;
                    nDS.Filter = filter;
                    SearchResult src = nDS.FindOne();
                    if (src == null)
                    {
                        var oufilter = model.system_ou_lvl1;
                        if (!string.IsNullOrEmpty(model.system_ou_lvl2))
                            oufilter = model.system_ou_lvl2 + "," + oufilter;
                        if (!string.IsNullOrEmpty(model.system_ou_lvl3))
                            oufilter = model.system_ou_lvl3 + "," + oufilter;

                        DirectoryEntry de = entry.Children.Find(oufilter);

                        //DirectoryEntry newUser = entry.Children.Add("CN=" + username, "person");
                        DirectoryEntry newUser = de.Children.Add("uid=" + model.basic_uid, "inetOrgPerson");
                        newUser.Properties["cn"].Value = AppUtil.ManageNull(model.basic_cn);
                        newUser.Properties["sn"].Value = AppUtil.ManageNull(model.basic_sn);
                        newUser.Properties["displayName"].Value = AppUtil.ManageNull(model.basic_displayname);
                        newUser.Properties["givenName"].Value = AppUtil.ManageNull(model.basic_givenname);
                        newUser.Properties["mail"].Value = AppUtil.ManageNull(model.basic_mail);
                        newUser.Properties["telephoneNumber"].Value = AppUtil.ManageNull(model.basic_telephonenumber);
                        newUser.Properties["mobile"].Value = AppUtil.ManageNull(model.basic_mobile);
                        newUser.Properties["userPassword"].Value = AppUtil.ManageNull(Cryptography.decrypt(model.basic_userPassword));

                        newUser.CommitChanges();
                        newUser.RefreshCache();

                        /*chulaInfo*/
                        newUser.Properties["objectClass"].Add("chulaInfo");
                        newUser.Properties["jobcode"].Value = AppUtil.ManageNull(model.cu_jobcode);
                        newUser.Properties["internetaccess"].Value = AppUtil.ManageNull(model.internetaccess);
                        newUser.Properties["mailacceptinggeneralid"].Value = AppUtil.ManageNull(model.cu_mailacceptinggeneralid);
                        newUser.Properties["maildrop"].Value = AppUtil.ManageNull(model.cu_maildrop);
                        newUser.Properties["netcastaccess"].Value = AppUtil.ManageNull(model.netcastaccess);
                        newUser.Properties["pplid"].Value = AppUtil.ManageNull(model.cu_pplid);
                        newUser.Properties["pwdchangedby"].Value = AppUtil.ManageNull(model.cu_pwdchangedby);
                        newUser.Properties["pwdchangedloc"].Value = AppUtil.ManageNull(model.cu_pwdchangedloc);
                        newUser.Properties["thcn"].Value = AppUtil.ManageNull(model.cu_thcn);
                        newUser.Properties["thsn"].Value = AppUtil.ManageNull(model.cu_thsn);
                        newUser.Properties["nsaccountlock"].Value = AppUtil.ManageNull(model.cu_nsaccountlock);
                        newUser.Properties["CUexpire"].Value = AppUtil.ManageNull(model.cu_CUexpire);
                        newUser.Properties["SCE-Package"].Value = AppUtil.ManageNull(model.cu_sce_package);
                        newUser.Properties["userprincipalname"].Value = AppUtil.ManageNull(model.basic_userprincipalname);
                        newUser.Properties["thaidescription"].Value = AppUtil.ManageNull(model.thaidescription);

                        if (model.system_idm_user_type != IDMUserType.temporary)
                        {
                            /*dspswuser*/
                            newUser.Properties["objectClass"].Add("dspswuser");

                            /*mirapointMailUser*/
                            newUser.Properties["objectClass"].Add("mirapointMailUser");
                            newUser.Properties["mailHost"].Value = AppUtil.ManageNull(model.cu_mailhost);
                            newUser.Properties["miWmprefCharset"].Value = AppUtil.ManageNull(model.mail_miWmprefCharset);
                            newUser.Properties["miWmprefEmailAddress"].Value = AppUtil.ManageNull(model.mail_miWmprefEmailAddress);
                            newUser.Properties["miWmprefFullName"].Value = AppUtil.ManageNull(model.mail_miWmprefFullName);
                            newUser.Properties["miWmprefReplyOption"].Value = AppUtil.ManageNull(model.mail_miWmprefReplyOption);
                            newUser.Properties["miWmprefTimezone"].Value = AppUtil.ManageNull(model.mail_miWmprefTimezone);

                            /*mirapointUser*/
                            newUser.Properties["objectClass"].Add("mirapointUser");
                            //newUser.Properties["miMailExpirePolicy"].Value = AppUtil.ManageNull(model.miMailExpirePolicy);
                            //newUser.Properties["miMailQuota"].Value = AppUtil.ManageNull(model.miMailQuota);
                            //newUser.Properties["miService"].Value = AppUtil.ManageNull(model.miService);
                            //newUser.Properties["miDefaultJunkmailFilter"].Value = AppUtil.ManageNull(model.miDefaultJunkmailFilter);

                            /*ipUser*/
                            newUser.Properties["objectClass"].Add("ipUser");
                            newUser.Properties["inetCOS"].Value = AppUtil.ManageNull(model.unix_inetCOS);

                            /*cVPN3000-User-Authorization*/
                            newUser.Properties["objectClass"].Add("cVPN3000-User-Authorization");
                            //newUser.Properties["cVPN3000-Access-Hours"].Value = AppUtil.ManageNull(model.cVPN3000_Access_Hours);
                            //newUser.Properties["cVPN3000-Simultaneous-Logins"].Value = AppUtil.ManageNull(model.cVPN3000_Simultaneous_Logins);

                            /*shadowAccount*/
                            newUser.Properties["objectClass"].Add("shadowAccount");
                            newUser.Properties["uid"].Value = AppUtil.ManageNull(model.basic_uid);


                            /*mailrecipient*/
                            newUser.Properties["objectClass"].Add("mailrecipient");
                            newUser.Properties["mailRoutingAddress"].Value = AppUtil.ManageNull(model.cu_mailRoutingAddress);

                            /*radiusprofile*/
                            newUser.Properties["objectClass"].Add("radiusprofile");

                            /*posixaccount*/
                            newUser.Properties["objectClass"].Add("posixaccount");
                            newUser.Properties["gecos"].Value = AppUtil.ManageNull(model.cu_gecos);
                            newUser.Properties["gidNumber"].Value = AppUtil.ManageNull(model.unix_gidNumber);
                            newUser.Properties["homeDirectory"].Value = AppUtil.ManageNull(model.unix_homeDirectory);
                            newUser.Properties["loginShell"].Value = AppUtil.ManageNull(model.unix_loginShell);
                            newUser.Properties["uidNumber"].Value = AppUtil.ManageNull(model.unix_uidNumber);
                        }

                        newUser.CommitChanges();
                        entry.Close();
                        newUser.Close();

                        //newUser.Properties["dn"].Value = AppUtil.ManageNull(model.basic_dn);
                        //newUser.Properties["suntype"].Value = AppUtil.ManageNull(model.suntype);

                        return new Result() { result = true };
                    }
                }
            }
            catch (Exception ex)
            {
                return new Result() { result = false, Message = ex.Message };
            }
            return new Result() { result = false };
        }
        public Result UpdateUser(visual_fim_user model, SpuContext spucontext)
        {

            try
            {
                var setup = spucontext.table_setup.FirstOrDefault();
                using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))
                {
                    string filter = "(&(|(objectClass=inetOrgPerson))(&(uid=" + model.basic_uid + ")))";

                    DirectorySearcher nDS = new DirectorySearcher(entry);
                    nDS.SearchScope = SearchScope.Subtree;
                    nDS.Filter = filter;
                    SearchResult src = nDS.FindOne();
                    if (src != null)
                    {
                        DirectoryEntry de = src.GetDirectoryEntry();
                        de.Properties["cn"].Value = AppUtil.ManageNull(model.basic_cn);
                        de.Properties["sn"].Value = AppUtil.ManageNull(model.basic_sn);
                        de.Properties["displayName"].Value = AppUtil.ManageNull(model.basic_displayname);
                        de.Properties["givenName"].Value = AppUtil.ManageNull(model.basic_givenname);
                        de.Properties["telephoneNumber"].Value = AppUtil.ManageNull(model.basic_telephonenumber);
                        de.Properties["mobile"].Value = AppUtil.ManageNull(model.basic_mobile);
                        de.Properties["jobcode"].Value = AppUtil.ManageNull(model.cu_jobcode);
                        de.Properties["pplid"].Value = AppUtil.ManageNull(model.cu_pplid);
                        de.Properties["thcn"].Value = AppUtil.ManageNull(model.cu_thcn);
                        de.Properties["thsn"].Value = AppUtil.ManageNull(model.cu_thsn);
                        de.Properties["inetCOS"].Value = AppUtil.ManageNull(model.unix_inetCOS);
                        de.Properties["CUexpire"].Value = AppUtil.ManageNull(model.cu_CUexpire);

                        if (model.system_idm_user_type != IDMUserType.temporary)
                        {
                            de.Properties["gecos"].Value = AppUtil.ManageNull(model.cu_gecos);
                        }
                        de.CommitChanges();
                        entry.Close();
                        de.Close();

                        return new Result() { result = true };
                    }

                }
            }
            catch (Exception ex)
            {
                return new Result() { result = false, Message = ex.Message };
            }
            return new Result() { result = false };
        }

        public Result MoveOU(visual_fim_user model, SpuContext spucontext)
        {

            try
            {
                var setup = spucontext.table_setup.FirstOrDefault();
                using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))
                {
                    string filter = "(&(|(objectClass=inetOrgPerson))(&(uid=" + model.basic_uid + ")))";

                    DirectorySearcher nDS = new DirectorySearcher(entry);
                    nDS.SearchScope = SearchScope.Subtree;
                    nDS.Filter = filter;
                    SearchResult src = nDS.FindOne();
                    if (src != null)
                    {
                        var system_ou_lvl1 = AppUtil.getOuName(model.system_ou_lvl1);
                        var system_ou_lvl2 = AppUtil.getOuName(model.system_ou_lvl2);
                        var system_ou_lvl3 = AppUtil.getOuName(model.system_ou_lvl3);

                        var nou = "";
                        if (!string.IsNullOrEmpty(model.system_ou_lvl3))
                            nou += "," + model.system_ou_lvl3.ToLower();
                        if (!string.IsNullOrEmpty(model.system_ou_lvl2))
                            nou += "," + model.system_ou_lvl2.ToLower();
                        if (!string.IsNullOrEmpty(model.system_ou_lvl1))
                            nou += "," + model.system_ou_lvl1.ToLower();

                        nou = nou.Substring(1);
                        DirectoryEntry de = src.GetDirectoryEntry();
                        DirectoryEntry nde = new DirectoryEntry(setup.LDAPHost + nou + "," + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind);
                        if (model.system_idm_user_type != IDMUserType.temporary)
                        {
                            de.Properties["gecos"].Value = AppUtil.ManageNull(model.cu_gecos);
                        }
                        de.CommitChanges();
                        de.MoveTo(nde);
                        entry.Close();
                        de.Close();
                        nde.Close();
                        return new Result() { result = true };
                    }

                }
            }
            catch (Exception ex)
            {
                return new Result() { result = false, Message = ex.Message };
            }
            return new Result() { result = false };
        }
        public Result ChangePwd(visual_fim_user model,string pwd, SpuContext spucontext)
        {

            try
            {
                var setup = spucontext.table_setup.FirstOrDefault();
                using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))
                {
                    string filter = "(&(|(objectClass=inetOrgPerson))(&(uid=" + model.basic_uid + ")))";

                    DirectorySearcher nDS = new DirectorySearcher(entry);
                    nDS.SearchScope = SearchScope.Subtree;
                    nDS.Filter = filter;
                    SearchResult src = nDS.FindOne();
                    if (src != null)
                    {
                        DirectoryEntry de = src.GetDirectoryEntry();
                        //de.Invoke("SetPassword", new object[] { AppUtil.ManageNull(pwd) });
                        de.Properties["userPassword"].Value = AppUtil.ManageNull(pwd);
                        de.CommitChanges();
                        entry.Close();
                        de.Close();

                        return new Result() { result = true };
                    }

                }
            }
            catch (Exception ex)
            {
                return new Result() { result = false, Message = ex.Message };
            }
            return new Result() { result = false };
        }
        public Result NsLockUser(visual_fim_user model, SpuContext spucontext)
        {
            try
            {
                var setup = spucontext.table_setup.FirstOrDefault();
                using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))
                {
                    string filter = "(&(|(objectClass=inetOrgPerson))(&(uid=" + model.basic_uid + ")))";

                    DirectorySearcher nDS = new DirectorySearcher(entry);
                    nDS.SearchScope = SearchScope.Subtree;
                    nDS.Filter = filter;
                    SearchResult src = nDS.FindOne();
                    if (src != null)
                    {
                        DirectoryEntry de = src.GetDirectoryEntry();
                        de.Properties["nsaccountlock"].Value = AppUtil.ManageNull(model.cu_nsaccountlock);
                        de.CommitChanges();
                        entry.Close();
                        de.Close();

                        return new Result() { result = true };
                    }

                }
            }
            catch (Exception ex)
            {
                return new Result() { result = false, Message = ex.Message };
            }
            return new Result() { result = false };
        }

        public Task<List<Organization>> GetOrganization(SpuContext spucontext, SystemConf conf, string oulvl1, string oulvl2 = null, string oulvl3 = null)
        {
            return Task.Run(() =>
            {
                try
                {
                    var ous = new List<Organization>();
                    var setup = spucontext.table_setup.FirstOrDefault();

                    var oufilter = "";

                    if (!string.IsNullOrEmpty(oulvl3))
                        oufilter += oulvl3 + ",";
                    if (!string.IsNullOrEmpty(oulvl2))
                        oufilter += oulvl2 + ",";
                    oufilter += oulvl1 + ",";

                    using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + oufilter + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))
                    {
                        foreach (DirectoryEntry entryChild in entry.Children)
                        {
                            var ouname = entryChild.Name.Replace("o=", "").Replace("ou=", "");
                            var schemaname = entryChild.SchemaClassName.ToLower();

                        }
                    }
                    return ous.OrderBy(o => o.ouname).ToList();
                }
                catch (Exception ex)
                {
                    throw new Exception("Error retrieving LDAP User", ex);
                }
            });
        }
        public Task<List<Organization>> GetOrganizationLvl1(SpuContext spucontext, SystemConf conf)
        {
            return Task.Run(() =>
            {
                try
                {
                    var ous = new List<Organization>();
                    var setup = spucontext.table_setup.FirstOrDefault();
                    var ouselectd = conf.DefaultValue_OU_Filter.Split(",", StringSplitOptions.RemoveEmptyEntries);
                    using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))
                    {
                        foreach (DirectoryEntry entryChild in entry.Children)
                        {
                            var ouname = entryChild.Name.Replace("o=", "").Replace("ou=", "");
                            if (ouselectd.Contains(ouname.ToLower()))
                            {
                                var ou = new Organization();
                                ou.ouname = ouname;
                                ou.schemaname = entryChild.SchemaClassName.ToLower();
                                ou.path = entryChild.Path.ToLower();
                                ou.ou = entryChild.Name;//.Replace("=","|");
                                ous.Add(ou);
                            }
                        }
                    }
                    return ous.OrderBy(o => o.ouname).ToList();
                }
                catch (Exception ex)
                {
                    throw new Exception("Error retrieving LDAP User", ex);
                }
            });
        }
        public Task<List<Organization>> GetOrganizationLvl2(SpuContext spucontext, SystemConf conf, string oulvl1)
        {
            return Task.Run(() =>
            {
                try
                {
                    //oulvl1 = oulvl1.Replace("|", "=");

                    if (oulvl1 == "o=internet" | oulvl1 == "o=tmpacc")
                        return new List<Organization>();

                    var oufilter = oulvl1 + ",";

                    var ous = new List<Organization>();
                    var setup = spucontext.table_setup.FirstOrDefault();
                    using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + oufilter + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))
                    {

                        foreach (DirectoryEntry entryChild in entry.Children)
                        {
                            var ouname = entryChild.Name.Replace("o=", "").Replace("ou=", "");

                            var ou = new Organization();
                            ou.ouname = ouname;
                            ou.schemaname = entryChild.SchemaClassName.ToLower();
                            ou.path = entryChild.Path.ToLower();
                            ou.ou = entryChild.Name;//.Replace("=","|");
                            ous.Add(ou);
                        }
                    }
                    return ous.OrderBy(o => o.ouname).ToList();
                }
                catch (Exception ex)
                {
                    throw new Exception("Error retrieving LDAP User", ex);
                }
            });
        }
        public Task<List<Organization>> GetOrganizationLvl3(SpuContext spucontext, SystemConf conf, string oulvl1, string oulvl2)
        {
            return Task.Run(() =>
            {
                try
                {
                    //oulvl1 = oulvl1.Replace("|", "=");
                    //oulvl2 = oulvl2.Replace("|", "=");
                    var oufilter = "";
                    if (!string.IsNullOrEmpty(oulvl2))
                        oufilter += oulvl2 + ",";

                    oufilter += oulvl1 + ",";

                    var ous = new List<Organization>();
                    var setup = spucontext.table_setup.FirstOrDefault();
                    var ouselectd = conf.DefaultValue_OU_Filter.Split(",", StringSplitOptions.RemoveEmptyEntries);
                    using (DirectoryEntry entry = new DirectoryEntry(setup.LDAPHost + oufilter + setup.LDAPBase, setup.LDAPUsername, setup.LDAPPassword, AuthenticationTypes.FastBind))

                    {
                        foreach (DirectoryEntry entryChild in entry.Children)
                        {
                            var ouname = entryChild.Name.Replace("o=", "").Replace("ou=", "");
                            var ou = new Organization();
                            ou.ouname = ouname;
                            ou.schemaname = entryChild.SchemaClassName.ToLower();
                            ou.path = entryChild.Path.ToLower();
                            ou.ou = entryChild.Name;//.Replace("=","|");
                            ous.Add(ou);
                        }
                    }
                    return ous.OrderBy(o => o.ouname).ToList();
                }
                catch (Exception ex)
                {
                    throw new Exception("Error retrieving LDAP User", ex);
                }
            });
        }
        private string getPropertyValue(PropertyCollection propertyCollection, string propertyName)
        {
            PropertyValueCollection ValueCollection = propertyCollection[propertyName];
            var value = "";
            for (int i = 0; i < ValueCollection.Count; i++)
            {
                if (i == 0)
                    value = ValueCollection[i].ToString();
                else
                    value = value + "|" + ValueCollection[i].ToString();
            }
            return value;
        }
        

    }
}