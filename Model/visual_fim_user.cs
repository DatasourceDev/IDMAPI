using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;
using IDMAPI.Extensions;

namespace IDMAPI.Models
{


    public class visual_fim_user
    {
        [Key]
        public Int64 id { get; set; }

        public string basic_dn { get; set; }


        private string _basic_cn;
        public string basic_cn
        {
            get
            {
                if (!string.IsNullOrEmpty(basic_givenname) && !string.IsNullOrEmpty(basic_sn))
                {
                    _basic_cn = basic_givenname + " " + basic_sn;
                }
                else if (!string.IsNullOrEmpty(basic_givenname) && string.IsNullOrEmpty(basic_sn))
                {
                    _basic_cn = basic_givenname;
                }
                else if (string.IsNullOrEmpty(basic_givenname) && !string.IsNullOrEmpty(basic_sn))
                {
                    _basic_cn = basic_sn;
                }
                return _basic_cn;

            }
            set
            {
                _basic_cn = value;
            }
        }

        private string _basic_sn;
        public string basic_sn
        {
            get
            {
                return AppUtil.stringUpper(_basic_sn);
            }
            set
            {
                _basic_sn = value;
            }
        }

        public string basic_displayname { get; set; }

        public string basic_mail { get; set; }
        public string basic_mobile { get; set; }
        public string basic_uid { get; set; }

        private string _basic_givenname;
        public string basic_givenname
        {
            get
            {
                return AppUtil.stringUpper(_basic_givenname);
            }
            set
            {
                _basic_givenname = value;
            }
        }
        public string basic_userprincipalname { get; set; }

        private string _basic_telephonenumber;
        public string basic_telephonenumber
        {
            get
            {
                if (!string.IsNullOrEmpty(_basic_telephonenumber))
                {
                    _basic_telephonenumber = _basic_telephonenumber.Trim().Replace(" ", "").Replace("-", "");
                }
                return _basic_telephonenumber;
            }
            set
            {
                _basic_telephonenumber = value;
            }
        }

        
        public string basic_userPassword { get; set; }

        public string cu_nsaccountlock { get; set; }
        public string cu_mailhost { get; set; }
        public string cu_mailRoutingAddress { get; set; }
        public string cu_maildrop { get; set; }
        public string cu_mailacceptinggeneralid { get; set; }
        public string cu_pwdchangedby { get; set; }
        public DateTime? cu_pwdchangeddate { get; set; }
        public string cu_pwdchangedloc { get; set; }

        public string cu_gecos { get; set; }

        private string _cu_thcn;

        public string cu_thcn
        {
            get
            {
                if (!string.IsNullOrEmpty(_cu_thcn))
                    return _cu_thcn.Trim();
                return _cu_thcn;
            }
            set
            {
                _cu_thcn = value;
            }
        }

        private string _cu_thsn;
        public string cu_thsn
        {
            get
            {
                if (!string.IsNullOrEmpty(_cu_thsn))
                    return _cu_thsn.Trim();
                return _cu_thsn;
            }
            set
            {
                _cu_thsn = value;
            }
        }
        public string cu_CUexpire { get; set; }

        [NotMapped]
        public bool cu_CUexpire_select { get; set; }

        [NotMapped]
        public int? cu_CUexpire_day { get; set; }

        [NotMapped]
        public int? cu_CUexpire_month { get; set; }

        [NotMapped]
        public int? cu_CUexpire_year { get; set; }

        public string cu_jobcode { get; set; }

        private string _cu_pplid;

        public string cu_pplid
        {
            get
            {
                if (!string.IsNullOrEmpty(_cu_pplid))
                    return _cu_pplid.Trim();
                return _cu_pplid;
            }
            set
            {
                _cu_pplid = value;
            }
        }
        public string cu_sce_package { get; set; }
        public string unix_gidNumber { get; set; }
        public string unix_uidNumber { get; set; }
        public string unix_homeDirectory { get; set; }
        public string unix_loginShell { get; set; }
        public string unix_inetCOS { get; set; }
        public string mail_miWmprefFullName { get; set; }
        public string mail_miWmprefEmailAddress { get; set; }
        public string mail_miWmprefReplyOption { get; set; }
        public string mail_miWmprefTimezone { get; set; }
        public string mail_miWmprefCharset { get; set; }

        public string system_question1 { get; set; } /*need to remove after migration*/
        public string system_answer1 { get; set; } /*need to remove after migration*/
        public string system_question2 { get; set; } /*need to remove after migration*/
        public string system_answer2 { get; set; } /*need to remove after migration*/
        public string system_question3 { get; set; } /*need to remove after migration*/
        public string system_answer3 { get; set; } /*need to remove after migration*/
        public string system_create_by_uid { get; set; }
        public string system_modify_by_uid { get; set; }
        public string system_last_accessed_by_uid { get; set; }
        public DateTime? system_create_date { get; set; }
        public DateTime? system_modify_date { get; set; }
        public DateTime? system_last_accessed_date { get; set; }
        public int? system_waiting_time_for_access { get; set; }
        public int? system_temporary_user_expire_date_counter { get; set; }
        public string system_org { get; set; } /*need to remove after migration*/
        public int? system_enable_password_forgot { get; set; }
        public int? internetaccess { get; set; }
        public int? netcastaccess { get; set; }

        public int? system_faculty_id { get; set; }
        public int? system_sub_office_id { get; set; }

        public IDMUserType system_idm_user_type { get; set; }
        public bool system_actived { get; set; }

        
        private string _system_ou_lvl1;
        public string system_ou_lvl1
        {
            get
            {
                if (string.IsNullOrEmpty(_system_ou_lvl1) && !string.IsNullOrEmpty(basic_dn))
                {
                    var dn = basic_dn.Replace(",dc=chula,dc=ac,dc=th", "");
                    var dnarr = dn.Split(',');
                    _system_ou_lvl1 = dnarr[dnarr.Length - 1];
                    return _system_ou_lvl1;
                }
                else
                    return _system_ou_lvl1;
            }
            set
            {
                _system_ou_lvl1 = value;
            }
        }

        private string _system_ou_lvl2;
        public string system_ou_lvl2
        {
            get
            {
                if (string.IsNullOrEmpty(_system_ou_lvl2) && !string.IsNullOrEmpty(basic_dn))
                {
                    var dn = basic_dn.Replace(",dc=chula,dc=ac,dc=th", "");
                    var dnarr = dn.Split(',');
                    if(dnarr.Length - 2 >= 0)
                        _system_ou_lvl2 = dnarr[dnarr.Length - 2];
                    return _system_ou_lvl2;
                }
                else
                    return _system_ou_lvl2;
            }
            set
            {
                _system_ou_lvl2 = value;
            }
        }

        private string _system_ou_lvl3;
        public string system_ou_lvl3
        {
            get
            {
                if (string.IsNullOrEmpty(_system_ou_lvl3) && !string.IsNullOrEmpty(basic_dn))
                {
                    var dn = basic_dn.Replace(",dc=chula,dc=ac,dc=th", "");
                    var dnarr = dn.Split(',');
                    if (dnarr.Length - 3 >= 0)
                        _system_ou_lvl3 = dnarr[dnarr.Length - 3];
                    return _system_ou_lvl3;
                }
                else
                    return _system_ou_lvl3;
            }
            set
            {
                _system_ou_lvl3 = value;
            }
        }

        public bool ad_created { get; set; }
        public bool ldap_created { get; set; }
        public string thaidescription { get; set; }

    }



}
