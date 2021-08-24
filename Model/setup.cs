using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class setup
    {
        [Key]
        public int ID { get; set; }

        #region AD
        [Display(Name = "Host")]
        [MaxLength(150)]
        public string Host { get; set; }

        [Display(Name = "Port")]
        [MaxLength(150)]
        public string Port { get; set; }

        [Display(Name = "Base")]
        [MaxLength(150)]
        public string Base { get; set; }

        [Display(Name = "Username")]
        [MaxLength(150)]
        public string Username { get; set; }

        [Display(Name = "Password")]
        [MaxLength(150)]
        public string Password { get; set; }
        #endregion

        #region LDAP
        [Display(Name = "Host")]
        [MaxLength(150)]
        public string LDAPHost { get; set; }

        [Display(Name = "Port")]
        [MaxLength(150)]
        public string LDAPPort { get; set; }

        [Display(Name = "Base")]
        [MaxLength(150)]
        public string LDAPBase { get; set; }

        [Display(Name = "Username")]
        [MaxLength(150)]
        public string LDAPUsername { get; set; }

        [Display(Name = "Password")]
        [MaxLength(150)]
        public string LDAPPassword { get; set; }
        #endregion

        #region SMTP

        [Display(Name = "SMTP Server")]
        [MaxLength(150)]
        public string SMTP_Server { get; set; }

        [Display(Name = "SMTP Port")]
        public int SMTP_Port { get; set; }

        [Display(Name = "SMTP From")]
        [MaxLength(150)]
        public string SMTP_From { get; set; }

        [Display(Name = "SMTP Username")]
        [MaxLength(150)]
        public string SMTP_Username { get; set; }

        [Display(Name = "SMTP Password")]
        [MaxLength(150)]
        public string SMTP_Password { get; set; }

        [Display(Name = "SMTP SSL")]
        public bool? SMTP_SSL { get; set; }
        #endregion

        #region setup
        public bool change_password_otp_enable { get; set; }
        public bool change_password_approve_enable { get; set; }
        public string first_page_description { get; set; }

        #endregion


        #region 

        [Display(Name = "ผู้สร้าง")]
        [MaxLength(250)]
        public string Create_By { get; set; }
        [Display(Name = "เวลาสร้าง")]
        public Nullable<DateTime> Create_On { get; set; }
        [Display(Name = "ผู้แก้ไข")]
        [MaxLength(250)]
        public string Update_By { get; set; }
        [Display(Name = "เวลาแก้ไข")]
        public Nullable<DateTime> Update_On { get; set; }

        #endregion
    }
}
