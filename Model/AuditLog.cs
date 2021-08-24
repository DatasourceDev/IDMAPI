using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class AuditLog
    {
        [Key]
        public int ID { get; set; }

        [Display(Name = "Action")]
        [MaxLength(250)]
        public string Action { get; set; }


        [Display(Name = "ชื่อ")]
        [MaxLength(250)]
        public string FirstName { get; set; }


        [Display(Name = "นามสกุล")]
        [MaxLength(250)]
        public string LastName { get; set; }

        [Display(Name = "ผู้สร้าง")]
        [MaxLength(250)]
        public string Create_By { get; set; }

        [Display(Name = "เวลาสร้าง")]
        public Nullable<DateTime> Create_On { get; set; }
    }
}
