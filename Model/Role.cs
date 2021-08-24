using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class Role
    {
        [Key]
        public int ID { get; set; }

        [Required]
        [Display(Name = "OU")]
        public int? OUID { get; set; }

        [Required]
        [Display(Name = "ชื่อสิทธิ์")]
        [MaxLength(250)]
        public string RoleName { get; set; }
        public int Index { get; set; }

        [Display(Name = "คำอธิบาย")]
        [MaxLength(1000)]
        public string Description { get; set; }

        public OU OU { get; set; }


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


        [NotMapped]
        public IQueryable<visual_fim_user> SelectedAdmins { get; set; }
        [NotMapped]
        public IQueryable<visual_fim_user> UnSelecteAdmins { get; set; }
        [NotMapped]
        public int[] UnSelectedID { get; set; }
        [NotMapped]
        public int[] SelectedID { get; set; }


    }
}
