using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class group_user
    {
        [Key]
        public Int64 id { get; set; }

        [Required]
        [Display(Name = "กลุ่ม")]
        [ForeignKey("group")]
        public Int64 group_id { get; set; }

        [Required]
        [Display(Name = "ผู้ดูแลระบบ")]
        [ForeignKey("fim_user")]
        public Int64 fim_user_id { get; set; }

        public group group { get; set; }

        public visual_fim_user fim_user { get; set; }


    }
}
