using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class faculty
    {
        [Key]
        public Int64 faculty_id { get; set; }

        public string faculty_name { get; set; }
        public string faculty_name_eng { get; set; }
        public string faculty_shot_name { get; set; }
        public string faculty_distinguish_name_staff { get; set; }
        public string faculty_distinguish_name_student { get; set; }
        public string faculty_distinguish_name_outsider { get; set; }
        public string faculty_distinguish_name_affiliate { get; set; }
        public string faculty_telephonenumber { get; set; }
        public DateTime? create_date { get; set; }
        public string create_by_username { get; set; }
        public DateTime? modified_date { get; set; }
        public string modified_by_username { get; set; }
    }
}
