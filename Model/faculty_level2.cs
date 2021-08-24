using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class faculty_level2
    {
        [Key]
        public Int64 sub_office_id { get; set; }
        public string sub_office_name { get; set; }
        public string sub_office_name_eng { get; set; }
        public string sub_office_shot_name { get; set; }
        public string sub_office_telephonenumber { get; set; }
        public Int64? faculty_id { get; set; }
        public string faculty_name { get; set; }
        public string create_by_username { get; set; }
        public DateTime? create_date { get; set; }

    }
}
