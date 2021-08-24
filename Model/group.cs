using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class group
    {
        [Key]
        public Int64 group_id { get; set; }
        public string group_name { get; set; }

        public string group_username_list { get; set; }
        public string group_manage_distinguish_name_list { get; set; }
        public Int64? group_priority { get; set; }
        public string group_description { get; set; }

    }
}
