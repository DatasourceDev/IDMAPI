using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class system_log
    {
        [Key]
        public Int64 log_id { get; set; }

        public string log_username { get; set; }
        public string log_ip { get; set; }
        public Int64 log_type_id { get; set; }
        public string log_type { get; set; }
        public string log_action { get; set; }
        public string log_status { get; set; }
        public string log_description { get; set; }
        public string log_target { get; set; }
        public string log_target_ip  { get; set; }
        public string log_exception { get; set; }
        public string log_datetime { get; set; }
    }
}
