using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class cu_unix
    {
        [Key]
        public Int64 uid_number { get; set; }

        public string username { get; set; }
        public Int64 status_id { get; set; }
        public string userPassword { get; set; }
        public string full_name { get; set; }
        public string home_directory { get; set; }
        public string directory { get; set; }
        public DateTime? create_date { get; set; }
        public DateTime? modify_date { get; set; }
        public string create_by_username { get; set; }
        public string modify_by_username { get; set; }
    }
}
