using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class reset_password_temp
    {
        [Key]
        public Int64 temp_id { get; set; }

        public string username  { get; set; }

        public string password  { get; set; }

        public string ip { get; set; }

        public string target_ip { get; set; }

        public string reset_by { get; set; }
        public DateTime? reset_date { get; set; }

        public string status { get; set; }
    }
}
