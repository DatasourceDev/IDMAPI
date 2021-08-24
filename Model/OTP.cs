using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class OTP
    {
        [Key]
        public int ID { get; set; }

        [Display(Name = "Username")]
        [MaxLength(150)]
        public string Username { get; set; }

        [Display(Name = "ชื่อ")]
        [MaxLength(250)]
        public string FirstName { get; set; }

        [Display(Name = "นามสกุล")]
        [MaxLength(250)]
        public string LastName { get; set; }

        [Display(Name = "RefNo")]
        [MaxLength(10)]
        public string RefNo { get; set; }


        [Display(Name = "OTP Number")]
        [MaxLength(10)]
        public string OTPNumber { get; set; }

        [Display(Name = "เบอร์โทรศัพท์")]
        [MaxLength(15)]
        public string MobileNo { get; set; }


        [Display(Name = "อีเมล์")]
        [MaxLength(150)]
        public string Email { get; set; }

        public SendMessageType SendMessageType { get; set; }

        [Display(Name = "เวลาสร้าง")]
        public Nullable<DateTime> Create_On { get; set; }

        [Display(Name = "เวลาหมดอายุ")]
        public Nullable<DateTime> Expire_On { get; set; }

        [Display(Name = "ใช้งานแล้ว")]
        public bool Used { get; set; }
    }
}
