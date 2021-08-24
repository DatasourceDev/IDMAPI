using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Models
{
    public class Guest
    {
        [Key]
        public int ID { get; set; }

        [Display(Name = "รหัสผู้ใช้")]
        [MaxLength(250)]
        public string GuestCode { get; set; }

        [Display(Name = "ชื่อ")]
        [MaxLength(250, ErrorMessage = "จำนวนอักษรไม่ควรเกิน 250 ตัวอักษร")]
        public string FirstName { get; set; }

        [Display(Name = "นามสกุล")]
        [MaxLength(250, ErrorMessage = "จำนวนอักษรไม่ควรเกิน 250 ตัวอักษร")]
        public string LastName { get; set; }

        [Required]
        [Display(Name = "สถานะการใช้งาน")]
        public Status Status { get; set; }

        [Display(Name = "OTP Verify")]
        public bool OTPVerify { get; set; }

        [Required]
        [Display(Name = "สถานะการอนุมัติ")]
        public ApprovalStatus ApprovalStatus { get; set; }

        [Display(Name = "วันที่อนุมัติ")]
        public Nullable<DateTime> ApprovalDate { get; set; }

        [Display(Name = "อนุมัติโดย")]
        [MaxLength(250)]
        public string ApprovalBy { get; set; }

        [Display(Name = "รหัสบัตรประชาชน")]
        [MaxLength(14)]
        public string IDCard { get; set; }

        [Display(Name = "อีเมล")]
        [MaxLength(100)]
        public string Email { get; set; }

        [Display(Name = "โทรศัพท์")]
        [MaxLength(10)]
        public string Phone { get; set; }

        [Display(Name = "ชื่อบริษัท / ชื่อหน่วยงาน")]
        [MaxLength(500)]
        public string Job { get; set; }

        [Display(Name = "ชื่อบริษัท / ชื่อหน่วยงาน")]
        [MaxLength(500)]
        public string Department { get; set; }

        [Display(Name = "ที่อยู่")]
        [MaxLength(1000)]
        public string Address { get; set; }

        [Display(Name = "จังหวัด")]
        public int? ProvinceID { get; set; }


        [Display(Name = "อำเภอ")]
        public int? AumphurID { get; set; }


        [Display(Name = "ตำบล")]
        public int? TumbonID { get; set; }

        [Display(Name = "รหัสไปรษณีย์")]
        [MaxLength(5)]
        public string PostalCode { get; set; }

        [Display(Name = "วันที่เปิดใช้งาน")]
        public DateTime? OpenDate { get; set; }

        [Display(Name = "วันที่หมดอายุ")]
        public DateTime? ExpiryDate { get; set; }

        [NotMapped]
        public string ExpiryDateStr { get; set; }

        [Display(Name = "รหัสประจำอุปกรณ์ 1")]
        [MaxLength(17)]
        public string MacAddress1 { get; set; }

        [Display(Name = "รหัสประจำอุปกรณ์ 2")]
        [MaxLength(17)]
        public string MacAddress2 { get; set; }

        [Display(Name = "รหัสประจำอุปกรณ์ 3")]
        [MaxLength(17)]
        public string MacAddress3 { get; set; }

        [Display(Name = "ผู้ใช้งาน")]
        public int UserID { get; set; }

        [Display(Name = "OU")]
        public int? OUID { get; set; }

        [Display(Name = "วิธีการลงทะเบียน")]
        public RegisterType RegisterType { get; set; }

        [Display(Name = "สร้างบัญชีบน AD แล้ว")]
        public bool ADCreated { get; set; }

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
        public User User { get; set; }
        public OU OU { get; set; }


        [NotMapped]
        public string ImportRemark { get; set; }
        [NotMapped]
        public bool ImportVerify { get; set; }

       

        [NotMapped]
        public int? MacAddressNumShow { get; set; }

        


    }
}
