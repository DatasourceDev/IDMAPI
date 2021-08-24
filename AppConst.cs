using IDMAPI.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI
{
    public class AppConst
    {

    }
    public enum IDMSource
    {
        VisualFim,
        AD,
        LDAP
    }
    public enum IDMUserType
    {
        staff = 301, //บุคลากร
        student = 302, //นิสิต
        outsider = 303, //บุคคลภายนอก
        affiliate = 304, //วิสาหกิจ
        temporary = 305, //ผู้ใช้แบบชั่วคราว
    }
    public enum Status
    {
        Enable = 0,
        Disable = 1,
    }
    public enum ApprovalStatus
    {
        Pending,
        Approved,
        Rejected
    }

    public enum ReturnCode
    {
        Success = 1,
        Error = -1,
    }
    public enum userAccountControl
    {
        Enable = 512,
        Disable = 514,
        EnablePasswordNotRequired = 544,
        DisablePasswordNotRequired = 546,
    }

    public enum RegisterType
    {
        Manual,
        Import
    }
    public enum SendMessageType
    {
        SMS,
        Email
    }
    public enum ImportCreateOption
    {
        student,
        student_sasin,
        student_ppc,
        student_other,
        staff_hr,
        staff_other,
        temp
    }
    public enum ImportLockOption
    {
        pplid,
        loginname
    }
    public enum ImportDeleteOption
    {
        pplid,
        loginname
    }

    public enum ImportType
    {
        lockunlock,
        delete,
        create
    }
    public static class ReturnMessage
    {
        public static string Success = "บันทึกข้อมูลสำเร็จ";
        public static string ChangePasswordSuccess = "เปลี่ยนรหัสผ่านสำเร็จ";
        public static string Error = "บันทึกข้อมูลไม่สำเร็จ";
        public static string ChangePasswordFail = "เปลี่ยนรหัสผ่านไม่สำเร็จ";
        public static string SuccessOTP = "ส่งรหัส OTP สำเร็จ";
        public static string DataInUse = "ไม่สามารถลบรายการน้ได้เนื่องจากมีข้อมูลบางรายการที่อ้างอิงถึงรายการนี้";
        public static string ImportFail = "นำเข้าข้อมูลไม่สำเร็จ";
        public static string ImportSuccess = "นำเข้าข้อมูลข้อมูลสำเร็จ";
    }
    public static class  Portal
    {
        public static string admin = "admin";
        public static string user = "user";
    }
    public static class LogStatus
    {
        public static string successfully = "successfully";
        public static string failed = "failed";
    }
    public enum LogType
    {
        log_login = 15,
        log_edit_security_questions,
        log_logout,
        log_receive_account_student,
        log_try_access_page,
        log_helpdesk,
        log_reset_password_in_forgot_password,
        log_change_password,
        log_reset_password,
        log_check_privilege,
        log_add_new_menu,
        log_add_menu_to_group,
        log_create_script,
        log_create_account,
        log_synchronize_student_account,
        log_synchronize_staff_account,
        log_delete_account_with_file,
        log_synchronize_all_account,
        log_create_account_with_file,
        log_move_account,
        log_add_account_to_group,
        log_edit_menu,
        log_remove_menu_from_group,
        log_add_new_admin,
        log_edit_group,
        log_check_database,
        log_backup_database,
        log_edit_account_for_admin,
        log_setup_database,
        log_test_connection,
        log_restore_database,
        log_delete_menu,
        log_reset_password_admin,
        log_delete_account,
        log_delete_admin,
        log_synchronize_temporary_account,
        log_add_new_group,
        log_edit_account_for_helpdesk,
        log_create_account_temporary,
        log_edit_account,
        log_edit_vpn,
        log_delete_group,
        log_edit_internetaccess,
        log_edit_lock_unlock_account,
        log_edit_netcastaccess,
        log_edit_email_student,
        log_create_one_day_account,
        log_disable_account_from_file,
        log_synchronize_oneday_account,
        log_approve_reset_password,
        log_lock_account,
        log_unlock_account,
        log_lock_account_with_file,
        log_unlock_account_with_file,
        log_approved_reset_password,
        log_reset_password_api,

    }
    public static class LogActivity
    {
        public static string ResetPassword = "Reset Password";
        public static string ForgotPassword = "Forgot Password";
        public static string ChangePassword = "Change Password";
        public static string RegisterGuest = "Register Guest";
        public static string ChangeExpiryDate = "Change Expiry Date";
        public static string ApproveGuest = "Approve Guest";
        public static string RejectGuest = "Reject Guest";
        public static string EditGuest = "Edit Guest";
        public static string DeleteGuest = "Delete Guest";
        public static string ImportGuest = "Import Guest";
        public static string OTPRequest = "OTP Requested";
        public static string OTPVerified = "OTP Verified";
        public static string DisableGuest = "Disable Guest";
        public static string EnableGuest = "Enable Guest";
    }
    public static class LockStaus
    {
        public static string Lock = "TRUE";
        public static string Unlock = "FALSE";
    }

    public static class EnumStatus
    {
        public static IDMUserType ToUserType(this string text)
        {
            var status = IDMUserType.staff;
            switch (text)
            {
                case "staff":
                    status = IDMUserType.staff;
                    break;
                case "student":
                    status = IDMUserType.student;
                    break;
                case "outsider":
                    status = IDMUserType.outsider;
                    break;
                case "affiliate":
                    status = IDMUserType.affiliate;
                    break;
                case "temporary":
                    status = IDMUserType.temporary;
                    break;
                default:
                    break;
            }
            return status;
        }

        public static string toUserTypeName(this IDMUserType statusType)
        {
            string status = "";
            switch (statusType)
            {
                case IDMUserType.staff:
                    status = "Staff";
                    break;
                case IDMUserType.student:
                    status = "Student";
                    break;
                case IDMUserType.outsider:
                    status = "Outsider";
                    break;
                case IDMUserType.affiliate:
                    status = "Affiliate";
                    break;
                case IDMUserType.temporary:
                    status = "Temporary";
                    break;
                default:
                    break;
            }
            return status;
        }

        public static Status toStatus(this string text)
        {
            var status = Status.Enable;
            switch (text)
            {
                case "Disable":
                    status = Status.Disable;
                    break;
                case "Enable":
                    status = Status.Enable;
                    break;
                default:
                    break;
            }
            return status;
        }

        public static string toStatusName(this Status statusType)
        {
            string status = "";
            switch (statusType)
            {
                case Status.Disable:
                    status = "Disable";
                    break;
                case Status.Enable:
                    status = "Enable";
                    break;
                default:
                    break;
            }
            return status;
        }

        public static ApprovalStatus toApprovalStatus(this string text)
        {
            var status = ApprovalStatus.Pending;
            switch (text)
            {
                case "รอการอนุมัติ":
                    status = ApprovalStatus.Pending;
                    break;
                case "อนุมัติแล้ว":
                    status = ApprovalStatus.Approved;
                    break;
                case "ไม่อนุมัติ":
                    status = ApprovalStatus.Rejected;
                    break;
                default:
                    break;
            }
            return status;
        }

        public static string toApprovalStatusName(this ApprovalStatus statusType)
        {
            string status = "";
            switch (statusType)
            {
                case ApprovalStatus.Pending:
                    status = "รอการอนุมัติ";
                    break;
                case ApprovalStatus.Approved:
                    status = "อนุมัติแล้ว";
                    break;
                case ApprovalStatus.Rejected:
                    status = "ไม่อนุมัติ";
                    break;
                default:
                    break;
            }
            return status;
        }

        public static userAccountControl toUserAccountControl(this string text)
        {
            if (text == ((int)userAccountControl.Disable).ToString())
            {
                return userAccountControl.Disable;
            }
            else if (text == ((int)userAccountControl.DisablePasswordNotRequired).ToString())
            {
                return userAccountControl.DisablePasswordNotRequired;
            }
            else if (text == ((int)userAccountControl.Enable).ToString())
            {
                return userAccountControl.Enable;
            }
            else if (text == ((int)userAccountControl.EnablePasswordNotRequired).ToString())
            {
                return userAccountControl.EnablePasswordNotRequired;
            }
            return userAccountControl.Enable;
        }

        public static string toUserAccountControl(this userAccountControl statusType)
        {
            string status = "";
            switch (statusType)
            {
                case userAccountControl.Disable:
                    status = ((int)userAccountControl.Disable).ToString();
                    break;
                case userAccountControl.DisablePasswordNotRequired:
                    status = ((int)userAccountControl.DisablePasswordNotRequired).ToString();
                    break;
                case userAccountControl.Enable:
                    status = ((int)userAccountControl.Enable).ToString();
                    break;
                case userAccountControl.EnablePasswordNotRequired:
                    status = ((int)userAccountControl.EnablePasswordNotRequired).ToString();
                    break;
                default:
                    break;
            }
            return status;
        }

        public static ImportCreateOption toImportCreateOption(this string text)
        {
            if (text == ((int)ImportCreateOption.student).ToString())
            {
                return ImportCreateOption.student;
            }
            else if (text == ((int)ImportCreateOption.student_sasin).ToString())
            {
                return ImportCreateOption.student_sasin;
            }
            else if (text == ((int)ImportCreateOption.student_ppc).ToString())
            {
                return ImportCreateOption.student_ppc;
            }
            else if (text == ((int)ImportCreateOption.student_other).ToString())
            {
                return ImportCreateOption.student_other;
            }
            else if (text == ((int)ImportCreateOption.staff_hr).ToString())
            {
                return ImportCreateOption.staff_hr;
            }
            else if (text == ((int)ImportCreateOption.staff_other).ToString())
            {
                return ImportCreateOption.staff_other;
            }
            else if (text == ((int)ImportCreateOption.temp).ToString())
            {
                return ImportCreateOption.temp;
            }
            return ImportCreateOption.student;
        }
    }

}
