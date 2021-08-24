using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using IDMAPI.DAL;
using IDMAPI.Extensions;
using IDMAPI.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
namespace IDMAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class APIController : ControllerBase
    {
        public IUserProvider _provider;
        public ILDAPUserProvider _providerldap;
        public SpuContext _context;

        private readonly IConfiguration _config;
        private List<User> appUsers = new List<User>
        {
            new User { FullName = "Vaibhav Bhapkar", Username = "admin", Password = "1234", UserRole = "Admin" },
            new User { FullName = "Test User", Username = "user", Password = "1234", UserRole = "User" }
        };
        public APIController(IConfiguration config, SpuContext context, IUserProvider provider, ILDAPUserProvider providerldap)
        {
            _config = config;
            this._provider = provider;
            this._providerldap = providerldap;
            this._context = context;
        }

        [HttpPost]
        [Route("gettoken")]
        public IActionResult GetToken([FromBody] Token model)
        {
            IActionResult response = Unauthorized();
            if(model.Username != _config["Jwt:UserName"])
                return response;
            if (model.Password != _config["Jwt:Password"])
                return response;

            var user = new User();
            user.FullName = "API";
            user.Username = model.Username;
            user.Password = model.Username;
            user.UserRole = Policies.User;
            var tokenString = GenerateJWTToken(user);
            response = Ok(new
            {
                token = tokenString
            });
            return response;
        }

        string GenerateJWTToken(User userInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userInfo.Username),
                new Claim("fullName", userInfo.FullName.ToString()),
                new Claim("role",userInfo.UserRole),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };
            var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpPost]
        [Route("resetpwd")]
        [Authorize(Policy = Policies.User)]
        public async Task<IActionResult> ResetPwd([FromBody] User model)
        {
            if (string.IsNullOrEmpty(model.Username))
            {
                return Ok(new { code = -1, msg = "username cannot be null." });
            }
            if (string.IsNullOrEmpty(model.Password))
            {
                return Ok(new { code = -1, msg = "password cannot be null." });
            }

            var basic_uid = model.Username;
            var pwd ="";
            try
            {
                pwd = DataEncryptor.Decrypt(model.Password);
            }
            catch
            {
                return Ok(new { code = -1, msg = "password format is incorrect." });
            }
            if(pwd.Length < 8)
            {
                return Ok(new { code = -1, msg = "password length cannot be less than 8 characters." });
            }
            if (pwd.Length > 16)
            {
                return Ok(new { code = -1, msg = "password length cannot be more than 16 characters." });
            }           
            if (!Regex.IsMatch(pwd, @"\d"))
            {
                return Ok(new { code = -1, msg = "password must contain at least one numeric digit" });
            }
            if (!Regex.IsMatch(pwd, @"[a-z]"))
            {
                return Ok(new { code = -1, msg = "password must contain at least one lower letter" });
            }
            if (!Regex.IsMatch(pwd, @"[A-Z]"))
            {
                return Ok(new { code = -1, msg = "password must contain at least one uppercase letter" });
            }
            var fim_user = this._context.table_visual_fim_user.Where(w => w.basic_uid.ToLower() == basic_uid.ToLower()).FirstOrDefault();
            if (fim_user != null)
            {
                fim_user.basic_userPassword = Cryptography.encrypt(pwd);
                fim_user.cu_pwdchangeddate = DateUtil.Now();
                fim_user.cu_pwdchangedby = basic_uid;
                fim_user.cu_pwdchangedloc = getClientIP();
                fim_user.system_actived = true;

                _context.SaveChanges();

                var result_ldap = _providerldap.ChangePwd(fim_user, pwd, _context);
                if (result_ldap.result == true)
                    writelog(LogType.log_reset_password_api, LogStatus.successfully, IDMSource.LDAP, basic_uid);
                else
                    writelog(LogType.log_reset_password_api, LogStatus.failed, IDMSource.LDAP, basic_uid, log_exception: result_ldap.Message);

                var result_ad = _provider.ChangePwd(fim_user, pwd, _context);
                if (result_ad.result == true)
                    writelog(LogType.log_reset_password_api, LogStatus.successfully, IDMSource.AD, basic_uid);
                else
                    writelog(LogType.log_reset_password_api, LogStatus.failed, IDMSource.AD, basic_uid, log_exception: result_ad.Message);

                writelog(LogType.log_reset_password_api, LogStatus.successfully, IDMSource.VisualFim, basic_uid);
                return Ok(new { code = 1, msg = "password has been reset successfully." });

            }
            return Ok(new { code = -1, msg = "user has not found" });
        }

        public string getHostIP()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            var ipAddress = "";
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    ipAddress += ip.ToString() + " ";
                }
            }
            return ipAddress;
        }

        public string getClientIP()
        {
            string result = "";
            var UserHostAddress = this.HttpContext.Connection.RemoteIpAddress.ToString();
            var UserHostName = this.HttpContext.Connection.LocalIpAddress.ToString();
            string HTTP_X_FORWARDED_FOR = HttpContext.Request.Headers["X-Forwarded-For"];
            string REMOTE_ADDR = HttpContext.Request.Headers["REMOTE_ADDR"];


            if (string.IsNullOrEmpty(REMOTE_ADDR) == false)
            {
                //---------------------------------------------------------------
                //ComputerName = System.Net.Dns.GetHostEntry(REMOTE_ADDR).HostName;
                //---------------------------------------------------------------
                if (string.IsNullOrEmpty(result)) { result = REMOTE_ADDR; }
                else { if (result.Contains(REMOTE_ADDR)) { } else { result += "," + REMOTE_ADDR; } }
            }
            if (string.IsNullOrEmpty(HTTP_X_FORWARDED_FOR) == false)
            {
                string[] ipRange = HTTP_X_FORWARDED_FOR.Split(',');
                for (int i = 0; i < ipRange.Length; i++)
                {
                    if (string.IsNullOrEmpty(result)) { result = ipRange[i]; }
                    else { if (result.Contains(ipRange[i])) { } else { result += "," + ipRange[i]; } }
                }
            }
            if (string.IsNullOrEmpty(UserHostAddress) == false)
            {
                if (string.IsNullOrEmpty(result)) { result = UserHostAddress; }
                else { if (result.Contains(UserHostAddress)) { } else { result += "," + UserHostAddress; } }
            }
            if (string.IsNullOrEmpty(UserHostName) == false)
            {
                if (string.IsNullOrEmpty(result)) { result = UserHostName; }
                else { if (result.Contains(UserHostName)) { } else { result += "," + UserHostName; } }
            }
            return UserHostAddress;
        }

        public bool logTableIsExist(string tablename)
        {
            try
            {
                var object_id = "";
                var sql = "select object_id from sys.tables where name = '" + tablename + "'";
                using (var command = _context.Database.GetDbConnection().CreateCommand())
                {
                    command.CommandText = sql;
                    _context.Database.OpenConnection();
                    using (var result = command.ExecuteReader())
                    {
                        // do something with result
                        while (result.Read())
                        {
                            object_id = result.GetValue(0).ToString();
                        }
                    }
                    _context.Database.CloseConnection();
                }
                var column_id = "";
                sql = "select column_id from sys.columns where name = 'log_exception' and object_id = '" + object_id + "'";
                using (var command = _context.Database.GetDbConnection().CreateCommand())
                {
                    command.CommandText = sql;
                    _context.Database.OpenConnection();
                    using (var result = command.ExecuteReader())
                    {
                        // do something with result
                        while (result.Read())
                        {
                            column_id = result.GetValue(0).ToString();
                        }
                    }
                    _context.Database.CloseConnection();
                }
                if (string.IsNullOrEmpty(column_id))
                {
                    using (var command = _context.Database.GetDbConnection().CreateCommand())
                    {
                        command.CommandText = "alter table " + tablename + " add [log_exception][nvarchar](max) NULL";
                        _context.Database.OpenConnection();
                        var result = command.ExecuteNonQuery();
                        _context.Database.CloseConnection();
                    }
                }
                if (!string.IsNullOrEmpty(object_id))
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                return false;
            }
            return false;
        }
        public bool logTableCreate(string tablename)
        {
            try
            {
                var datetime = DateUtil.Now();
                var curdate = datetime.Year + "_" + datetime.Month.ToString("00") + "_" + datetime.Day.ToString("00");
                var sql = new StringBuilder();
                sql.AppendLine("CREATE TABLE[dbo].[" + tablename + "](");
                sql.AppendLine(" [log_id] [bigint] IDENTITY(1,1) NOT NULL,");
                sql.AppendLine(" [log_username][nvarchar](max) NULL,");
                sql.AppendLine(" [log_ip][nvarchar](max) NULL,");
                sql.AppendLine(" [log_type_id] [bigint] NULL,");
                sql.AppendLine(" [log_type][nvarchar](max) NULL,");
                sql.AppendLine(" [log_action][nvarchar](max) NULL,");
                sql.AppendLine(" [log_status][nvarchar](max) NULL,");
                sql.AppendLine(" [log_description][nvarchar](max) NULL,");
                sql.AppendLine(" [log_target][nvarchar](max) NULL,");
                sql.AppendLine(" [log_target_ip][nvarchar](max) NULL,");
                sql.AppendLine(" [log_datetime][nvarchar](max) NULL,");
                sql.AppendLine(" [log_exception][nvarchar](max) NULL");
                sql.AppendLine(") ON[PRIMARY]");
                using (var command = _context.Database.GetDbConnection().CreateCommand())
                {
                    command.CommandText = sql.ToString();
                    _context.Database.OpenConnection();
                    var result = command.ExecuteNonQuery();
                    _context.Database.CloseConnection();
                }
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public void writelog(LogType log_type_id, string log_status, IDMSource source, string uid, string log_description = "", string logonname = "", string log_exception = "")
        {
            if (string.IsNullOrEmpty(log_description))
            {
                if (log_type_id == LogType.log_create_account)
                    log_description = "สร้างบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_create_account_with_file)
                    log_description = "สร้างบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_edit_account)
                    log_description = "แก้ไขบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_delete_account)
                    log_description = "ลบบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_delete_account_with_file)
                    log_description = "ลบบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_change_password)
                    log_description = "เปลี่ยนรหัสผ่านบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_reset_password)
                    log_description = "เปลี่ยนรหัสผ่านบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_lock_account)
                    log_description = "ล็อกบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_unlock_account)
                    log_description = "ปลดล็อกบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_lock_account_with_file)
                    log_description = "ล็อกบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_unlock_account_with_file)
                    log_description = "ปลดล็อกบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_edit_internetaccess)
                    log_description = "แก้ไข Internet Access บัญชีผู้ใช้";
                else if (log_type_id == LogType.log_approve_reset_password)
                    log_description = "ขอเปลี่ยนรหัสผ่านบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_move_account)
                    log_description = "ย้ายกลุ่มของบัญชีรายชื่อผู้ใช้";
                else if (log_type_id == LogType.log_approved_reset_password)
                    log_description = "อนุมัติการขอเปลี่ยนรหัสผ่านบัญชีผู้ใช้";
                else if (log_type_id == LogType.log_reset_password_api)
                    log_description = "เปลี่ยนรหัสผ่านบัญชีผู้ใช้จาก API";

                log_description += " " + uid + " บน " + source.ToString();
                if (log_status == LogStatus.successfully)
                    log_description += " สำเร็จ";
                else
                    log_description += " ไม่สำเร็จ";
            }

            if (string.IsNullOrEmpty(logonname))
                logonname = this.HttpContext.User.Identity.Name;

            string controller = ControllerContext.ActionDescriptor.ControllerName;
            string action = ControllerContext.ActionDescriptor.ActionName;

            var log_target = Request.Scheme + "://" + Request.Host.Value + "/" + controller + "/" + action;
            var log_action = "";

            var datetime = DateUtil.Now();
            var curdate = datetime.Year + "_" + datetime.Month.ToString("00") + "_" + datetime.Day.ToString("00");
            var tablename = "table_system_log_" + curdate;
            if (logTableIsExist(tablename) == false)
            {
                if (logTableCreate(tablename) == false)
                    return;
            }
            try
            {
                var sql = new StringBuilder();
                sql.AppendLine("INSERT INTO [DSM].[dbo].[" + tablename + "](");
                sql.AppendLine(" [log_username]");
                sql.AppendLine(" ,[log_ip]");
                sql.AppendLine(" ,[log_type_id]");
                sql.AppendLine(" ,[log_type]");
                sql.AppendLine(" ,[log_action]");
                sql.AppendLine(" ,[log_status]");
                sql.AppendLine(" ,[log_description]");
                sql.AppendLine(" ,[log_target]");
                sql.AppendLine(" ,[log_target_ip]");
                sql.AppendLine(" ,[log_datetime]");
                sql.AppendLine(" ,[log_exception])");
                sql.AppendLine(" VALUES (");
                sql.AppendLine(" '" + logonname + "'");
                sql.AppendLine(" ,'" + getClientIP() + "'");
                sql.AppendLine(" ," + (int)log_type_id);
                sql.AppendLine(" ,'" + log_type_id.ToString() + "'");
                sql.AppendLine(" ,'" + log_action + "'");
                sql.AppendLine(" ,'" + log_status + "'");
                sql.AppendLine(" ,'" + log_description + "'");
                sql.AppendLine(" ,'" + log_target + "'");
                sql.AppendLine(" ,'" + getHostIP() + "'");
                sql.AppendLine(" , getdate() ");
                sql.AppendLine(" ,'" + log_exception + "'");
                sql.AppendLine(" )");
                using (var command = _context.Database.GetDbConnection().CreateCommand())
                {
                    command.CommandText = sql.ToString();
                    _context.Database.OpenConnection();
                    var result = command.ExecuteNonQuery();
                    _context.Database.CloseConnection();
                }
            }
            catch (Exception ex)
            {

            }

        }

    }
}