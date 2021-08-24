using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Extensions
{
    public class AppUtil
    {
        public static string getNewPassword()
        {
            string newPassword = getNewPassword(8);
            return newPassword;
        }
        public static string getNewPassword(int passwordLength)// gen new password
        {
            /*
             *  a,c,d,e,f,h,i,j,k,n,p,r,t,u,v,w,x,
                2,3,4,5,7,8,
                A,C,D,E,F,H,I,J,K,M,N,P,Q,R,S,T,U,V,W,X,Y 
             */
            string newPassword = "";
            //int passwordLength = 8;
            string[] numberSet = { "2", "3", "4", "5", "6", "7", "8" };
            string[] passwordSet = { "a", "c", "d", "e", "f", "h", "i", "j", "k", "n", "p", "r", "t", "u", "v", "w", "x", "A", "C", "D", "E", "F", "H", "I", "J", "K", "M", "N", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y" };
            Random random = new Random();
            while (newPassword.Length < passwordLength)
            {
                int randomSet = random.Next(0, 100);
                if ((randomSet % 2) == 0) { newPassword += numberSet[(random.Next(0, (numberSet.Length - 1)))]; }
                else if ((randomSet % 2) == 1) { newPassword += passwordSet[(random.Next(0, (passwordSet.Length - 1)))]; }
            }
            return newPassword;
        }
        public static string  getOuName(string ou, bool lower = true)
        {
            if (!string.IsNullOrEmpty(ou))
            {
                ou = ou.Replace("o=", "").Replace("ou=", "");
                if (lower)
                    ou = ou.ToLower();
            }
            return ou;
        }
        public static string stringUpper(string str)
        {
            if (!string.IsNullOrEmpty(str))
            {
                str = str.Substring(0, 1).ToUpper() + str.Substring(1).ToLower();
                str = str.Trim();
            }
            return str;
        }
        public static object ManageNull(object obj)
        {
            if (obj == null)
                return "";
            else
                return obj;
        }

    }
}
