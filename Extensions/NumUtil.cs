using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Extensions
{
    public class NumUtil
    {
        public static decimal Round(decimal? value)
        {
            if (value.HasValue)
            {
                return (decimal)Math.Round(value.Value, 2, MidpointRounding.AwayFromZero);
            }
            return 0;
        }

        public static decimal ParseDecimal(object s, decimal def = 0)
        {
            decimal d = 0;
            if (s != null)
            {
                try
                {
                    return Convert.ToDecimal(s.ToString().Trim().Replace(",", ""));
                }
                catch
                {
                    return d;
                }
            }
            return d;
        }

        public static decimal ParseDecimal(string s, decimal def = 0)
        {
            decimal d = 0;
            if (!string.IsNullOrEmpty(s))
            {
                try
                {
                    return Convert.ToDecimal(s.Trim().Replace(",", ""));
                }
                catch
                {
                    return d;
                }
            }
            return d;
        }

        public static int ParseInteger(string s, int def = 0)
        {
            int d = 0;
            if (!string.IsNullOrEmpty(s))
            {
                try
                {
                    return Convert.ToInt32(s.Trim().Replace(",", ""));
                }
                catch
                {
                    return d;
                }
            }
            return d;
        }

        public static int ParseInteger(object dd, int def = 0)
        {
            int d = 0;
            try
            {
                return Convert.ToInt32(dd);
            }
            catch
            {
                return d;
            }
        }

        public static string FormatCurrency(Nullable<double> val, int digit = 2)
        {
            try
            {
                if (val.HasValue)
                {
                    if (GetDoubleLength(val.Value) > 0)
                    {
                        if (digit > 0)
                            return val.Value.ToString("n" + digit.ToString());
                        else
                            return val.Value.ToString("n2");
                    }
                    else
                    {
                        if (digit > 0)
                            return val.Value.ToString("n" + digit.ToString());
                        else
                            return val.Value.ToString("n0");
                    }

                }
                if (digit > 0)
                    return "0.00";
                else
                    return "0";
            }
            catch
            {
                if (digit > 0)
                    return "0.00";
                else
                    return "0";
            }
        }
        public static string FormatCurrencyExcel(Nullable<decimal> val, int digit = 0)
        {
            try
            {
                if (val.HasValue)
                {
                    if (val.Value > 0)
                        return val.Value.ToString("n2");
                }
                return "";
            }
            catch
            {
                return "";
            }
        }
        public static string FormatPercenExcel(Nullable<decimal> val, int digit = 0)
        {
            try
            {
                if (val.HasValue)
                {
                    if (val.Value > 0)
                        return val.Value.ToString("n2") + "%";
                }
                return "";
            }
            catch
            {
                return "";
            }
        }
        public static string FormatCurrency(Nullable<decimal> val, int digit = 0)
        {
            try
            {
                if (val.HasValue)
                {
                    if (GetDecimalLength(val.Value) > 0)
                    {
                        if (digit > 0)
                            return val.Value.ToString("n" + digit.ToString());
                        else
                            return val.Value.ToString("n2");
                    }

                    else
                    {
                        if (digit > 0)
                            return val.Value.ToString("n" + digit.ToString());
                        else
                            return val.Value.ToString("n0");
                    }
                }
                if (digit > 0)
                    return "0.00";
                else
                    return "0";
            }
            catch
            {
                if (digit > 0)
                    return "0.00";
                else
                    return "0";
            }
        }
        public static string FormatYearMonthDay(Nullable<DateTime> d1, Nullable<DateTime> d2)
        {
            try
            {
                //var a = d1.Value.Subtract(d2).Year;
                if (d1.HasValue & d2.HasValue)
                {
                    var date2 = d2.Value;
                    var date1 = d1.Value;
                    if (date2 < date1)
                    {
                        var d2temp = date2;
                        date2 = date1;
                        date1 = d2temp;
                    }

                    var diff = date2.Subtract(date1); // May as well use midnight's
                    var totalDays = (int)Math.Ceiling(diff.TotalDays);

                    int years = 0, months = 0, days = 0;

                    while (totalDays >= 365)
                    {
                        years++;
                        totalDays = totalDays - 365;
                    }
                    while (totalDays >= 30)
                    {
                        months++;
                        totalDays = totalDays - 30;
                    }
                    days = totalDays;

                    var str = "";
                    if (years > 0)
                        str += years.ToString() + " ปี, ";
                    if (months > 0)
                        str += months.ToString() + " เดือน, ";
                    if (days > 0)
                        str += days.ToString() + " วัน";

                    if (str.Length > 2 && str[str.Length - 2] == ',')
                    {
                        str = str.Substring(0, str.Length - 2);
                    }
                    return str;
                }
                return "0 วัน";
            }
            catch
            {
                return "0 วัน";
            }
        }
        public static string FormatCurrency(Nullable<int> val)
        {
            try
            {
                if (val.HasValue)
                    return val.Value.ToString("n0");

                return "0";
            }
            catch
            {
                return "0";
            }
        }

        public static int GetDoubleLength(double dValue)
        {

            var tempValue = dValue.ToString();
            int decimalLength = 0;
            if (tempValue.Contains('.') || tempValue.Contains(','))
            {
                char[] separator = new char[] { '.', ',' };
                string[] tempstring = tempValue.Split(separator);

                if (ParseInteger(tempstring[1]) > 0)
                    decimalLength = tempstring[1].Length;
            }
            return decimalLength;
        }
        public static int GetDecimalLength(decimal dValue)
        {

            var tempValue = dValue.ToString();
            int decimalLength = 0;
            if (tempValue.Contains('.') || tempValue.Contains(','))
            {
                char[] separator = new char[] { '.', ',' };
                string[] tempstring = tempValue.Split(separator);

                if (ParseInteger(tempstring[1]) > 0)
                    decimalLength = tempstring[1].Length;
            }
            return decimalLength;
        }

        public static int GetDecimalLength(string dValue)
        {
            var tempValue = dValue;
            int decimalLength = 0;
            if (tempValue.Contains('.') || tempValue.Contains(','))
            {
                char[] separator = new char[] { '.', ',' };
                string[] tempstring = tempValue.Split(separator);

                if (ParseInteger(tempstring[1]) > 0)
                    decimalLength = tempstring[1].Length;
            }
            return decimalLength;
        }

        public static bool IsNumeric(object s)
        {
            if (s != null)
                return IsNumeric2(s.ToString());

            return false;
        }

        private static bool IsNumeric2(string s)
        {
            if (!string.IsNullOrEmpty(s))
            {
                try
                {
                    var num = Convert.ToDecimal(s.Trim().Replace(",", ""));
                    return true;
                }
                catch
                {
                    return false;
                }
            }
            return false;
        }
    }
}
