using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace IDMAPI.Extensions
{
   public class DateUtil
   {
      private static string BangkokTimeZoneCode = "SE Asia Standard Time";
      public static DateTime Now()
      {
         TimeZoneInfo cstZone = TimeZoneInfo.FindSystemTimeZoneById(BangkokTimeZoneCode);
         DateTime cstTime = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, cstZone);
         return cstTime;
      }
      public static string GetShortMonth(Nullable<int> month)
      {
         try
         {
            switch (month)
            {
               case 1:
                  return "Jan";
               case 2:
                  return "Feb";
               case 3:
                  return "Mar";
               case 4:
                  return "Apr";
               case 5:
                  return "May";
               case 6:
                  return "Jun";
               case 7:
                  return "Jul";
               case 8:
                  return "Aug";
               case 9:
                  return "Sep";
               case 10:
                  return "Oct";
               case 11:
                  return "Nov";
               case 12:
                  return "Dec";
               default:
                  return "";
            }
         }
         catch
         {
            return "";
         }
      }

      public static string GetFullMonth(Nullable<int> month)
      {
         try
         {
            switch (month)
            {
               case 1:
                  return "มกราคม";
               case 2:
                  return "กุมภาพันธ์";
               case 3:
                  return "มีนาคม";
               case 4:
                  return "เมษายน";
               case 5:
                  return "พฤษภาคม";
               case 6:
                  return "มิถุนายน";
               case 7:
                  return "กรกฎาคม";
               case 8:
                  return "สิงหาคม";
               case 9:
                  return "กันยายน";
               case 10:
                  return "ตุลาคม";
               case 11:
                  return "พฤศจิกายน";
               case 12:
                  return "ธันวาคม";
               default:
                  return "";
            }
         }
         catch
         {
            return "";
         }
      }
      public static string GetFullDayOfweek(Nullable<int> dayOfweek)
      {
         try
         {

            switch (dayOfweek)
            {
               case -1:
                  return "ทุกวัน";
               case 0:
                  return "อาทิตย์";
               case 1:
                  return "จันทร์";
               case 2:
                  return "อังคาร";
               case 3:
                  return "พุธ";
               case 4:
                  return "พฤหัสบดี";
               case 5:
                  return "ศุกร์";
               case 6:
                  return "เสาร์";
               default:
                  return "";
            }
         }
         catch
         {
            return "";
         }
      }
      public static string ToDisplayDate(DateTime d)
      {
         try
         {
            CultureInfo UsaCulture = new CultureInfo("en-US");
            return d.ToString("dd/MM/yyyy", UsaCulture);
         }
         catch
         {
            return "";
         }
      }

      public static string ToDisplayDate(Nullable<DateTime> d, string indicator = "/")
      {
         try
         {
            if (d.HasValue)
            {
               CultureInfo UsaCulture = new CultureInfo("en-US");
               return d.Value.ToString("dd/MM/yyyy", UsaCulture);
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static string ToDisplayDate2(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               return d.Value.ToString("dd.MM.yyyy");
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static string ToDisplayDate3(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               return d.Value.ToString("ddMMyyyy");
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }
      public static string ToDisplayFullDayOfweek(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               CultureInfo UsaCulture = new CultureInfo("en-US");
               return d.Value.ToString("dddd dd MMM yyyy", UsaCulture);
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static string ToDisplayFullDate(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               CultureInfo UsaCulture = new CultureInfo("en-US");
               return d.Value.ToString("dd MMM yyyy", UsaCulture);
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }
      public static string ToDisplayFullDateTime(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               CultureInfo UsaCulture = new CultureInfo("en-US");
               return d.Value.ToString("dd MMM yyyy HH:mm:ss", UsaCulture);
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static string ToDisplayDateTime(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               CultureInfo culture = new CultureInfo("en-us");
               return d.Value.ToString("dd/MM/yyyy HH:mm:ss", culture);
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static string ToDisplayTime(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               return d.Value.ToString("HH:mm");
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static string ToDisplayTime(Nullable<System.TimeSpan> t)
      {
         try
         {
            if (t.HasValue)
            {
               var h = t.Value.Hours.ToString("00");
               var m = t.Value.Minutes.ToString("00");

               return h + ":" + m;
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static String ToLocalTime(DateTime dt)
      {
         try
         {
            return dt.ToLocalTime().ToShortTimeString();

         }
         catch (FormatException)
         {
            return dt.ToShortTimeString();
         }
      }
      public static int SubtractMonth(int smonth, int syear, int emonth, int eyear)
      {
         if (eyear > syear)
         {
            var m = (12 - smonth) + 1;
            for (var i = syear + 1; i < eyear; i++)
            {
               m += 12;
            }
            m += emonth;
            return m;
         }
         else if (eyear == syear)
         {
            if (emonth >= smonth)
            {
               return (emonth - smonth) + 1;
            }
         }

         return 0;
      }

      public static Nullable<DateTime> ToDate(string str, string indicator = "/", bool monthfirst = false)
      {
         try
         {
            if (str == null)
               return null;

            str = str.Replace("AM", "");
            str = str.Replace("PM", "");
            str = str.Trim();
            int day = 0;
            int month = 0;
            int year = 0;

            string[] indicators = { indicator };
            var datesplit = str.Split(indicators, StringSplitOptions.RemoveEmptyEntries);
            if (datesplit.Length == 3)
            {
               if (monthfirst)
               {
                  month = NumUtil.ParseInteger(datesplit[0]);
                  day = NumUtil.ParseInteger(datesplit[1]);
               }
               else
               {
                  day = NumUtil.ParseInteger(datesplit[0]);
                  month = NumUtil.ParseInteger(datesplit[1]);
               }
               year = NumUtil.ParseInteger(datesplit[2].Substring(0, 4));
            }


            if (str.Contains(":"))
            {
               int hour = 0;
               int min = 0;
               int sec = 0;
               var dsplte = str.Split(' ');
               if (dsplte.Length >= 2)
               {
                  dsplte = dsplte[1].Split(':');
                  if (dsplte.Length >= 2)
                  {
                     hour = NumUtil.ParseInteger(dsplte[0]);
                     min = NumUtil.ParseInteger(dsplte[1]);
                     if (string.IsNullOrEmpty(dsplte[0]) && string.IsNullOrEmpty(dsplte[1]))
                     {
                        str = str.Replace(":", "").Trim();
                     }
                     //var d = DateTime.ParseExact(str, "dd" + indicator + "MM" + indicator + "yyyy HH:mm", null);
                     if (year < 1500)
                        year += 543;
                     else if (year > 2500)
                        year -= 543;

                     str = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString() + " " + hour.ToString("00") + ":" + min.ToString("00");

                     return DateTime.ParseExact(str, "dd" + indicator + "MM" + indicator + "yyyy HH:mm", new CultureInfo("en-US", false));
                  }
                  else if (dsplte.Length == 3)
                  {
                     hour = NumUtil.ParseInteger(dsplte[0]);
                     min = NumUtil.ParseInteger(dsplte[1]);
                     sec = NumUtil.ParseInteger(dsplte[2]);
                     if (string.IsNullOrEmpty(dsplte[0]) && string.IsNullOrEmpty(dsplte[1]) && string.IsNullOrEmpty(dsplte[2]))
                     {
                        str = str.Replace(":", "").Trim();
                     }
                     //var d = DateTime.ParseExact(str, "dd" + indicator + "MM" + indicator + "yyyy HH:mm:ss", null);

                     if (year < 1500)
                     {
                        year += 543;
                        str = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString() + " " + hour.ToString("00") + ":" + min.ToString("00") + ":" + sec.ToString("00");
                     }
                     else if (year > 2500)
                     {
                        year -= 543;
                        str = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString() + " " + hour.ToString("00") + ":" + min.ToString("00") + ":" + sec.ToString("00");
                     }

                     return DateTime.ParseExact(str, "dd" + indicator + "MM" + indicator + "yyyy HH:mm:ss", new CultureInfo("en-US", false));
                  }

               }


            }
            else
            {
               str = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString();
               var d = DateTime.ParseExact(str, "dd" + indicator + "MM" + indicator + "yyyy", new CultureInfo("en-US", false));
               if (d.Year < 1500)
               {
                  year += 543;
                  str = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString();
               }
               else if (d.Year > 2500)
               {
                  year -= 543;
                  str = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString();
               }
               return DateTime.ParseExact(str, "dd" + indicator + "MM" + indicator + "yyyy", new CultureInfo("en-US", false));
            }
         }
         catch (Exception ex)
         {
            return null;
         }

         return null;
      }

      public static Nullable<DateTime> ToDate(int day, int month, int year, string indicator = "/")
      {
         try
         {
            if (day == 0 || month == 0 || year == 0)
            {
               return null;
            }
            var datestr = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString();
            var d = DateTime.ParseExact(datestr, "dd/MM/yyyy", new CultureInfo("en-US", false));
            if (d.Year < 1500)
            {
               year += 543;
               datestr = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString();
            }
            else if (d.Year > 2500)
            {
               year -= 543;
               datestr = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString();
            }
            return DateTime.ParseExact(datestr, "dd" + indicator + "MM" + indicator + "yyyy", new CultureInfo("en-US", false));
         }
         catch
         {
            return null;
         }
      }

      public static Nullable<DateTime> ToDate(int day, int month, int year, int hour, int minute, int second, string indicator = "/")
      {
         try
         {
            if (day == 0 || month == 0 || year == 0)
            {
               return null;
            }
            var datestr = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString();

            var timeStr = hour.ToString("00") + ":" + minute.ToString("00") + ":" + second.ToString("00");

            var d = DateTime.ParseExact(datestr, "dd/MM/yyyy", new CultureInfo("en-US", false));

            if (d.Year < 1500)
            {
               year += 543;
               datestr = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString();
            }
            else if (d.Year > 2500)
            {
               year -= 543;
               datestr = day.ToString("00") + indicator + month.ToString("00") + indicator + year.ToString();
            }
            return DateTime.ParseExact(datestr + " " + timeStr, "dd" + indicator + "MM" + indicator + "yyyy" + " HH:mm:ss", new CultureInfo("en-US", false));
         }
         catch
         {
            return null;
         }
      }

      public static Nullable<TimeSpan> ToTime(string str)
      {
         try
         {
            if (str == null)
               return null;

            str = str.Replace(":", ".");
            var spls = str.Split('.');
            if (spls.Length > 2)
               return TimeSpan.ParseExact(str, "hh'.'mm'.'ss", new CultureInfo("en-US", false));
            else
               return TimeSpan.ParseExact(str, "hh'.'mm", new CultureInfo("en-US", false));
         }
         catch
         {
            return null;
         }
      }

      public static double WorkDays(DateTime? sdate, DateTime? edate, List<int> workingDays, List<DateTime> holidays = null)
      {
         double returnDays = 0;
         if (sdate.HasValue && edate.HasValue)
         {
            var firstDay = sdate.Value;
            var lastDay = edate.Value;
            while (firstDay <= lastDay)
            {
               int firstDayOfWeek = (int)firstDay.DayOfWeek;
               if (workingDays.Contains(firstDayOfWeek))
               {
                  if (holidays != null)
                  {
                     if (!holidays.Contains(firstDay))
                        returnDays++;
                  }
                  else
                     returnDays++;
               }
               firstDay = firstDay.AddDays(1);
            }
         }
         return returnDays;
      }


      public static double WorkDays(int year, int month, List<int> workingDays, List<DateTime> holidays = null)
      {
         double returnDays = 0;

         if (ToDate(1, month, year) == null) return 0;

         var firstDay = ToDate(1, month, year).Value;
         var lastDay = ToDate(DateTime.DaysInMonth(year, month), month, year).Value;

         while (firstDay <= lastDay)
         {
            int firstDayOfWeek = (int)firstDay.DayOfWeek;
            if (workingDays.Contains(firstDayOfWeek))
            {
               if (holidays != null)
               {
                  if (!holidays.Contains(firstDay))
                     returnDays++;
               }
               else
                  returnDays++;
            }
            firstDay = firstDay.AddDays(1);
         }
         return returnDays;
      }



      public static string ToDisplayDateRange(Nullable<DateTime> sdate, string speriod, Nullable<DateTime> edate, string eperiod)
      {
         return ToDisplayDateRange(ToDisplayDate(sdate), speriod, ToDisplayDate(edate), eperiod);
      }

      public static string ToDisplayDateRange(string sdate, string speriod, string edate, string eperiod)
      {
         var str = "";
         if (!string.IsNullOrEmpty(sdate) & !string.IsNullOrEmpty(edate))
         {
            str += sdate;
            if (!string.IsNullOrEmpty(speriod))
            {
               str += " " + speriod;
            }
            str += " to ";
            if (string.IsNullOrEmpty(edate))
            {
               edate = sdate;
               eperiod = speriod;
            }

            str += edate;
            if (!string.IsNullOrEmpty(eperiod))
            {
               str += " " + eperiod;
            }
         }
         else if (!string.IsNullOrEmpty(sdate))
         {
            str += sdate;
            if (!string.IsNullOrEmpty(speriod))
            {
               str += " " + speriod;
            }
         }
         else if (!string.IsNullOrEmpty(edate))
         {
            str += edate;
            if (!string.IsNullOrEmpty(eperiod))
            {
               str += " " + eperiod;
            }
         }
         return str;
      }

      public static string ToInternalDate(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               CultureInfo UsaCulture = new CultureInfo("en-US");
               return d.Value.ToString("yyyy-MM-dd", UsaCulture);
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static string ToInternalDate3(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               return d.Value.ToString("yyyyMMdd");
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static string ToInternalDate4(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               CultureInfo UsaCulture = new CultureInfo("en-US");
               return d.Value.ToString("dd-MM-yyyy", UsaCulture);
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static string ToInternalDateTime(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               return d.Value.ToString("yyMMddHHmmss");
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }
      public static string ToInternalDate2(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               return d.Value.ToString("yyyy-MM-dd");
            }
            else
            {
               return "";
            }

         }
         catch
         {
            return "";
         }
      }

      public static string ToInternalDate(string str, string indicator = "/")
      {
         try
         {
            if (str == null)
               return null;

            int day = 0;
            int month = 0;
            int year = 0;
            var datestr = "";
            string[] indicators = { indicator };
            var datesplit = str.Split(indicators, StringSplitOptions.RemoveEmptyEntries);
            if (datesplit.Length == 3)
            {
               datestr = datesplit[0] + "/" + datesplit[1] + "/" + datesplit[2].Substring(0, 4);
               day = NumUtil.ParseInteger(datesplit[0]);
               month = NumUtil.ParseInteger(datesplit[1]);
               year = NumUtil.ParseInteger(datesplit[2].Substring(0, 4));


            }

            if (str.Contains(":"))
            {
               int hour = 0;
               int min = 0;
               int sec = 0;

               var newstr = str.Replace(datestr, "").Trim();
               var dsplte = newstr.Split(':');

               if (dsplte.Length == 2)
               {
                  hour = NumUtil.ParseInteger(dsplte[0]);
                  min = NumUtil.ParseInteger(dsplte[1]);
                  if (string.IsNullOrEmpty(dsplte[0]) && string.IsNullOrEmpty(dsplte[1]))
                  {
                     str = str.Replace(":", "").Trim();
                  }
                  //var d = DateTime.ParseExact(str, "dd" + indicator + "MM" + indicator + "yyyy HH:mm", null);
                  if (year < 1500)
                     year += 543;
                  else if (year > 2500)
                     year -= 543;

                  str = year.ToString("0000") + "-" + month.ToString("00") + "-" + day.ToString("00") + " " + hour.ToString("00") + ":" + min.ToString("00");
                  return str;
               }
               else if (dsplte.Length == 3)
               {
                  hour = NumUtil.ParseInteger(dsplte[0]);
                  min = NumUtil.ParseInteger(dsplte[1]);
                  sec = NumUtil.ParseInteger(dsplte[2]);
                  if (string.IsNullOrEmpty(dsplte[0]) && string.IsNullOrEmpty(dsplte[1]) && string.IsNullOrEmpty(dsplte[2]))
                  {
                     str = str.Replace(":", "").Trim();
                  }

                  if (year < 1500)
                     year += 543;
                  else if (year > 2500)
                     year -= 543;


                  str = year.ToString("0000") + "-" + month.ToString("00") + "-" + day.ToString("00") + " " + hour.ToString("00") + ":" + min.ToString("00") + ":" + sec.ToString("00");
                  return str;
               }
            }
            else
            {
               if (year < 1500)
                  year += 543;
               else if (year > 2500)
                  year -= 543;

               str = year.ToString("0000") + "-" + month.ToString("00") + "-" + day.ToString("00");
               return str;
            }
         }
         catch
         {
            return "";
         }

         return "";
      }

      public static int GetWeekNumber(Nullable<DateTime> d)
      {
         try
         {
            if (d.HasValue)
            {
               return CultureInfo.CurrentCulture.Calendar.GetWeekOfYear(d.Value, CalendarWeekRule.FirstFourDayWeek,
                   DayOfWeek.Sunday) - CultureInfo.CurrentCulture.Calendar.GetWeekOfYear(d.Value.AddDays(1 - d.Value.Day),
                   CalendarWeekRule.FirstFourDayWeek, DayOfWeek.Sunday) + 1;
            }
            else
            {
               return 0;
            }
         }
         catch
         {
            return 0;
         }
      }

      public static DayOfWeek GetDaysOfWeek(int no)
      {
         switch (no)
         {
            case 0:
               return DayOfWeek.Sunday;
            case 1:
               return DayOfWeek.Monday;
            case 2:
               return DayOfWeek.Tuesday;
            case 3:
               return DayOfWeek.Wednesday;
            case 4:
               return DayOfWeek.Thursday;
            case 5:
               return DayOfWeek.Friday;
            case 6:
               return DayOfWeek.Saturday;
            default:
               return DayOfWeek.Sunday;

         }
      }

        public static int GetMonth(string month)
        {
            try
            {
                switch (month)
                {
                    case "Jan":
                        return 1;
                    case "Feb":
                        return 2;
                    case "Mar":
                        return 3;
                    case "Apr":
                        return 4;
                    case "May":
                        return 5;
                    case "Jun":
                        return 5;
                    case "Jul":
                        return 7;
                    case "Aug":
                        return 8;
                    case "Sep":
                        return 9;
                    case "Oct":
                        return 10;
                    case "Nov":
                        return 11;
                    case "Dec":
                        return 12;
                    default:
                        return 0;
                }
            }
            catch
            {
                return 0;
            }
        }

    }
}
