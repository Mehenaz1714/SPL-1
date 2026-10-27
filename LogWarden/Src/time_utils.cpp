#include "time_utils.h"

// Convert a single digit character into an integer.
int digitValue(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }

    return -1;
}

// Read an integer from a specified position.
bool readNumber(const string &text, int start, int count, int &value)
{
    value = 0;

    if (start < 0 || count <= 0)
    {
        return false;
    }

    if (start + count > (int)text.length())
    {
        return false;
    }

    for (int i = start; i < start + count; i++)
    {
        int digit = digitValue(text[i]);

        if (digit == -1)
        {
            return false;
        }

        value = value * 10 + digit;
    }

    return true;
}

// Convert an English month abbreviation into a month number.
int monthNumber(const string &month)
{
    if (month == "Jan")
        return 1;
    if (month == "Feb")
        return 2;
    if (month == "Mar")
        return 3;
    if (month == "Apr")
        return 4;
    if (month == "May")
        return 5;
    if (month == "Jun")
        return 6;
    if (month == "Jul")
        return 7;
    if (month == "Aug")
        return 8;
    if (month == "Sep")
        return 9;
    if (month == "Oct")
        return 10;
    if (month == "Nov")
        return 11;
    if (month == "Dec")
        return 12;

    return -1;
}

// Check whether a year is a leap year.
bool isLeapYear(int year)
{
    if (year % 400 == 0)
    {
        return true;
    }

    if (year % 100 == 0)
    {
        return false;
    }

    return year % 4 == 0;
}

// Return the number of days in a month.
int daysInMonth(int month, int year)
{
    if (month == 2)
    {
        return isLeapYear(year) ? 29 : 28;
    }

    if (month == 4 || month == 6 ||
        month == 9 || month == 11)
    {
        return 30;
    }

    if (month >= 1 && month <= 12)
    {
        return 31;
    }

    return 0;
}

// Convert a calendar date into the number of days
// since 1 January 1970.
long long daysSinceEpoch(int year, int month, int day)
{
    long long totalDays = 0;

    for (int y = 1970; y < year; y++)
    {
        totalDays += isLeapYear(y) ? 366 : 365;
    }

    for (int m = 1; m < month; m++)
    {
        totalDays += daysInMonth(m, year);
    }

    totalDays += day - 1;

    return totalDays;
}

// Parse the timestamp into separate fields.
bool parseTimestamp(const string &timestamp, bool isSSH,
                    TimestampParts &result)
{
    result.year = 2026;
    result.month = 0;
    result.day = 0;
    result.hour = 0;
    result.minute = 0;
    result.second = 0;
    result.timezoneOffsetMinutes = 360;
    result.hasYear = !isSSH;

    if (isSSH)
    {
        // Expected format: Sep 19 01:44:25
        if (timestamp.length() < 15)
        {
            return false;
        }

        string monthText = timestamp.substr(0, 3);
        result.month = monthNumber(monthText);

        if (result.month == -1)
        {
            return false;
        }

        int dayStart = 4;

        // SSH syslog timestamps may have a space before
        // a single-digit day, e.g. "Sep  9 01:44:25".
        if (timestamp[4] == ' ')
        {
            dayStart = 5;
        }

        if (!readNumber(timestamp, dayStart, 2, result.day))
        {
            // Retry with a one-digit day.
            if (!readNumber(timestamp, dayStart + 1, 1, result.day))
            {
                return false;
            }
        }

        int timeStart = dayStart + 3;

        if (timeStart + 7 > (int)timestamp.length())
        {
            return false;
        }

        if (timestamp[timeStart + 2] != ':' ||
            timestamp[timeStart + 5] != ':')
        {
            return false;
        }

        if (!readNumber(timestamp, timeStart, 2, result.hour) ||
            !readNumber(timestamp, timeStart + 3, 2, result.minute) ||
            !readNumber(timestamp, timeStart + 6, 2, result.second))
        {
            return false;
        }
    }
    else
    {
        // Expected formats:
        // Web:      16/Sep/2026:00:03:34 +0600
        // Outbound: 20/Sep/2026:02:05:00 +0600

        if (timestamp.length() < 20)
        {
            return false;
        }

        if (!readNumber(timestamp, 0, 2, result.day))
        {
            return false;
        }

        if (timestamp[2] != '/')
        {
            return false;
        }

        result.month = monthNumber(timestamp.substr(3, 3));

        if (result.month == -1 || timestamp[6] != '/')
        {
            return false;
        }

        if (!readNumber(timestamp, 7, 4, result.year))
        {
            return false;
        }

        if (timestamp[11] != ':')
        {
            return false;
        }

        if (!readNumber(timestamp, 12, 2, result.hour) ||
            !readNumber(timestamp, 15, 2, result.minute) ||
            !readNumber(timestamp, 18, 2, result.second))
        {
            return false;
        }

        if (timestamp[14] != ':' || timestamp[17] != ':')
        {
            return false;
        }

        // Read the timezone offset, e.g. +0600 or -0500.
        int zoneStart = 20;

        while (zoneStart < (int)timestamp.length() &&
               timestamp[zoneStart] == ' ')
        {
            zoneStart++;
        }

        if (zoneStart + 5 <= (int)timestamp.length() &&
            (timestamp[zoneStart] == '+' ||
             timestamp[zoneStart] == '-'))
        {
            int zoneHour;
            int zoneMinute;

            if (!readNumber(timestamp, zoneStart + 1, 2, zoneHour) ||
                !readNumber(timestamp, zoneStart + 3, 2, zoneMinute))
            {
                return false;
            }

            if (zoneHour > 23 || zoneMinute > 59)
            {
                return false;
            }

            int offset = zoneHour * 60 + zoneMinute;

            if (timestamp[zoneStart] == '-')
            {
                offset = -offset;
            }

            result.timezoneOffsetMinutes = offset;
        }
    }

    // Validate the parsed date and time.
    if (result.year < 1970 ||
        result.month < 1 || result.month > 12 ||
        result.day < 1 ||
        result.day > daysInMonth(result.month, result.year) ||
        result.hour < 0 || result.hour > 23 ||
        result.minute < 0 || result.minute > 59 ||
        result.second < 0 || result.second > 59)
    {
        return false;
    }

    return true;
}

// Convert the parsed timestamp into UTC seconds.
long long timestampToSeconds(const TimestampParts &timestamp)
{
    long long totalSeconds =
        daysSinceEpoch(timestamp.year, timestamp.month, timestamp.day) * 86400LL;

    totalSeconds += timestamp.hour * 3600LL;
    totalSeconds += timestamp.minute * 60LL;
    totalSeconds += timestamp.second;

    // Local time to UTC:
    // UTC = local time - timezone offset.
    totalSeconds -=
        (long long)timestamp.timezoneOffsetMinutes * 60LL;

    return totalSeconds;
}

// Return the absolute time difference in seconds.
long long timeDifference(long long first, long long second)
{
    if (first >= second)
    {
        return first - second;
    }

    return second - first;
}