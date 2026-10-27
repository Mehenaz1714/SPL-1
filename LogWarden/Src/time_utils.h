#ifndef TIME_UTILS_H
#define TIME_UTILS_H

#include <string>

using namespace std;

struct TimestampParts
{
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    int timezoneOffsetMinutes;
    bool hasYear;
};

bool parseTimestamp(const string &timestamp, bool isSSH,
                    TimestampParts &result);

long long timestampToSeconds(const TimestampParts &timestamp);

long long timeDifference(long long first, long long second);

#endif