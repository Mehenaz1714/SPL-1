#include <iostream>
#include "time_utils.h"

using namespace std;

int main()
{
    TimestampParts sshTime;
    TimestampParts webTime;
    TimestampParts outboundTime;

    string sshTimestamp = "Sep 19 01:44:25";
    string webTimestamp = "16/Sep/2026:00:03:34 +0600";
    string outboundTimestamp = "20/Sep/2026:02:05:00 +0600";

    cout << "Testing SSH timestamp..." << endl;

    if (parseTimestamp(sshTimestamp, true, sshTime))
    {
        cout << "SSH timestamp parsed successfully." << endl;
        cout << "Year: " << sshTime.year << endl;
        cout << "Month: " << sshTime.month << endl;
        cout << "Day: " << sshTime.day << endl;
    }
    else
    {
        cout << "SSH timestamp parsing failed." << endl;
    }

    cout << "\nTesting Web timestamp..." << endl;

    if (parseTimestamp(webTimestamp, false, webTime))
    {
        cout << "Web timestamp parsed successfully." << endl;
        cout << "Year: " << webTime.year << endl;
        cout << "Month: " << webTime.month << endl;
        cout << "Day: " << webTime.day << endl;
    }
    else
    {
        cout << "Web timestamp parsing failed." << endl;
    }

    cout << "\nTesting Outbound timestamp..." << endl;

    if (parseTimestamp(outboundTimestamp, false, outboundTime))
    {
        cout << "Outbound timestamp parsed successfully." << endl;
        cout << "Year: " << outboundTime.year << endl;
        cout << "Month: " << outboundTime.month << endl;
        cout << "Day: " << outboundTime.day << endl;
    }
    else
    {
        cout << "Outbound timestamp parsing failed." << endl;
    }

    if (parseTimestamp(sshTimestamp, true, sshTime) &&
        parseTimestamp(webTimestamp, false, webTime))
    {
        long long sshSeconds = timestampToSeconds(sshTime);
        long long webSeconds = timestampToSeconds(webTime);

        cout << "\nSSH time in seconds: " << sshSeconds << endl;
        cout << "Web time in seconds: " << webSeconds << endl;

        cout << "Time difference: "
             << timeDifference(sshSeconds, webSeconds)
             << " seconds" << endl;
    }

    return 0;
}
