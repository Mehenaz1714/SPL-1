#include <iostream>
#include "event.h"
#include "detection.h"

using namespace std;

Event makeFailedEvent(const string &ip, const string &timestamp)
{
    Event event;

    event.type = SSH;
    event.authResult = AUTH_FAILED;
    event.sourceIP = ip;
    event.username = "root";
    event.timestamp = timestamp;
    event.rawLog = "Test failed SSH login";

    return event;
}

void printResult(const string &testName, vector<Event> &events)
{
    vector<Alert> alerts = detectSSHBruteForce(events);

    cout << "\n========== " << testName << " ==========" << endl;
    cout << "Input events: " << events.size() << endl;
    cout << "Alerts generated: " << alerts.size() << endl;

    for (int i = 0; i < (int)alerts.size(); i++)
    {
        cout << "Alert " << i + 1
             << ": IP = " << alerts[i].sourceIP
             << ", failures = " << alerts[i].eventCount
             << ", severity = " << alerts[i].severity
             << endl;
    }
}

int main()
{
    // TEST A: Two IP addresses.
    vector<Event> testA;

    testA.push_back(makeFailedEvent(
        "198.51.100.200", "Sep 19 01:44:25"));
    testA.push_back(makeFailedEvent(
        "198.51.100.200", "Sep 19 01:44:30"));
    testA.push_back(makeFailedEvent(
        "198.51.100.200", "Sep 19 01:44:35"));
    testA.push_back(makeFailedEvent(
        "198.51.100.200", "Sep 19 01:44:40"));
    testA.push_back(makeFailedEvent(
        "198.51.100.200", "Sep 19 01:44:45"));

    testA.push_back(makeFailedEvent(
        "192.0.2.222", "Sep 19 02:15:00"));
    testA.push_back(makeFailedEvent(
        "192.0.2.222", "Sep 19 02:15:05"));
    testA.push_back(makeFailedEvent(
        "192.0.2.222", "Sep 19 02:15:10"));
    testA.push_back(makeFailedEvent(
        "192.0.2.222", "Sep 19 02:15:15"));
    testA.push_back(makeFailedEvent(
        "192.0.2.222", "Sep 19 02:15:20"));

    printResult("TEST A: Separate IPs", testA);

    // TEST B: Failures spread outside the 5-minute window.
    vector<Event> testB;

    testB.push_back(makeFailedEvent(
        "203.0.113.10", "Sep 19 01:44:00"));
    testB.push_back(makeFailedEvent(
        "203.0.113.10", "Sep 19 01:44:30"));
    testB.push_back(makeFailedEvent(
        "203.0.113.10", "Sep 19 01:45:00"));
    testB.push_back(makeFailedEvent(
        "203.0.113.10", "Sep 19 01:45:30"));
    testB.push_back(makeFailedEvent(
        "203.0.113.10", "Sep 19 01:50:00"));

    printResult("TEST B: Outside time window", testB);

    // TEST C: Seven failures close together.
    vector<Event> testC;

    testC.push_back(makeFailedEvent(
        "203.0.113.50", "Sep 19 03:00:00"));
    testC.push_back(makeFailedEvent(
        "203.0.113.50", "Sep 19 03:00:05"));
    testC.push_back(makeFailedEvent(
        "203.0.113.50", "Sep 19 03:00:10"));
    testC.push_back(makeFailedEvent(
        "203.0.113.50", "Sep 19 03:00:15"));
    testC.push_back(makeFailedEvent(
        "203.0.113.50", "Sep 19 03:00:20"));
    testC.push_back(makeFailedEvent(
        "203.0.113.50", "Sep 19 03:00:25"));
    testC.push_back(makeFailedEvent(
        "203.0.113.50", "Sep 19 03:00:30"));

    printResult("TEST C: Duplicate suppression", testC);

    return 0;
}