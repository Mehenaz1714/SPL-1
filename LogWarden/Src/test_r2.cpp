#include <iostream>
#include <vector>
#include "detection.h"

using namespace std;

Event makeSSHEvent(
    const string &ip,
    const string &timestamp,
    AuthResult result)
{
    Event event;

    event.type = SSH;
    event.authResult = result;
    event.sourceIP = ip;
    event.username = "root";
    event.timestamp = timestamp;

    if (result == AUTH_FAILED)
    {
        event.rawLog = timestamp + " Failed password for root from " + ip;
    }
    else
    {
        event.rawLog = timestamp + " Accepted password for root from " + ip;
    }

    return event;
}

void printAlerts(const vector<Alert> &alerts)
{
    cout << "Alerts generated: " << alerts.size() << endl;

    for (int i = 0; i < (int)alerts.size(); i++)
    {
        cout << "\nAlert " << i + 1 << endl;
        cout << "Rule ID: " << alerts[i].ruleID << endl;
        cout << "Rule Name: " << alerts[i].ruleName << endl;
        cout << "Severity: " << alerts[i].severity << endl;
        cout << "Source IP: " << alerts[i].sourceIP << endl;
        cout << "Failed login count: " << alerts[i].eventCount << endl;
        cout << "First event: " << alerts[i].firstEventTime << endl;
        cout << "Successful login: " << alerts[i].lastEventTime << endl;
        cout << "Evidence count: " << alerts[i].evidence.size() << endl;
    }
}

int main()
{
    vector<Event> events;

    // Five failed logins from the same IP.
    events.push_back(makeSSHEvent(
        "192.0.2.10", "Sep 19 01:00:00", AUTH_FAILED));

    events.push_back(makeSSHEvent(
        "192.0.2.10", "Sep 19 01:00:20", AUTH_FAILED));

    events.push_back(makeSSHEvent(
        "192.0.2.10", "Sep 19 01:00:40", AUTH_FAILED));

    events.push_back(makeSSHEvent(
        "192.0.2.10", "Sep 19 01:01:00", AUTH_FAILED));

    events.push_back(makeSSHEvent(
        "192.0.2.10", "Sep 19 01:01:20", AUTH_FAILED));

    // A successful login from the same IP.
    events.push_back(makeSSHEvent(
        "192.0.2.10", "Sep 19 01:01:40", AUTH_SUCCESS));

    cout << "Total test events: " << events.size() << endl;

    vector<Alert> alerts =
        detectSuccessfulLoginAfterFailures(events);

    printAlerts(alerts);

    return 0;
}
