#ifndef DETECTION_H
#define DETECTION_H

#include <string>
#include <vector>
#include "event.h"

using namespace std;

struct Alert
{
    string ruleID;
    string ruleName;
    string severity;
    string sourceIP;

    string firstEventTime;
    string lastEventTime;

    string reason;
    int eventCount;

    vector<string> evidence;
};

vector<Alert> detectSSHBruteForce(
    const vector<Event>& events,
    int threshold = 5,
    long long windowSeconds = 300,
    long long suppressionSeconds = 300
);

vector<Alert> detectSuccessfulLoginAfterFailures(
    const vector<Event>& events,
    int threshold = 5,
    long long windowSeconds = 300,
    long long suppressionSeconds = 300
);

#endif
