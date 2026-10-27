#include "detection.h"
#include "time_utils.h"

#include <iostream>

using namespace std;

// Check whether two IP addresses are equal.
bool sameIP(const string &ip1, const string &ip2)
{
    return ip1 == ip2;
}

// Check whether an event is a failed SSH login.
bool isFailedSSH(const Event &event)
{
    return event.type == SSH &&
           event.authResult == AUTH_FAILED &&
           !event.sourceIP.empty();
}

// Calculate the absolute difference between two timestamps.
long long absoluteDifference(long long a, long long b)
{
    if (a >= b)
    {
        return a - b;
    }

    return b - a;
}

// Detect SSH brute-force activity.
vector<Alert> detectSSHBruteForce(
    const vector<Event> &events,
    int threshold,
    long long windowSeconds,
    long long suppressionSeconds)
{
    vector<Alert> alerts;

    int totalEvents = (int)events.size();

    // Store the converted timestamp of every event.
    vector<long long> eventTimes(totalEvents, 0);

    // Record which events have valid timestamps.
    vector<bool> validTime(totalEvents, false);

    // Step 1: Convert SSH timestamps into seconds.
    for (int i = 0; i < totalEvents; i++)
    {
        if (events[i].type != SSH)
        {
            continue;
        }

        TimestampParts parts;

        if (parseTimestamp(events[i].timestamp, true, parts))
        {
            eventTimes[i] = timestampToSeconds(parts);
            validTime[i] = true;
        }
    }

    // Store candidate event indices.
    vector<int> candidates;

    // Step 2: Find events that reach the threshold.
    for (int i = 0; i < totalEvents; i++)
    {
        if (!isFailedSSH(events[i]) || !validTime[i])
        {
            continue;
        }

        long long currentTime = eventTimes[i];
        int failureCount = 0;

        // Count failures from the same IP within
        // the trailing time window.
        for (int j = 0; j < totalEvents; j++)
        {
            if (!isFailedSSH(events[j]) || !validTime[j])
            {
                continue;
            }

            if (!sameIP(events[i].sourceIP, events[j].sourceIP))
            {
                continue;
            }

            long long otherTime = eventTimes[j];

            if (otherTime <= currentTime &&
                currentTime - otherTime <= windowSeconds)
            {
                failureCount++;
            }
        }

        if (failureCount >= threshold)
        {
            candidates.push_back(i);
        }
    }

    // Step 3: Sort candidate indices by timestamp.
    // Implemented manually; no std::sort().
    for (int i = 0; i < (int)candidates.size() - 1; i++)
    {
        int earliest = i;

        for (int j = i + 1; j < (int)candidates.size(); j++)
        {
            if (eventTimes[candidates[j]] <
                eventTimes[candidates[earliest]])
            {
                earliest = j;
            }
        }

        if (earliest != i)
        {
            int temp = candidates[i];
            candidates[i] = candidates[earliest];
            candidates[earliest] = temp;
        }
    }

    // Step 4: Create alerts and suppress duplicates.
    vector<long long> alertTimes;

    for (int c = 0; c < (int)candidates.size(); c++)
    {
        int anchorIndex = candidates[c];

        long long currentTime = eventTimes[anchorIndex];

        bool duplicate = false;

        for (int a = 0; a < (int)alerts.size(); a++)
        {
            if (sameIP(
                    alerts[a].sourceIP,
                    events[anchorIndex].sourceIP))
            {
                long long difference =
                    absoluteDifference(currentTime, alertTimes[a]);

                if (difference <= suppressionSeconds)
                {
                    duplicate = true;
                    break;
                }
            }
        }

        if (duplicate)
        {
            continue;
        }

        Alert alert;

        alert.ruleID = "R1";
        alert.ruleName = "SSH Brute-Force";
        alert.severity = "HIGH";
        alert.sourceIP = events[anchorIndex].sourceIP;
        alert.lastEventTime = events[anchorIndex].timestamp;
        alert.firstEventTime = events[anchorIndex].timestamp;
        alert.reason =
            "Repeated failed SSH login attempts from the same IP "
            "within the configured time window.";

        alert.eventCount = 0;

        long long earliestTime = currentTime;

        // Collect evidence from the triggering window.
        for (int j = 0; j < totalEvents; j++)
        {
            if (!isFailedSSH(events[j]) || !validTime[j])
            {
                continue;
            }

            if (!sameIP(
                    events[j].sourceIP,
                    events[anchorIndex].sourceIP))
            {
                continue;
            }

            long long eventTime = eventTimes[j];

            if (eventTime <= currentTime &&
                currentTime - eventTime <= windowSeconds)
            {
                alert.eventCount++;

                if (eventTime < earliestTime)
                {
                    earliestTime = eventTime;
                    alert.firstEventTime = events[j].timestamp;
                }

                alert.evidence.push_back(events[j].rawLog);
            }
        }

        alerts.push_back(alert);
        alertTimes.push_back(currentTime);
    }

    return alerts;
}
// Check whether an event is a successful SSH login.
bool isSuccessfulSSH(const Event &event)
{
    return event.type == SSH &&
           event.authResult == AUTH_SUCCESS &&
           !event.sourceIP.empty();
}

// Detect a successful SSH login after repeated failures.
vector<Alert> detectSuccessfulLoginAfterFailures(
    const vector<Event> &events,
    int threshold,
    long long windowSeconds,
    long long suppressionSeconds)
{
    vector<Alert> alerts;

    int totalEvents = (int)events.size();

    // Store the converted timestamp of every event.
    vector<long long> eventTimes(totalEvents, 0);

    // Record which events have valid timestamps.
    vector<bool> validTime(totalEvents, false);

    // Step 1: Convert SSH timestamps into seconds.
    for (int i = 0; i < totalEvents; i++)
    {
        if (events[i].type != SSH)
        {
            continue;
        }

        TimestampParts parts;

        if (parseTimestamp(events[i].timestamp, true, parts))
        {
            eventTimes[i] = timestampToSeconds(parts);
            validTime[i] = true;
        }
    }

    // Step 2: Find successful logins that meet the rule.
    vector<int> candidates;

    for (int i = 0; i < totalEvents; i++)
    {
        if (!isSuccessfulSSH(events[i]) || !validTime[i])
        {
            continue;
        }

        long long successTime = eventTimes[i];
        int failureCount = 0;

        // Count failures from the same IP that occurred
        // before this successful login within the window.
        for (int j = 0; j < totalEvents; j++)
        {
            if (!isFailedSSH(events[j]) || !validTime[j])
            {
                continue;
            }

            if (!sameIP(events[i].sourceIP, events[j].sourceIP))
            {
                continue;
            }

            long long failureTime = eventTimes[j];

            if (failureTime <= successTime &&
                successTime - failureTime <= windowSeconds)
            {
                failureCount++;
            }
        }

        if (failureCount >= threshold)
        {
            candidates.push_back(i);
        }
    }

    // Step 3: Sort qualifying successful logins by time.
    // Manual selection sort; no std::sort().
    for (int i = 0; i < (int)candidates.size() - 1; i++)
    {
        int earliest = i;

        for (int j = i + 1; j < (int)candidates.size(); j++)
        {
            if (eventTimes[candidates[j]] <
                eventTimes[candidates[earliest]])
            {
                earliest = j;
            }
        }

        if (earliest != i)
        {
            int temp = candidates[i];
            candidates[i] = candidates[earliest];
            candidates[earliest] = temp;
        }
    }

    // Step 4: Generate alerts and suppress duplicates.
    vector<long long> alertTimes;

    for (int c = 0; c < (int)candidates.size(); c++)
    {
        int successIndex = candidates[c];
        long long successTime = eventTimes[successIndex];

        bool duplicate = false;

        for (int a = 0; a < (int)alerts.size(); a++)
        {
            if (sameIP(
                    alerts[a].sourceIP,
                    events[successIndex].sourceIP))
            {
                long long difference =
                    absoluteDifference(successTime, alertTimes[a]);

                if (difference <= suppressionSeconds)
                {
                    duplicate = true;
                    break;
                }
            }
        }

        if (duplicate)
        {
            continue;
        }

        Alert alert;

        alert.ruleID = "R2";
        alert.ruleName = "Successful Login After Repeated Failures";
        alert.severity = "CRITICAL";
        alert.sourceIP = events[successIndex].sourceIP;

        alert.firstEventTime = events[successIndex].timestamp;
        alert.lastEventTime = events[successIndex].timestamp;

        alert.reason =
            "A successful SSH login occurred after repeated failed "
            "login attempts from the same IP within the configured "
            "time window.";

        alert.eventCount = 0;

        long long earliestFailureTime = successTime;

        // Step 5: Collect failed-login evidence.
        for (int j = 0; j < totalEvents; j++)
        {
            if (!isFailedSSH(events[j]) || !validTime[j])
            {
                continue;
            }

            if (!sameIP(
                    events[j].sourceIP,
                    events[successIndex].sourceIP))
            {
                continue;
            }

            long long failureTime = eventTimes[j];

            if (failureTime <= successTime &&
                successTime - failureTime <= windowSeconds)
            {
                alert.eventCount++;

                if (failureTime < earliestFailureTime)
                {
                    earliestFailureTime = failureTime;
                    alert.firstEventTime = events[j].timestamp;
                }

                alert.evidence.push_back(events[j].rawLog);
            }
        }

        // Add the successful login as the final evidence item.
        alert.evidence.push_back(events[successIndex].rawLog);

        alert.lastEventTime = events[successIndex].timestamp;

        alerts.push_back(alert);
        alertTimes.push_back(successTime);
    }

    return alerts;
}
