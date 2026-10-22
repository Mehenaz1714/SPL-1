
#ifndef EVENT_H
#define EVENT_H

#include <string>

using namespace std;

enum LogType
{
    SSH,
    WEB,
    OUTBOUND,
    UNKNOWN
};

enum AuthResult
{
    AUTH_UNKNOWN,
    AUTH_FAILED,
    AUTH_SUCCESS
};

struct Event
{
    LogType type;
    AuthResult authResult;

    string timestamp;
    string sourceIP;

    string username;
    string method;
    string target;

    int status;
    int port;
    long long responseSize;

    string rawLog;

    Event()
    {
        type = UNKNOWN;
        authResult = AUTH_UNKNOWN;

        status = -1;
        port = -1;
        responseSize = -1;
    }
};

#endif
