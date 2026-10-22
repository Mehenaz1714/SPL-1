
#include "parser.h"

#include <sstream>
using namespace std;

bool parseLogLine(const string &line, Event &event)
{
    event = Event();
    event.rawLog = line;

    // Ignore empty lines and comments
    if (line.empty() || line[0] == '#')
        return false;

    // =====================================
    // 1. SSH LOG
    // =====================================
    if (line.find("sshd[") != string::npos)
    {
        event.type = SSH;

        istringstream input(line);
        string month, day, time;

        if (!(input >> month >> day >> time))
            return false;

        event.timestamp = month + " " + day + " " + time;

        // Extract authentication result
        if (line.find("Failed password") != string::npos ||
            line.find("authentication failure") != string::npos ||
            line.find("Invalid user ") != string::npos)
        {
            event.authResult = AUTH_FAILED;
        }
        else if (line.find("Accepted password") != string::npos ||
                 line.find("Accepted publickey") != string::npos)
        {
            event.authResult = AUTH_SUCCESS;
        }

        // Extract username
        size_t userPos = line.find(" for ");

        if (userPos != string::npos)
        {
            size_t userStart = userPos + 5;

            if (line.compare(userStart, 12, "invalid user") == 0)
            {
                userStart += 13;
            }

            size_t userEnd = line.find(' ', userStart);

            if (userEnd != string::npos)
            {
                event.username =
                    line.substr(userStart, userEnd - userStart);
            }
        }
        else
        {
            // Handle: Invalid user backup from ...
            size_t invalidPos = line.find("Invalid user ");

            if (invalidPos != string::npos)
            {
                size_t userStart = invalidPos + 13;
                size_t userEnd = line.find(' ', userStart);

                if (userEnd != string::npos)
                {
                    event.username =
                        line.substr(userStart, userEnd - userStart);
                }
            }
        }

        // Extract source IP after " from "
        size_t fromPos = line.find(" from ");

        if (fromPos != string::npos)
        {
            size_t ipStart = fromPos + 6;
            size_t ipEnd = line.find(' ', ipStart);

            if (ipEnd != string::npos)
            {
                event.sourceIP =
                    line.substr(ipStart, ipEnd - ipStart);
            }
        }

        // Extract port
        size_t portPos = line.find(" port ");

        if (portPos != string::npos)
        {
            istringstream portInput(line.substr(portPos + 6));
            string portText;

            if (portInput >> portText)
            {
                try
                {
                    event.port = stoi(portText);
                }
                catch (...)
                {
                    event.port = -1;
                }
            }
        }

        return true;
    }

    // =====================================
    // 2. WEB LOG (Apache combined format)
    // =====================================
    size_t bracketStart = line.find('[');
    size_t bracketEnd = line.find(']');
    size_t quoteStart = line.find('"');

    if (bracketStart != string::npos &&
        bracketEnd != string::npos &&
        quoteStart != string::npos &&
        bracketStart < bracketEnd &&
        bracketEnd < quoteStart)
    {
        istringstream input(line);
        string dash1, dash2;

        event.type = WEB;

        if (!(input >> event.sourceIP))
        {
            event.type = UNKNOWN;
            return false;
        }

        event.timestamp = line.substr(
            bracketStart + 1,
            bracketEnd - bracketStart - 1);

        size_t quoteEnd = line.find('"', quoteStart + 1);

        if (quoteEnd == string::npos)
        {
            event.type = UNKNOWN;
            return false;
        }

        string request = line.substr(
            quoteStart + 1,
            quoteEnd - quoteStart - 1);

        istringstream requestInput(request);
        string protocol;

        if (!(requestInput >> event.method >> event.target >> protocol))
        {
            event.type = UNKNOWN;
            return false;
        }

        istringstream remaining(line.substr(quoteEnd + 1));

        string sizeText;

        if (!(remaining >> event.status >> sizeText))
        {
            event.status = -1;
            event.responseSize = -1;
        }
        else
        {
            try
            {
                event.responseSize = stoll(sizeText);
            }
            catch (...)
            {
                event.responseSize = -1;
            }
        }

        return true;
    }

    // =====================================
    // 3. OUTBOUND LOG
    // =====================================
    {
        istringstream input(line);

        string datePart, timezone;
        string sizeText;

        if (input >> datePart >> timezone >> event.sourceIP >> event.method >> event.target)
        {
            if (datePart.find('/') != string::npos &&
                datePart.find(':') != string::npos &&
                event.target.find("://") != string::npos)
            {
                event.type = OUTBOUND;
                event.timestamp = datePart + " " + timezone;

                if (!(input >> event.status >> sizeText))
                {
                    event.status = -1;
                    event.responseSize = -1;
                }
                else
                {
                    try
                    {
                        event.responseSize = stoll(sizeText);
                    }
                    catch (...)
                    {
                        event.responseSize = -1;
                    }
                }

                return true;
            }
        }
    }

    // Unrecognized format
    event.type = UNKNOWN;
    return false;
}
