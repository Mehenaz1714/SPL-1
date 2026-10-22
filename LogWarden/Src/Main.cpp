
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "event.h"
#include "parser.h"

using namespace std;

int main(int argc, char *argv[])
{
    vector<string> fileNames;

    // Read file names from command-line arguments
    for (int i = 1; i < argc; i++)
    {
        fileNames.push_back(argv[i]);
    }

    if (fileNames.empty())
    {
        cout << "Usage: ./a.out <file1> <file2> ..." << endl;
        return 1;
    }

    // Parsing statistics
    int totalLines = 0;
    int parsedLines = 0;
    int sshCount = 0;
    int webCount = 0;
    int outboundCount = 0;
    int unknownCount = 0;
    int displayedEvents = 0;

    const int MAX_DISPLAY = 30;

    // Process every input file
    for (int i = 0; i < (int)fileNames.size(); i++)
    {
        ifstream file(fileNames[i]);

        if (!file)
        {
            cout << "Cannot open: " << fileNames[i] << endl;
            continue;
        }

        cout << "\nParsing: " << fileNames[i] << endl;

        string line;

        while (getline(file, line))
        {
            totalLines++;

            Event event;

            if (parseLogLine(line, event))
            {
                parsedLines++;

                // Count event types
                if (event.type == SSH)
                    sshCount++;
                else if (event.type == WEB)
                    webCount++;
                else if (event.type == OUTBOUND)
                    outboundCount++;
                else
                    unknownCount++;

                // Display the first 30 parsed events
                if (displayedEvents < MAX_DISPLAY)
                {
                    displayedEvents++;

                    cout << "\n========== Parsed Event "
                         << displayedEvents
                         << " ==========" << endl;

                    // Event type
                    cout << "Type: ";

                    if (event.type == SSH)
                        cout << "SSH";
                    else if (event.type == WEB)
                        cout << "WEB";
                    else if (event.type == OUTBOUND)
                        cout << "OUTBOUND";
                    else
                        cout << "UNKNOWN";

                    // Common event fields
                    cout << "\nTimestamp: " << event.timestamp;
                    cout << "\nSource IP: " << event.sourceIP;
                    cout << "\nUsername: " << event.username;
                    cout << "\nMethod: " << event.method;
                    cout << "\nTarget: " << event.target;
                    cout << "\nStatus: " << event.status;
                    cout << "\nPort: " << event.port;

                    // SSH authentication result
                    cout << "\nAuthentication result: ";

                    if (event.authResult == AUTH_FAILED)
                        cout << "FAILED";
                    else if (event.authResult == AUTH_SUCCESS)
                        cout << "SUCCESS";
                    else
                        cout << "UNKNOWN";

                    // Web / outbound response size
                    cout << "\nResponse size: "
                         << event.responseSize;

                    // Original log line
                    cout << "\nRaw log: " << event.rawLog << endl;
                }
            }
            else if (!line.empty() && line[0] != '#')
            {
                unknownCount++;
            }
        }

        file.close();
    }

    // Final parsing summary
    cout << "\n\n========== PARSING SUMMARY ==========" << endl;

    cout << "Total files provided: "
         << fileNames.size() << endl;

    cout << "Total lines read: "
         << totalLines << endl;

    cout << "Successfully parsed: "
         << parsedLines << endl;

    cout << "SSH events: "
         << sshCount << endl;

    cout << "Web events: "
         << webCount << endl;

    cout << "Outbound events: "
         << outboundCount << endl;

    cout << "Unrecognized lines: "
         << unknownCount << endl;

    cout << "Events displayed: "
         << displayedEvents << endl;

    return 0;
}
