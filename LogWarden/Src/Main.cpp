
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

int main(int argc, char *argv[])
{
    string fileName;

    // If file name is given while running the program
    if (argc >= 2)
    {
        fileName = argv[1];
    }
    else
    {
        // Otherwise, ask the user for the file name
        cout << "Enter log file path: ";
        getline(cin, fileName);
    }

    ifstream file(fileName);

    if (!file)
    {
        cout << "Cannot open log file: " << fileName << endl;
        return 1;
    }

    cout << "Log file opened successfully." << endl;
    cout << "File: " << fileName << endl;
    cout << endl;

    string line;
    int lineCount = 0;

    while (getline(file, line))
    {
        cout << line << endl;

        lineCount++;

        if (lineCount == 10)
        {
            break;
        }
    }

    file.close();

    cout << endl;
    cout << "Lines read: " << lineCount << endl;

    return 0;
}