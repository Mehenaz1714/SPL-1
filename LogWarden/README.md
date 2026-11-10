# LogWarden

### Offline Command Line-Based Log-Based Intrusion Detection System

LogWarden is an offline command-line project for parsing server logs and
identifying suspicious activity through rule-based detection.

> **Status:** Work in progress. This README documents only the features
> completed or tested so far.

## 1. Current Features

### Log parsing

-   Accepts multiple log-file paths through command-line arguments.
-   Reads files line by line using `ifstream` and `getline()`.
-   Recognizes three log categories: SSH authentication, web access, and
    outbound network/application logs.
-   Converts parsed records into a common `Event` representation.
-   Tracks total lines, successfully parsed events, event categories,
    and unrecognized lines.
-   Displays a preview of parsed events and a parsing summary.

### SSH detection rules

Two SSH rules have been implemented and tested separately.

  -----------------------------------------------------------------------
  Rule              Description       Severity          Current condition
  ----------------- ----------------- ----------------- -----------------
  R1                Repeated failed   HIGH              At least 5
                    SSH login                           failures within
                    attempts from the                   300 seconds
                    same IP                             

  R2                Successful SSH    CRITICAL          A successful
                    login after                         login follows at
                    repeated failures                   least 5 failures
                    from the same IP                    within 300
                                                        seconds
  -----------------------------------------------------------------------

R1 also uses a 300-second duplicate-suppression interval. R2 preserves
evidence containing the failed attempts and the subsequent successful
login.

## 2. Current Processing Flow

1.  Receive log-file paths through command-line arguments.
2.  Open each file.
3.  Read each file line by line.
4.  Pass each line to `parseLogLine()`.
5.  Store successfully parsed records as `Event` objects.
6.  Count events by log category.
7.  Display a limited event preview.
8.  Print the parsing summary.

**Important:** R1 and R2 have been tested using separate test programs.
The current main parsing flow does not yet automatically run these
detection rules on the parsed event collection.

## 3. Detection Rule Tests

### R1 --- Repeated Failed SSH Logins

-   Counts SSH authentication failures from the same source IP.
-   Checks whether at least 5 failures occur within a 300-second window.
-   Generates a HIGH-severity alert when the threshold is reached.
-   Suppresses repeated alerts for the same IP during the configured
    300-second suppression period.

  -----------------------------------------------------------------------
  Test                    Scenario                Observed result
  ----------------------- ----------------------- -----------------------
  A                       Two different IPs       2 alerts
                          independently reach the 
                          threshold               

  B                       Five failures are       0 alerts
                          outside the 300-second  
                          window                  

  C                       Further qualifying      1 alert
                          events occur during the 
                          suppression period      
  -----------------------------------------------------------------------

### R2 --- Successful Login After Repeated Failures

-   Looks for at least 5 failed SSH attempts from the same IP within 300
    seconds.
-   Checks whether a successful SSH login follows those failures.
-   Generates a CRITICAL-severity alert.
-   Keeps the five failed attempts and successful login as evidence.

Test performed: 5 failed attempts followed by 1 successful login.
Observed result: 1 CRITICAL alert with 6 evidence events.

## 4. Parsing Statistics

One parsing run produced this summary:

  Metric                          Result
  ---------------------------- ---------
  Log files supplied                   4
  Total lines read               142,256
  Successfully parsed events     142,234
  SSH events                         116
  Web access events              142,090
  Outbound events                     28
  Unrecognized lines                   1
  Events shown in preview             30

The three event-category counts add up to 142,234. The difference
between total lines and parsed events may include blank or skipped
lines; it should not automatically be described as entirely unrecognized
records.

## 5. Project Structure

The files discussed so far include:

``` text
LogWarden/
├── Src/
│   ├── Main.cpp
│   ├── event.h
│   ├── parser.cpp
│   ├── parser.h
│   ├── time_utils.cpp
│   ├── time_utils.h
│   ├── detection.cpp
│   └── detection.h
├── Logs/
│   └── [input log files]
└── README.md
```

The actual repository may contain additional files, including test
programs. Match directory and filename capitalization to the repository.

## 6. Build and Run

Compile the parsing program:

``` bash
g++ Src/parser.cpp Src/Main.cpp -o logwarden
```

Run it with the current sample log files:

``` bash
./logwarden \
  Logs/LBIDS_combined_access_ssh_outbound.log \
  Logs/combined_ssh_web_intrusion_log.log \
  Logs/student-access-SPL1.log \
  Logs/Synthetic_Log.log
```

Compile and run the R1 test:

``` bash
g++ Src/test_detection.cpp Src/time_utils.cpp Src/detection.cpp -o test_r1
./test_r1
```

Compile and run the R2 test:

``` bash
g++ Src/test_r2.cpp Src/time_utils.cpp Src/detection.cpp -o test_r2
./test_r2
```

These commands assume the source files are located at the paths shown.
Adjust them if the repository structure differs.

## 7. Pending Work

The following work is not claimed as completed:

-   Integrate R1 and R2 into the main parsing workflow.
-   Run detection automatically on the parsed event collection.
-   Implement and test further rules for web probing, repeated web
    errors, and unusual outbound connections.
-   Improve handling of malformed, incomplete, duplicate, and
    out-of-order records.
-   Review timestamp assumptions and edge cases, including year and
    timezone handling.
-   Expand parser and detection test coverage.
-   Measure processing time and memory usage.
-   Evaluate detection quality using true positives, false positives,
    and false negatives.

## 8. Technologies

-   C++
-   Standard C++ libraries
-   Command-line interface
-   File-based log input
-   Rule-based detection

## 9. Project Goal

LogWarden aims to provide an offline tool that processes server log
records, identifies suspicious patterns using explicit detection rules,
and presents alerts with supporting evidence.

The project is under active development. This README will be updated as
additional modules are completed and integrated.
