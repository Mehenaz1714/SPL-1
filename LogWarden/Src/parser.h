
#ifndef PARSER_H
#define PARSER_H

#include <string>
#include "event.h"

bool parseLogLine(const std::string &line, Event &event);

#endif
