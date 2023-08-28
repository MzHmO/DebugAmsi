#pragma once
#include <Windows.h>
#include <iostream>
#include <locale>
#include "strhide.h"
#include <sstream>
#include <iomanip>
#define DEBUG

std::string GetWinapiErrorDescription(DWORD errorCode);