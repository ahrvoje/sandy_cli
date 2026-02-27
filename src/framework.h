// framework.h : include file for standard system include files
//

#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <cstdio>

// Additional headers for Sandy
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cwchar>
#include <userenv.h>
#include <sddl.h>
#include <aclapi.h>

#pragma comment(lib, "userenv.lib")
