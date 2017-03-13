#pragma once

/* Includes ******************************************************************/
#include <Windows.h>
#include "Status.h"

/* Function Declarations *****************************************************/
/*
 * Receives a file path and returns its directory path
 * The directory path must be freed via HeapFree
 */
DOUBLEAGENT_STATUS PATH_GetDirectory(IN PCWSTR pcwszFilePath, OUT PWSTR *ppwszDirPath);
