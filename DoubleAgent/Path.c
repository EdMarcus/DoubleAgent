/* Includes ******************************************************************/
#include <Windows.h>
#include <Shlwapi.h>
#include "Status.h"
#include "Path.h"

/* Public Function Definitions ***********************************************/
DOUBLEAGENT_STATUS PATH_GetDirectory(IN PCWSTR pcwszFilePath, OUT PWSTR *ppwszDirPath)
{
	DOUBLEAGENT_STATUS eStatus = DOUBLEAGENT_STATUS_INVALID_VALUE;
	PWSTR pwszDirPathLocal = NULL;
	SIZE_T nFilePathLenInBytes = 0;

	/* Validates the parameters */
	if ((NULL == pcwszFilePath) || (NULL == ppwszDirPath))
	{
		DOUBLEAGENT_SET(eStatus, DOUBLEAGENT_STATUS_DOUBLEAGENT_PATH_GETDIRECTORY_INVALID_PARAMS);
		goto lbl_cleanup;
	}

	/* Gets the file path length in bytes */
	nFilePathLenInBytes = (wcslen(pcwszFilePath) + 1) * sizeof(*pcwszFilePath);

	/* Allocates the directory path */
	pwszDirPathLocal = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nFilePathLenInBytes);
	if (NULL == pwszDirPathLocal)
	{
		DOUBLEAGENT_SET(eStatus, DOUBLEAGENT_STATUS_DOUBLEAGENT_PATH_GETDIRECTORY_HEAPALLOC_FAILED);
		goto lbl_cleanup;
	}

	/* Copies the file path to the directory path */
	CopyMemory(pwszDirPathLocal, pcwszFilePath, nFilePathLenInBytes);

	/* Creates the directory path by removing the file name */
	if (FALSE == PathRemoveFileSpecW(pwszDirPathLocal))
	{
		DOUBLEAGENT_SET(eStatus, DOUBLEAGENT_STATUS_DOUBLEAGENT_PATH_GETDIRECTORY_PATHREMOVEFILESPECW_FAILED);
		goto lbl_cleanup;
	}

	/* Sets the received parameters */
	*ppwszDirPath = pwszDirPathLocal;
	pwszDirPathLocal = NULL;

	/* Succeeded */
	DOUBLEAGENT_SET(eStatus, DOUBLEAGENT_STATUS_SUCCESS);

lbl_cleanup:
	/* Frees the directory path */
	if (NULL != pwszDirPathLocal)
	{
		(VOID)HeapFree(GetProcessHeap(), 0, pwszDirPathLocal);
		pwszDirPathLocal = NULL;
	}

	/* Returns status */
	return eStatus;
}
