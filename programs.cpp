/*
#
# Copyright (c) 2008 Taschek Joerg - behaveu@gmail.com
#  Program is under GPL
#
*/

#include <string.h>
#include <malloc.h>
#include "programs.h"

//damit er weiﬂ das es diese Funktion auch gibt
extern void log(int level, const char* str,...);

Programs::Programs()
{
	errorAttempt = 3;
	releaseBanSec = 60 * 10; // == 10 Minuten
	lineStart = NULL;
	removeChars = NULL;
	ipToken = -1;
	userToken = -1;
	watchFor = NULL;
	releaseFor = NULL;
}



Programs::~Programs()
{
	if(progName != NULL)
		delete(progName);
	if(lineStart != NULL)
		delete(lineStart);
	if(watchFor != NULL)
		delete(watchFor);
	if(releaseFor != NULL)
		delete(releaseFor);
	if(removeChars != NULL)
		delete(removeChars);
}



bool Programs::isValidProgram()
{
	if(progName == NULL || strlen(progName) == 0 || ipToken == -1 || watchFor == NULL || strlen(watchFor) == 0)
		return false;
	return true;
}


int Programs::getReleaseSec()
{
	return releaseBanSec; 

}

int Programs::getMaxErrorCnt()
{
	return errorAttempt;
}

char* Programs::getProgramName()
{
	return progName;
}

char* Programs::getLineStart()
{
	if(lineStart == NULL || strlen(lineStart) == 0)
		return getProgramName();
	return lineStart;
}


void Programs::setName(char *name)
{
	progName = name;
}
void Programs::setLineStart(char *line)
{
	lineStart = line;
}
void Programs::setWatchFor(char *errorLine)
{
	watchFor = errorLine;
}

void Programs::setReleaseFor(char *successLine)
{
	releaseFor = successLine;
}
	
void Programs::setUserToken(int token)
{
	userToken = token;
}

void Programs::setIpToken(int token)
{
	ipToken = token;
}

void Programs::setErrorCnt(int error)
{
	errorAttempt = error;
}

void Programs::setReleaseBan(int secs)
{
	releaseBanSec = secs;
}

void Programs::setReplaceString(char *signs)
{
	removeChars = signs;
}

char* Programs::getRemoveChars()
{
	return removeChars;
}


char* Programs::getErrorText()
{
	return watchFor;
}

char* Programs::getSuccessText()
{
	return releaseFor; 
}

int Programs::getIpToken()
{
	return ipToken;
}

int Programs::getUserToken()
{
	return userToken;
}

bool Programs::isValidLine(char *line)
{
	try{
		if(line == NULL)
			return false;
		if(!isValidProgram())
			return false;
		if(strstr(line, watchFor))
			return true;
		if(releaseFor == NULL)
			return false;
		if(strstr(line, releaseFor))
			return true;
	}
	catch(...)
	{}
	return false;
}


bool Programs::isErrorOrSuccess(char *line, bool *error)
{
	if(isValidLine(line))
	{
		try{
			if(strstr(line, watchFor))
				*error = true;
			else 
			{
				if(releaseFor == NULL)
					return false;
				if(strstr(line, releaseFor))
					*error = false;
			}
			return true;
		}catch(...)
		{}
	}
	return false;
}


