/*
#
# Copyright (c) 2008 Taschek Joerg - behaveu@gmail.com
#  Program is under GPL
#
*/

#include <string.h>
#include <malloc.h>
#include "programs.h"

//damit er weiß das es diese Funktion auch gibt
extern void log(int level, const char* str,...);

Programs::Programs()
{
	errorAttempt = 3;
	releaseBanSec = 60 * 10; // == 10 Minuten
	lineStart = NULL;
	removeChars = NULL;
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



bool Programs::isProgram(char *line)
{
	if(progName == NULL || strlen(progName) == 0)
		return false;

	return false;
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

//
char** Programs::parseIPandUser(char *line)
{
	
	char *ip = parseItemFromLine(line, ipToken);
	if(ip != NULL && strlen(ip) > 0)
	{
		char *tmp = parseIP(ip);
		if(tmp == NULL) //wenn du NULL bist,gab es einen Fehler
			ip = replaceIllegal(ip); //ersetze einfach die illegalen Zeichen
		else
			ip = tmp;
	}

	log(0,"FOUND IP: %s", ip);
	char *name = parseItemFromLine(line, userToken);
	if(name != NULL && strlen(name) > 0)
		name = replaceIllegal(name);
	
	log(0, "FOUND NAME: %s", name);
	char **ret = (char**)malloc(2);
	ret[0] = ip;
	ret[1] = name;
	return ret;
}

// Funktion gibt die IP Adresse zurück
char* Programs::parseIP(char* ip)
{
	try{
		char *ret =(char*)    malloc(strlen(ip) * sizeof(char));
		for(unsigned int x = 0, y =0, points = 0; x != strlen(ip); x++)
		{
			if(ip[x] >= '0' && ip[x] <= '9') 
			{
				ret[y] = ip[x];
				y++;
			}
			else if(ip[x] == '.')
			{
				points++;
				ret[y] = '.';
				y++;
			}
			else if(points >= 3) //wenn es schon mehr als 3 Punkte sind und keine Zahl mehr, dann bist du keine Zahl mehr und Abbruch
			{
				break;
			}

		}
		ret[y] = '\0';
		return ret;
	}
	catch(...)
	{
	}
	return NULL;
}

//
char* Programs::replaceIllegal(char *str)
{
	if(removeChars != NULL && strlen(removeChars) > 0)
	{
		char *ret = (char*) malloc(strlen(str) * sizeof(char));
		int z = 0;
		for(unsigned int x = 0; x != strlen(str); x++)
		{
			bool found = false;
			for(unsigned int y = 0; y != strlen(removeChars); y++)
			{
				if(str[x] == removeChars[y])
				{
					found = true;
					break;
				}
			}
			if(!found)
			{
				ret[z] = str[x];
				z++;
			}
		}
		ret[z] = '\0';
		return ret;
	}
	return str;
}

/**
** Funktion liest einen Eintrag aus anderen Einträgen, jenachdem welche Zahl man ergibt
** Also wird der 11te Token genommen
*/
char* Programs::parseItemFromLine(char *line, int itemCount)
{
	try{
		if(line != NULL)
		{
			char *ptr = strchr(line,' ');
			int result = ptr - line + 1;
			int	x = 0;
			while(x < itemCount)
			{
				ptr = strchr(line + result,' ');
				result = ptr - line + 1;
				x++;
			}
			result = ptr - line + 1;
			ptr = strchr(line + result, ' ');
			int until = ptr - line + 1;
			if(ptr == NULL)
				until = strlen(line) + 1;
			char* ret = (char*)malloc(until - result  * sizeof(char));
			strncpy(ret, line + result, until - result - 1);
			ret[until - result - 1] = '\0';
			return ret;
		}
	}catch(...)
	{
		log(0, "Error fetching item: %d from line: %s", itemCount, line);

	}
	return NULL;
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
