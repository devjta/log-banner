/*
#
# Copyright (c) 2008 Taschek Joerg - behaveu@gmail.com
#  Program is under GPL
#
*/

#include <stddef.h>

#include "programs.h"

//damit er weiﬂ das es diese Funktion auch gibt
extern void log(int level, const char* str,...);

Programs::Programs()
{


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
}



bool Programs::isProgram(char *line)
{
	

	return false;
}
