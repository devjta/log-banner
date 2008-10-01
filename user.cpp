/*
#
# Copyright (c) 2008 Taschek Joerg - behaveu@gmail.com
#  Program is under GPL
#
*/


#include "user.h"

//damit der weiß, das es diese Funktion auch gibt
extern void log(int level, const char* str,...);

User::User(char *_ip, char *_name, Programs* _program)
{
	failLogin = 1; //da der Benutzer nur beim Falsch anmelden angelegt wird
	ip = _ip;
	name = _name;
	program = _program;
	log(2, "New Fail user registered: %s IP: %s for program: %s", name, ip, program->getProgramName());
	time(&lastResponse);
}

User::~User()
{
	//log(3, "Desktruktor at: %s %s", ip, name);
	if(name != NULL)
		delete(name);	
	if(ip != NULL)
		delete(ip);
	//if(program != NULL)
	//	delete(program); //bad idea because the same programs are used in the programs list
}


void User::printTime()
{
	log(3,"Last response:%s", ctime( &lastResponse ) );
}

char* User::getIp()
{
	return ip;
}

char* User::getName()
{
	return name;
}

int User::getCnt()
{
	return failLogin;
}

void User::raiseCnt()
{
	failLogin++;
	time(&lastResponse);
}

void User::resetCnt()
{
	failLogin = 0;
	time(&lastResponse);
}


/** 
** Funktion gibt true zurueck wenn der 
*/
bool User::isTimeoutBan(time_t time)
{
	//log(0, "Current stamp: %ld\nMine stamp %ld\nBetween: %ld == %ld", time, lastResponse, between, time - lastResponse);
	if(program == NULL)
	{
		log(0, "Program has been deleted!! So release user!! ERROR!! User: %s %s", ip,name);
		return true;
	}
	return time - lastResponse > program->getReleaseSec();
}


bool User::toMuchErrorAttempts()
{
	if(program == NULL)
	{
		log(0, "Program has been deleted!! So error attempt is false!! ERROR!! User: %s %s", ip,name);
		return false;
	}
	return getCnt() >= program->getMaxErrorCnt();
}

char* User::getProgName()
{
	if(program == NULL)
	{
		log(0, "Program has been deleted!! So program name is NULL!! ERROR!! User: %s %s", ip, name);
		return NULL;
	}
	return program->getProgramName();
}

