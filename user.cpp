/*
#
# Copyright (c) 2008 Taschek Joerg - behaveu@gmail.com
#  Program is under GPL
#
*/


#include "user.h"

//damit der weiß, das es diese Funktion auch gibt
extern void log(int level, const char* str,...);

User::User(char *_ip, char *_name, char* _prog)
{
	failLogin = 1; //da der Benutzer nur beim Falsch anmelden angelegt wird
	ip = _ip;
	name = _name;
	progName = _prog;
	log(2, "New Fail user registered: %s IP: %s for program: %s", name, ip, progName);
	time(&lastResponse);
}

User::~User()
{
	//log(3, "Desktruktor at: %s %s", ip, name);
	if(name != NULL)
		delete(name);	
	if(ip != NULL)
		delete(ip);
	if(progName != NULL)
		delete(progName);
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

char* User::getProgName()
{
	return progName;
}

/** 
** Funktion gibt true zurueck wenn der 
*/
bool User::isTimeoutBan(time_t time, long between)
{
	//log(0, "Current stamp: %ld\nMine stamp %ld\nBetween: %ld == %ld", time, lastResponse, between, time - lastResponse);
	return time - lastResponse > between;
}
