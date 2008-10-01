/*
#
# Copyright (c) 2008 Taschek Joerg - behaveu@gmail.com
#  Program is under GPL
#
*/


#include <time.h>
#include "programs.h"

class User
{
private:
	char *ip;
	time_t lastResponse;
	char *name;
	int failLogin;
	Programs *program;
public:

	User(char *_ip, char *_name, Programs* _program);
	~User();
	void printTime();
	char* getIp();
	char *getName();
	char *getProgName();
	int getCnt();
	void raiseCnt();
	void resetCnt();
	bool isTimeoutBan(time_t time);
	//new functions
	bool toMuchErrorAttempts();
};

