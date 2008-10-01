/*
#
# Copyright (c) 2008 Taschek Joerg - behaveu@gmail.com
#  Program is under GPL
#
*/


#include <time.h>

class User
{
private:
	char *ip;
	time_t lastResponse;
	char *name;
	int failLogin;
	char *progName;
public:

	User(char *_ip, char *_name, char* _prog);
	~User();
	void printTime();
	char* getIp();
	char * getName();
	int getCnt();
	void raiseCnt();
	void resetCnt();
	char * getProgName();
	bool isTimeoutBan(time_t time, long between);
};
