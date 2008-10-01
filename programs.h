/*
#
# Copyright (c) 2008 Taschek Joerg - behaveu@gmail.com
#  Program is under GPL
#
*/


class Programs
{
private:
	char* progName;
	char* lineStart;
	char* watchFor;
	char* releaseFor;
	int userToken;
	int ipToken;
public:

	Programs();
	~Programs();
	bool isProgram(char *line);
};
