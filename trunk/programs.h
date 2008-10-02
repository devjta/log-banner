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
	int errorAttempt;
	int releaseBanSec;
	char *removeChars;
public:

	Programs();
	~Programs();
	bool isValidProgram();
	int getReleaseSec();
	int getMaxErrorCnt();
	char* getProgramName();
	char* getLineStart();
	char* getErrorText();
	char* getSuccessText();
	char* getRemoveChars();
	void setName(char *name);
	void setLineStart(char *line);
	void setWatchFor(char *errorLine);
	void setReleaseFor(char *successLine);
	void setUserToken(int token);
	void setIpToken(int token);
	void setErrorCnt(int error);
	void setReleaseBan(int secs);
	void setReplaceString(char *signs);
	int getIpToken();
	int getUserToken();
	bool isValidLine(char *line);
	bool isErrorOrSuccess(char *line, bool *error);
};

