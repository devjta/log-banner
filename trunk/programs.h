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
	char *userStart;
	int ipToken;
	char *ipStart;
	int errorAttempt;
	int releaseBanSec;
	char *removeChars;
	bool isAnyItemInLine(char *item, char *line);
public:

	Programs();
	~Programs();
	bool isValidProgram();
	bool isInlineProgram();
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
	void setUserTokenTxt(char *tokenTxt);
	void setIpToken(int token);
	void setIpTokenTxt(char *tokenTxt);
	void setErrorCnt(int error);
	void setReleaseBan(int secs);
	void setReplaceString(char *signs);
	int getIpToken();
	char *getIpTokenTxt();
	int getUserToken();
	char *getUserTokenTxt();
	bool isValidLine(char *line);
	bool isErrorOrSuccess(char *line, bool *error);
};

