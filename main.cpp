/*
#
# Copyright (c) 2008 Taschek Joerg - behaveu@gmail.com
#  Program is under GPL
#
# Version 1.1a 30.09.2008 - comments are currently just in german
# 
# Description: Program reads new lines from any log file and searches for any program names 
# after error count reached it bans the user via iptables and unbans him after some time
#
# Requirements: Linux: iptables for baning the user
#  Windows: Windows baning is not implemented!
# Mac OS: dunno what with mac os todo, had no time to test it yet (my macbook is at the repair center :-(   )     
# Homepage: http://code.google.com/p/log-banner/
*/


#include <list>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/timeb.h>
#include <sys/stat.h>
#include <stdarg.h>
#include "user.h"

//#include "programs.h" // not needed because user.h includes programs.h


#ifdef __linux__
	#include <termios.h>
	#include <unistd.h>
#else
	#include <conio.h>
#endif



//verschiedene Definitionen von den LogDateien und den Jumpern
#ifdef __linux__
 #define JUMP 1
#else
 #define JUMP 2
#endif

//allgemeine Defintionen
#define VERSION "1.1a"


char* LOGFILE = NULL;
bool logging = true;
char* logger = NULL;
int LOG_LEVEL = 3; //LOG_LEVEL 0 == fast nichts, 1 == user ban/unban, 2 == user gefunden, 3 == sonstige infos == ALLES
int SLEEPS = 2500; //schau alle 2.5 sekunden nach ob die log Datei groesser geworden ist
int START_FROM_TOKEN = 3; //Bei welchem Token man anf�ngt das Syslog auszuwerten



/*
** Funktion ist f�r das Logging zust�ndig
*/
void log(int level, const char* str,...)
{
	if(logging && level <= LOG_LEVEL)
	{
		va_list ap;
		char tmp[26];
		time_t now;
		time(&now);
		sprintf(tmp,"%.24s: ",ctime(&now));
		//Datei mitloggen
		if (logger != NULL)
		{
			FILE *fp = fopen(logger,"a");
			va_start(ap, str);
			vfprintf(fp,tmp,ap);
			vfprintf(fp,str,ap);
			vfprintf(fp,"\n",ap);
			fclose(fp);
			va_end(ap);
		}
		else{
			va_start(ap, str);
			vprintf(tmp, ap);
			vprintf(str,ap);
			vprintf("\n",ap);
			fflush(stdout);
			va_end(ap);
		}
		//delete(tmp);
	}
}

/**
** Funktion ersetzt ein Leerzeichen durch ein gesch�tztes Leerzeichen zwischen Klammern um so das Tokenizer Verfahren
** nicht zu gef�hrden
*/
char* replaceSpace(char *string)
{
	if(string != NULL)
	{
		char *ret = (char*) malloc(strlen(string) * sizeof(char));
		bool opened = false;
		int x = 0;
		for(; x != strlen(string); x++)
		{
			if(!opened && (string[x] == '(' || string[x] == '[' || string[x] == '{' || string[x] == '<' || string[x] == '\'' || string[x] == '\"'))
				opened = true;
			else if(opened && (string[x] == ')' || string[x] ==  ']' || string[x] == '}' || string[x] == '>' || string[x] == '\'' || string[x] == '\"'))
				opened = false;
			if(opened && string[x] == ' ')
			{
				ret[x] = (char)255; //gesch�tztes Leerzeichen, soda� trotzdem eines angezeigt wird, aber bei der Abfrage nicht zutrifft
			}
			else
			{
				ret[x] = string[x];
			}
		}
		ret[x] = '\0';
		delete(string);
		return ret;
	}
	return string;
}


/**
**  
*/
char* removeItemsFromLine(char *line, int itemCount)
{
	if(itemCount <= 0)
		return line;
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
			result = ptr - line;
			int until = strlen(line) + 1;
			char* ret = (char*)malloc((until - result) * sizeof(char));
			strncpy(ret, line + result + 1, until - result - 2);
			ret[until - result - 2] = '\0';
			return ret;
		}
	}catch(...)
	{
		log(0, "Error fetching item: %d from line: %s", itemCount, line);

	}
	return NULL;
}


//////////////////////////////LISTEN DEFINITIONEN////////////////////////////
	std::list<User *> users;
	std::list<User *>::iterator usersIterator;
	
	std::list<Programs *> programs;
	std::list<Programs *>::iterator programsIterator;
//////////////////////////////ENDE LISTEN DEFINITIONEN//////////////////////


/**
** eigene getch Funktion welche in Linux und Windows funktioniert
*/
int __getch()
{
#ifdef __linux__
	struct termios oldt,newt;
	int ch;
	tcgetattr( STDIN_FILENO, &oldt );
	newt = oldt;
	newt.c_lflag &= ~( ICANON | ECHO );
	tcsetattr( STDIN_FILENO, TCSANOW, &newt );
	ch = getchar();
	tcsetattr( STDIN_FILENO, TCSANOW, &oldt );
	return ch;
#else
    return _getch();
#endif
}


/**
** Gibt die Dateigroesse in Linux und Windows zurueck
*/
long _fileSize(const char* file)
{
#ifdef __linux__
	struct stat buf;
	stat(file, &buf);
	return buf.st_size;
#else
	struct _stat buf;
	_stat(file, &buf);
	return buf.st_size;
#endif 
}

/**
** Sleep Funktion unter Windows und Linux
*/
void __sleep(long millis)
{
#ifdef __linux__
	usleep(millis * 1000); //usleep schlaeft mikrosekunden
#else
	_sleep(millis);
#endif
}


/**
** Funktion bannt eine IP
*/
void banip(User * user)
{
	log(1, "BAN this ass with IP: %s", user->getIp());
#ifdef __linux__
	char BAN[200];
	sprintf(BAN, "iptables -I INPUT -p tcp -s %s -j DROP", user->getIp());
	system(BAN);
	sprintf(BAN, "iptables -I INPUT -p udp -s %s -j DROP", user->getIp());
	system(BAN);
#else
	log(0, "Banning users in windows is not implemented!!");	
#endif
}

/**
** Funktion geht die Liste der Bans durch und released diese dann und setzt den Counter zurueck
*/
void releaseBans()
{
	time_t currentTime;
	time(&currentTime);

	for(usersIterator = users.begin(); usersIterator != users.end() && users.size() > 0; usersIterator++)
    {
		if((*usersIterator)->isTimeoutBan(currentTime))
		{
			log(1, "UNBAN user (%s) with IP: %s", (*usersIterator)->getName(),(*usersIterator)->getIp());
			//if((*usersIterator)->toMuchErrorAttempts()) //nur wenn �berhaupt zuoft zugegriffen wurde, kann man den unbannen
			{
				#ifdef __linux__
					char UNBAN[200];
					sprintf(UNBAN, "iptables -D INPUT -p tcp -s %s -j DROP", (*usersIterator)->getIp());
					system(UNBAN);
					sprintf(UNBAN, "iptables -D INPUT -p udp -s %s -j DROP", (*usersIterator)->getIp());
					system(UNBAN);
				#else
					log(0, "Unbanning users in windows is not implemented!!");
				#endif
			}
			(*usersIterator)->resetCnt(); //resets the cnt
			delete(*usersIterator); //delete it
			users.erase(usersIterator); //removes from list
			releaseBans(); //ruft nochmals die Funktion auf, da die iterator pointer nicht mehr passen
			return; //bricht dann diese ab
		}
	}
}

/**
** Funtktion geht die Benutzer durch und falls die IP + Programname gleich sind, gib den gleichen Benutzer zurueck
*/
User* findUserInList(char *ip, Programs* program)
{
	try{
		for(usersIterator = users.begin(); usersIterator != users.end(); usersIterator++)
		{
			if(strcmp((*usersIterator)->getIp(), ip) == 0 && strcmp((*usersIterator)->getProgName(), program->getProgramName()) == 0)
			{
				log(2, "Found user: %s with IP: %s and error cnt %d in list!", (*usersIterator)->getName(),(*usersIterator)->getIp(),(*usersIterator)->getCnt());
				return *usersIterator;
			}
		}
	}
	catch(...)
	{
	}
	return NULL;
}


/**
** Programm sieht nach ob 
*/
Programs* isRegisteredProgram(char *line)
{
	try{
		//geht alle Programme durch
		for(programsIterator = programs.begin(); programsIterator != programs.end(); programsIterator++)
	    {
			//wenn g�ltiges Program == namen + iptoken + failString
			if( (*programsIterator)->isValidProgram() && 
				memcmp((*programsIterator)->getLineStart(),line, strlen((*programsIterator)->getLineStart())) == 0 &&
				(*programsIterator)->isValidLine(line))
			{
				log(2, "Found program: %s", (*programsIterator)->getProgramName());
				return *programsIterator;
			}
			else if( (*programsIterator)->isInlineProgram() )
			{
				log(2, "Found inline program");
				return *programsIterator;
			}
		}
	}
	catch(...)
	{
		log(0, "Exception occured when finding program at line: %s", line);
	}
	return NULL;
}

/**
** Funktion liest einen Eintrag aus anderen Eintr�gen, jenachdem welche Zahl man ergibt
** Also wird der 11te Token genommen
*/
char* parseItemFromLine(char *line, int itemCount)
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

/*
** Funktion l�scht "illegale" Zeichen
*/
char* replaceIllegal(char *str, Programs* prog)
{
	if(prog->getRemoveChars() != NULL && strlen(prog->getRemoveChars()) > 0)
	{
		char *ret = (char*) malloc(strlen(str) * sizeof(char));
		int z = 0;
		for(unsigned int x = 0; x != strlen(str); x++)
		{
			bool found = false;
			for(unsigned int y = 0; y != strlen(prog->getRemoveChars()); y++)
			{
				if(str[x] == prog->getRemoveChars()[y])
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


/*
** Funktion gibt die IP Adresse zur�ck
*/
char* parseIP(char* ip)
{
	try{
		char *ret =(char*)    malloc(strlen(ip) * sizeof(char));
		int y = 0;
		for(unsigned int x = 0, points = 0; x != strlen(ip); x++)
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
		if(ret == NULL || strlen(ret) == 0)
			return NULL;
		ret[y] = '\0';
		return ret;
	}
	catch(...)
	{
	}
	return NULL;
}

/*
**
*/
char* parseUserFromLine(char *line, Programs* prog)
{
	try{
		char *name = parseItemFromLine(line, prog->getUserToken());
		if(name != NULL && strlen(name) > 0)
			name = replaceIllegal(name, prog);

		log(0, "FOUND NAME: %s", name);
		return name;
	}
	catch(...)
	{
	}
	return ""; //Leerstring == kein user gefunden
}



/*
**
*/
char* parseIPFromLine(char *line, Programs *prog)
{
	try{
		char *ip = parseItemFromLine(line, prog->getIpToken());
		if(ip != NULL && strlen(ip) > 0)
		{
			char *tmp = parseIP(ip);
			if(tmp == NULL) //wenn du NULL bist,gab es einen Fehler
				ip = replaceIllegal(ip, prog); //ersetze einfach die illegalen Zeichen
			else
				ip = tmp;
		}

		log(0,"FOUND IP: %s", ip);
		return ip;
	}
	catch(...)
	{
	}
	return NULL;
}

/**
** Funktion ersetzt String im String
*/
char *replace_str(char *str, char *orig, char *rep)
{
  static char buffer[4096];
  char *p;

  if(!(p = strstr(str, orig)))  // Is 'orig' even in 'str'?
    return str;

  strncpy(buffer, str, p-str); // Copy characters from 'str' start to 'orig' st$
  buffer[p-str] = '\0';

  sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));	
  delete(orig);
  return buffer;
}


/**
** Liefert das Programm an der jeweiligen ID zur�ck
*/
Programs* getProgram(int count)
{
	//wenn zu wenig drinnen ist, dann erh�he
	while(count > programs.size())
	{
		programs.insert(programs.end(), new Programs());
	}
	int x = 1;
	for(programsIterator = programs.begin(); programsIterator != programs.end(); programsIterator++, x++)
    {
		if(x == count)
			return *programsIterator;
	}
	return NULL;
}


/**
** Programm liest die LogDatei aus
*/
bool readConfig(char *file)
{
	try{
		FILE *f = fopen(file, "r");
		if(f == NULL)
		{
			log(0, "Error opening log file: %s", file);
			return false;
		}
		char str[500]; //500 ist die maximale zeilenlaenge
		long fileSize = _fileSize(file);
		int progCount = 1;
		//solange bis kein Dateiende erreicht ist
		while(!feof( f ) && ftell(f) < fileSize )
		{
			fscanf(f, "%[^\n]", str); //liest bis zum naechsten Linebreak == 1 Zeile aus
			//wenn nicht null und gr��er 0 und kein # am anfang ist und kein Leerzeichen
			if(str != NULL && strlen(str) > 0 && str[0] != '#' && str[0] != ' ')
			{
				char *tmp = strstr(str, "readlog=");
				if(tmp != NULL && strlen(tmp) > 8)
				{
					int len = strlen(tmp + 8);
					free(LOGFILE); //gibt die alte Logdatei frei
					LOGFILE= (char*)malloc((len + 1) * sizeof(char));
					strncpy(LOGFILE, tmp + 8, len + 1);

				}
					
				tmp = strstr(str, "startparse=");
				if(tmp != NULL && strlen(tmp) > 11)
				{
					sscanf(tmp + 11, "%d", &START_FROM_TOKEN);
					log(0, "START FROM %d", START_FROM_TOKEN);
				}
				tmp = strstr(str, "loglevel=");
				if(tmp != NULL && strlen(tmp) > 9)
				{
					sscanf(tmp + 9, "%d", &LOG_LEVEL);
					log(0, "LOG LEVEL %d", LOG_LEVEL);
				}
				tmp = strstr(str, "outputlog=");
				if(tmp != NULL && strlen(tmp) > 10)
				{
					int len = strlen(tmp + 10) + 1;
					char* _tmp = (char*)malloc(len * sizeof(char));
					strncpy(_tmp, tmp + 10,len);
					log(0, "LOG TO FILE: %s", _tmp);
					logger = _tmp;
				}
				tmp = strstr(str, "refreshms");
				if(tmp != NULL && strlen(tmp) > 10)
				{
					sscanf(tmp + 10, "%d", &SLEEPS);
					if(SLEEPS < 500)
						SLEEPS = 500;
					log(0, "REFRESH MS %d", SLEEPS);
				}

				//hier werden die Programme ausgelesen
				tmp = strstr(str, "prog_name");
				if(tmp != NULL && strlen(tmp) > 11)
				{
					int number = 1;
					sscanf(tmp + 9, "%d", &number);
					int len = strlen(tmp + 11) + 1;
					char *_tmp = (char*)malloc(len * sizeof(char));
					strncpy(_tmp, tmp + 11, len );
					Programs *prog = getProgram(number);
					log(3, "PROG %d %s", number, _tmp);
					prog->setName(_tmp);
				}
				tmp = strstr(str, "prog_start");
				if(tmp != NULL && strlen(tmp) > 12)
				{
					int number = 1;
					sscanf(tmp + 10, "%d", &number);
					int len = strlen(tmp + 12) + 1;
					char *_tmp = (char*)malloc(len * sizeof(char));
					strncpy(_tmp, tmp + 12, len );
					Programs *prog = getProgram(number);
					log(3, "START %d %s", number, _tmp);
					prog->setLineStart(_tmp);
				}
				tmp = strstr(str, "prog_fail");
				if(tmp != NULL && strlen(tmp) > 11)
				{
					int number = 1;
					sscanf(tmp + 9, "%d", &number);
					int len = strlen(tmp + 11) + 1;
					char *_tmp = (char*)malloc(len * sizeof(char));
					strncpy(_tmp, tmp + 11, len );
					Programs *prog = getProgram(number);
					log(3, "FAIL %d %s", number, _tmp);
					prog->setWatchFor(_tmp);
				}
				tmp = strstr(str, "prog_success");
				if(tmp != NULL && strlen(tmp) > 14)
				{
					int number = 1;
					sscanf(tmp + 12, "%d", &number);
					int len = strlen(tmp + 14) + 1;
					char *_tmp = (char*)malloc(len * sizeof(char));
					strncpy(_tmp, tmp + 14, len );
					Programs *prog = getProgram(number);
					log(3, "SUCCESS %d %s", number, _tmp);
					prog->setReleaseFor(_tmp);
				}
				tmp = strstr(str, "prog_userparse");
				if(tmp != NULL && strlen(tmp) > 16)
				{
					int number = 1, token = -1;
					sscanf(tmp + 14, "%d", &number);
					Programs *prog = getProgram(number);	
					sscanf(tmp + 16, "%d", &token);
					log(3, "USERPARSE %d", token);
					prog->setUserToken(token);
				}
				tmp = strstr(str, "prog_ipparse");
				if(tmp != NULL && strlen(tmp) > 14)
				{
					int number = 1, token = -1;
					sscanf(tmp + 12, "%d", &number);
					Programs *prog = getProgram(number);	
					sscanf(tmp + 14, "%d", &token);
					log(3, "IPPARSE %d", token);
					prog->setIpToken(token);
				}
				tmp = strstr(str, "prog_errorAttempt");
				if(tmp != NULL && strlen(tmp) > 19)
				{
					int number = 1, token = -1;
					sscanf(tmp + 17, "%d", &number);
					Programs *prog = getProgram(number);	
					sscanf(tmp + 19, "%d", &token);
					log(3, "ERRATEMPT %d", token);
					prog->setErrorCnt(token);
				}
				tmp = strstr(str, "prog_releaseBanSec");
				if(tmp != NULL && strlen(tmp) > 20)
				{
					int number = 1, token = -1;
					sscanf(tmp + 18, "%d", &number);
					Programs *prog = getProgram(number);	
					sscanf(tmp + 20, "%d", &token);
					log(3, "RELEASEBANSEC %d", token);
					prog->setReleaseBan(token);
				}
				tmp = strstr(str, "prog_removeSigns");
				if(tmp != NULL && strlen(tmp) > 18)
				{
					int number = 1;
					sscanf(tmp + 16, "%d", &number);
					int len = strlen(tmp + 18) + 1;
					char *_tmp = (char*)malloc(len * sizeof(char));
					strncpy(_tmp, tmp + 18, len );
					Programs *prog = getProgram(number);
					log(3, "REMOVESIGN %d %s", number, _tmp);
					prog->setReplaceString(_tmp);
				}
			}
			
			strcpy(str,"\0"); //damit die leerzeilen ignoriert werden

			fseek(f, JUMP, SEEK_CUR); //springt immer um den linebreak weiter				
		}
		return true;
	}
	catch(...)
	{
		log(0, "Exception occured while parsing log file!");
	}
	return false;
}

/**
** Einstiegspunkt == main
*/
int main(int argc, char *argv[])
{
	#ifdef __linux__
		LOGFILE = (char*)malloc(35);
		sprintf(LOGFILE,"/tmp/syslog.log");
	#else
		LOGFILE = (char*)malloc(35);
		sprintf(LOGFILE,"E:\\syslog.log");
		_tzset();
	#endif

	//wenn argc > 1 ist, dann sind parameter uebergeben worden
	if(argc > 1)
	{
		//nur wenn der erste Parameter ein Abfrageparameter ist, dann wird die Hilfe ausgegeben, ansonsten nix
		if(strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "--?") == 0 || strcmp(argv[1], "/?") == 0|| strcmp(argv[1], "--help") == 0)
		{
			printf("\n  log_banner %s (c) 2008 by Taschek Joerg (Report bugs to ICQ: 83043730)\n\n  Usage: log_banner config_file\n\n", VERSION);
			return 0;
		}
		//geht die Parameter durch
		else{
			printf("\n\tlog_banner %s (c) 2008 by Taschek Joerg\n\n", VERSION);
			for(int x = 1; x != argc; x++)
			{
				if(!readConfig(argv[x]))
					return -1;
			}
		}
	}
	else //fehler
	{
		log(0, "You need to specify a config file!");
		return -1; 
	}
	//holt einfach mal die aktuelle Uhrzeit
	time_t ltime;
	time( &ltime );
	log(0, "Startup:\t\tTime: %s", ctime( &ltime ) );
	
	log(3, "%s Size: %ld bytes", LOGFILE, _fileSize(LOGFILE));
	
	char str[500]; //500 ist die maximale zeilenlaenge
	FILE *f = fopen(LOGFILE, "r");
	if(f != NULL)
	{
		fseek(f,JUMP,SEEK_END); //springt ans Ende
		long fileSize = _fileSize(LOGFILE);
		while(true)
		{
			long tmpSize = _fileSize(LOGFILE);
			if(tmpSize != fileSize)
			{
				do
				{
					fileSize = tmpSize;
					fscanf(f, "%[^\n]", str); //liest bis zum naechsten Linebreak == 1 Zeile aus
					char* line = removeItemsFromLine(str, START_FROM_TOKEN); //removed den Zeitstempel den keiner braucht
					line = replace_str(line, "  ", " "); //replace 2 spaces with 1 space
					//sucht nach der FAIL Antwort
					Programs* prog = isRegisteredProgram(line);
					if(prog != NULL && prog->isValidLine(line)) //wenn gefunden
					{
						line = replaceSpace(line); //wandelt die Leerzeichen in Paareintr�gen (sind Eintr�ge unter ',",(,[,{) in (char)255 um soda� das Tokening funktioniert
						bool error = false;
						//todo look for auth succeded values to reset cnt value
						if(prog->isErrorOrSuccess(line, &error) && error)
						{
							log(2, "Failed login attempt: %s", line);
							char *ip = parseIPFromLine(line, prog), *name = parseUserFromLine(line, prog); //ip + name
							if(ip != NULL) //nur wenn die IP �berhaupt geparst werden konnte
							{	
								User* user = findUserInList(ip, prog); //sucht den Benutzer + Programm
								//wenn User NULL
								if(user == NULL)
								{
									user = new User(ip, name ,prog);
									users.insert(users.end(), user);
								}
								else
								{
									user->raiseCnt(); //eins erhoehen + timestamp raufsetzen
									log(2, "Raise user error count(%d): %s[%s]", user->getCnt(), user->getIp(), user->getName());
									//wenn er die error attempts �berschritten hat (tztz) dann wird er gebannt
									if(user->toMuchErrorAttempts())
									{
										banip(user); //ban this ass
									}
								}
							}
						}
						else
							log(0, "Not able to parse IP from: %s with program: %s", str, prog->getProgramName());
					}
					fseek(f, JUMP, SEEK_CUR); //springt immer um den linebreak weiter				
				}while(!feof( f ) && ftell(f) < fileSize ); //nur solange bis file ende oder eben die position groesser als die datei ist
			}
			__sleep(SLEEPS); //schlafen
			releaseBans(); //released bans wenn diese lang genug inaktiv waren
		}
		fclose(f);
	}
	else
	{
		log(0, "Could not open %s!\nAborting...",LOGFILE);
		return 1;
	}
	return 0;
}