/*
#
# Copyright (c) 2008 Taschek Joerg - behaveu@gmail.com
#  Program is under GPL
#
# Version 1.0a 30.09.2008 - comments are currently just in german
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
#include <time.h>
#include <sys/types.h>
#include <sys/timeb.h>
#include <sys/stat.h>
#include <stdarg.h>

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
#define VERSION "1.0a"


static char* LOGFILE = NULL;
static bool logging = true;
static char* logger = NULL;
static int LOG_LEVEL = 3; //LOG_LEVEL 0 == fast nichts, 1 == user ban/unban, 2 == user gefunden, 3 == sonstige infos == ALLES
static int SLEEPS = 2500; //schau alle 2.5 sekunden nach ob die log Datei groesser geworden ist
static int ERROR_ATTEMPTS = 3; //3 falsche Loginversuche
static int RELEASE_BANS_SEC = 60  * 10; // == 10 Minuten, 
static int START_FROM_TOKEN = 3; //Bei welchem Token man anfängt das Syslog auszuwerten


/*
** Funktion ist für das Logging zuständig
*/
void log(int level, const char* str,...)
{
	if(logging && level <= LOG_LEVEL)
	{
		va_list ap;
		char *tmp = (char*) malloc(25 * sizeof(char));
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
** Funktion liest einen Eintrag aus anderen Einträgen, jenachdem welche Zahl man ergibt
** zB sieht so ein Eintrag aus Sat Sep 13 19:26:29 2008 [pid 5057] [Administrator] FAIL LOGIN: Client "200.68.66.93"
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
			char* ret = (char*)malloc(until - result - 2 * sizeof(char));
			strncpy(ret, line + result + 1, until - result - 3);
			ret[until - result - 3] = '\0';
			return ret;
		}
	}catch(...)
	{
		log(0, "Error fetching item: %d from line: %s", itemCount, line);

	}
	return NULL;
}


/*
** Klasse speichert die Programme + 
*/
class Program
{
private:
	char *progName;
	char *lineStart;
	char *watchFor;
	char *releaseFor;
	int userToken;
	int ipToken;
public:

	Program()
	{

	}

	~Program()
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
};


/*
** Klasse speichert den Benutzernamen + IP ab (Name ist nur fuer die Ausgabe)
*/
class User
{
private:
	char *ip;
	time_t lastResponse;
	char *name;
	int failLogin;
	char *progName;
public:

	User(char *_ip, char *_name, char* _prog)
	{
		failLogin = 1; //da der Benutzer nur beim Falsch anmelden angelegt wird
		ip = _ip;
		name = _name;
		progName = _prog;
		log(2, "New Fail user registered: %s IP: %s for program: %s", name, ip, progName);
		time(&lastResponse);
	}

	~User()
	{
		//log(3, "Desktruktor at: %s %s", ip, name);
		if(name != NULL)
			delete(name);	
		if(ip != NULL)
			delete(ip);
		if(progName != NULL)
			delete(progName);
	}


	void printTime()
	{
		log(3,"Last response:%s", ctime( &lastResponse ) );
	}

	char* getIp()
	{
		return ip;
	}

	char * getName()
	{
		return name;
	}

	int getCnt()
	{
		return failLogin;
	}

	void raiseCnt()
	{
		failLogin++;
		time(&lastResponse);
	}

	void resetCnt()
	{
		failLogin = 0;
		time(&lastResponse);
	}

	char * getProgName()
	{
		return progName;
	}

	/** 
	** Funktion gibt true zurueck wenn der 
	*/
	bool isTimeoutBan(time_t time, long between)
	{
		//log(0, "Current stamp: %ld\nMine stamp %ld\nBetween: %ld == %ld", time, lastResponse, between, time - lastResponse);
		return time - lastResponse > between;
	}
};


//////////////////////////////LISTEN DEFINITIONEN////////////////////////////
	std::list<User *> users;
	std::list<User *>::iterator usersIterator;
	
	std::list<Program *> programs;
	std::list<Program *>::iterator programsIterator;
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
#else
	log(0, "Banning users in windows is not implemented!!");	
#endif
}

/**
** Funtion geht die Liste der Bans durch und released diese dann und setzt den Counter zurueck
*/
void releaseBans()
{
	time_t currentTime;
	time(&currentTime);

	for(usersIterator = users.begin(); usersIterator != users.end() && users.size() > 0; usersIterator++)
    {
		if((*usersIterator)->isTimeoutBan(currentTime, RELEASE_BANS_SEC))
		{
			log(1, "UNBAN user (%s) with IP: %s", (*usersIterator)->getName(),(*usersIterator)->getIp());
			#ifdef __linux__
				char UNBAN[200];
				sprintf(UNBAN, "iptables -D INPUT -p tcp -s %s -j DROP", (*usersIterator)->getIp());
				system(UNBAN);
			#else
				log(0, "Unbanning users in windows is not implemented!!");
			#endif

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
User* findUserInList(char *ip, char* progName)
{
	for(usersIterator = users.begin(); usersIterator != users.end(); usersIterator++)
    {
		if(strcmp((*usersIterator)->getIp(), ip) == 0 && strcmp((*usersIterator)->getProgName(), progName) == 0)
		{
			log(2, "Found user: %s with IP: %s and error cnt %d in list!", (*usersIterator)->getName(),(*usersIterator)->getIp(),(*usersIterator)->getCnt());
			return *usersIterator;
		}
	}
	return NULL;
}


/**
** Programm sieht nach ob 
*/
bool isRegisteredProgram(char *line)
{
	try{
		//geht alle Programme durch
		for(programsIterator = programs.begin(); programsIterator != programs.end(); programsIterator++)
	    {
			
		}
	}
	catch(...)
	{

	}
	return false;
}


/**
** Programm liest die 
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
		//solange bis kein Dateiende erreicht ist
		while(!feof( f ) && ftell(f) < fileSize )
		{
			fscanf(f, "%[^\n]", str); //liest bis zum naechsten Linebreak == 1 Zeile aus
			

			fseek(f, JUMP, SEEK_CUR); //springt immer um den linebreak weiter				
		}
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
			printf("\n  log_banner %s (c) 2008 by Taschek Joerg (Report bugs to ICQ: 83043730)\n\n  Usage: log_banner config_file", VERSION);
			return 0;
		}
		//geht die Parameter durch
		else{
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
	log(0, "Startup:\t\t\t%s", ctime( &ltime ) );
	
	log(3, "%s %ld", LOGFILE, _fileSize(LOGFILE));
	
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
					//sucht nach der FAIL Antwort
					if(isRegisteredProgram(str)) //wenn gefunden
					{
						log(2, "Failed login attempt: %s", str);
						User* user = findUserInList("192.168.101.129","asf");
						//wenn User NULL
						if(user == NULL)
						{
							user = new User("192.168.101.129","blub","asf");
							users.insert(users.end(), user);
						}
						else
						{
							user->raiseCnt(); //eins erhoehen + timestamp raufsetzen
							log(2, "Raise user error count(%d): %s[%s]", user->getCnt(), user->getIp(), user->getName());
							//wenn er die error attempts überschritten hat (tztz) dann wird er gebannt
							if(user->getCnt() >= ERROR_ATTEMPTS)
							{
								banip(user); //ban this ass
							}
						}
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
