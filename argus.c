#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<signal.h>
#define  no_usb "# this rule does not allow any new usb devices, use script to disable\nACTION==\"add\", DRIVERS==\"usb\",  ATTR{authorized}=\"0\"\n"
#define fname "/etc/udev/rules.d/11-to_rule_all.rules"
#define wait 20           // wait time for temporary unblock

 
void failure(char* pattern, int* f);
int kmp(char* t, char* p);
 
int* init_array(int size) 
{
  int* arr = (int*)malloc(size * sizeof(int));
  int i;
  for(i = 0; i < size; i++) 
  {
    arr[i] = 0;
  }
 
  return arr;
}
 
int match(char* text, char* pattern) 
{              //pattern is what to search and text is whole line.
   
  int match = kmp(text, pattern);
 
  if (match>0)
  {
    return 1;
  }
  else
  {
    return 0;
  }
}
 
int kmp(char* t, char* p) 
{
  int m = strlen(p);
  int n = strlen(t);
 
  int* f = init_array(m); // Failure function values.
  int i = 0;
  int j = 0;
 
  while (i < n) 
  {
    if (t[i] == p[j]) 
    {
      if (j == m - 1) 
      {
        return i - j;
      }
      else 
      {
        i += 1;
        j += 1;
      }
    }
    else 
    {
      if (j > 0) 
      {
        j = f[j-1];
      }
      else 
      {
        i += 1;
      }
    }
  }
 
  return -1;
}
 
void failure(char* p, int* f) 
{
  f[0] = 0;
  int i = 1;
  int j = 0;
 
  int m = strlen(p);
 
  while (i < m) {
    if (p[i] == p[j]) 
    {
      f[i] = j + 1; // j+1 matches up to the current character.
      i += 1;
      j += 1;
    }
    else if (j > 0) 
    {
      j = f[j - 1];
    }
    else 
    {
      f[i] = 0;
      i += 1;
    }
  }
}
 
int secode()
{
    printf("\nSecure Code Analyzer is an automated code security review tool that handles C and PHP. It has a few features that should hopefully \nmake it useful to anyone conducting code security reviews, particularly where time is at a premium:");
    printf("\n\n\t\t\t\tNOTE\n\n1. Please note that your code file should either be saved in .PHP or .C type.");
    printf("\n2. Your code file should be saved in same directory as this code file.");
    printf("\n3. Your code file should be named as code.c or code.php.");
    printf("\n4. This file will scan for various vulnerabilities that are compiled from various sources.\n\n");
    char* str[255];
    char ch;
    int choice;
    int i=0,j,index;
    FILE *co;                       //for fetching chars
    //FILE *sr;
    //const char EOL = "/0";
    printf("What file type you want to scan for analysis?\n1.C\n2.PHP\n");
    scanf("%d",&choice);
    if (choice == 1)
    {
        co = fopen("code.c","r");  //code file
        if (co == NULL)
        {
            perror("Error opening file");
            return(-1);/* code */                           
        }
    }
    else
    {
        co = fopen("code.php","r");  //code file
        if (co == NULL)
        {
            perror("Error opening file");
            return(-1);/* code */
        }
    }
    
     
    while(!feof(co))
    {
        if( fgets (str, 255, co)!=NULL ) 
        {
      /* writing content to stdout */
      //puts(str);
     
        //if(word1 == "String" || word1 == "Query" || word1 == "1'='1" )
        //{
        //  printf("\n");
        //  printf("Your file contains SQL injection vulnerability and may pose threat in later stages of testing, fex fixes can be done by implementing few fixes.");
        //}
        if(match(str,"gets()")==1)
        {
            printf("\ngets(): It is vulnerable to BufferOverflow error as in the input, if it recives the input as a pointer, then it couldn't estimate the size of it.\n");
        }
        else if (match(str,"query") || match(str,"1'='1"))
        {
            printf("\nYour file contains SQL injection vulnerability and may pose threat in later stages of testing, fex fixes can be done by implementing few fixes.\n");
        }
        else if(match(str,"preg_replace")==1)
        {
            printf("\npreg_replace() [function.preg-replace]: Compilation failed: unmatched parentheses at offset 3 is a common error in cas eof preg_replace.\n");
        }
        else if(match(str,"sprintf()")==1)
        {
            printf("\nprintf and its sister function sprintf are considered unsafe due to the amount of undefined behaviour they emit if used incorrectly.\n\nVisual Studio is disabling these functions by default.\n\nBut, since they are part of the C++ standard library, you can use them. But Visual Studio will only allow you to do that if you include the line\n\n#define _CRT_SECURE_NO_WARNINGS\nbefore the relevant standard library headers are included.\n\nAlternatively, include _CRT_SECURE_NO_WARNINGS in your project preprocessor settings\n\n");
        }
        else if(match(str,"strcpy()")==1 || match(str,"strcpy")==1 || match(str,"strcpy(")==1)
        {
            printf("\nstrcpy() : Your code might have some vulnerablities and this can better be healed by replacing this function by strncpy().\n");
        }
        else if(match(str,"vsprintf()")==1)
        {
            printf("\nsprintf :  It is considered unsafe due to the amount of undefined behaviour they emit if used incorrectly.\n\nVisual Studio is disabling these functions by default.\n\nBut, since they are part of the C++ standard library, you can use them. But Visual Studio will only allow you to do that if you include the line\n\n#define _CRT_SECURE_NO_WARNINGS\nbefore the relevant standard library headers are included.\n\nAlternatively, include _CRT_SECURE_NO_WARNINGS in your project preprocessor settings\n\n");
        }
        else if(match(str,"strcpyA")==1)
        {
            printf("\nstrcpyA : This function appears in Microsoft's banned function list. This can proove vulnerab in some case. Can facilitate buffer overflow conditions.\n");
        }
        else if(match(str,"strcpyW")==1)
        {
            printf("\nstrcpyW function appears in Microsoft's banned function list. Can facilitate buffer overflow conditions.\n");
        }
        else if(match(str,"StrCpyNA")==1)
        {
            printf("\nStrCpyNA function appears in Microsoft's banned function list. Can facilitate buffer overflow conditions.\n");
        }
        else if(match(str,"StrCpyNW")==1)
        {
            printf("\nStrCpyNW function appears in Microsoft's banned function list. Can facilitate buffer overflow conditions.\n");
        }
        else if(match(str,"StrNCpyA")==1)
        {
            printf("\nStrNCpyA function appears in Microsoft's banned function list. Can facilitate buffer overflow conditions.\n");
        }
        else if(match(str,"StrNCpyW")==1)
        {
            printf("\nStrNCpyW function appears in Microsoft's banned function list. Can facilitate buffer overflow conditions\n");
        }
        else if(match(str,"StrNCpy")==1)
        {
            printf("\nStrNCpyFunction appears in Microsoft's banned function list. Can facilitate buffer overflow conditions.\n");
        }
        else if(match(str,"strcpynA")==1)
        {
            printf("\nstrcpynA appears in Microsoft's banned function list. Can facilitate buffer overflow conditions.\n");
        }
        else if(match(str,"strcpyn")==1)
        {
            printf("\nstrcpyn function appears in Microsoft's banned function list. Can facilitate buffer overflow conditions.\n");
        }
        else if(match(str,"strcpyn(")==1)
        {
            printf("\nstrcpyn() function appears in Microsoft's banned function list. Can facilitate buffer overflow conditions.\n");
        }
    }
}
}
 
char key[10]={'C','Y','B','E','R','L','A','W'};
int encrypt()
{
	int ch1,ch2;
	int i=0,k;
	int temp;
	int flag;
	FILE *fp;
	FILE *fp1;
	FILE *fp2;
	fp=fopen("file1.txt","r");//message
	fp1=fopen("file2.txt","r");//carrier
	fp2=fopen("steg.txt","w");//steg file
	if(fp==NULL)
	{
		printf("error in opening message file");
		return 0;
	}
	if(fp1==NULL)
	{
		printf("error in opening carrier file");
		return 0;
	}
	if(fp2==NULL)
	{
		printf("error in opening result file");
		return 0;
	}
	do{
		if(feof(fp))
		{
			flag=1;
			
			break;
		}
		if(feof(fp1))
		{
			flag=2;
			printf("error message too big");
			break;
		}	
		ch1=fgetc(fp);
		ch2=fgetc(fp1);
		
		//veginere cipher code
		if(ch1>=97&&ch1<=122)
		{
			ch1=ch1-97;
		}
		if(ch1>=65&&ch1<=90)
		{
			ch1=ch1-65;
		}
	
		k=key[i%strlen(key)]-65;
		temp=(ch1+k)%26;
		temp=temp+65;
		fputc(temp,fp2);
		fputc(ch2,fp2);
		i++;
	}while(1);
	ch1=';';
	fputc(ch1,fp2);
	
	if(flag==1)
	{
		while(feof(fp1))
		{
			ch1=fgetc(fp1);
			fputc(ch1,fp2);
		}
	}
}

int decrypt()
{
	int ch1,ch2,i=0,k,temp;
	FILE *fp;
	FILE *fp1;
	FILE *fp2;
	fp=fopen("steg.txt","r");//steg file
	fp1=fopen("file1.txt","w");//message
	fp2=fopen("file2.txt","w");//carrier
	if(fp==NULL)
	{
		printf("error in opening Steg file");
		return 0;
	}
	if(fp1==NULL)
	{
		printf("error in opening Result file");
		return 0;
	}
	if(fp2==NULL)
	{
		printf("error in opening carrier file");
		return 0;
	}
	do{
		if(feof(fp))
		{
			break;
		}
		ch1=fgetc(fp);
		ch2=fgetc(fp);
		if(ch1==';')
		{
			break;
		}
		
		
		/* decyption of vegienre
			d=(e-k+26)mod 26
			*/
		if(ch1>=97&&ch1<=122)
		{
			ch1=ch1-97;
		}
		if(ch1>=65&&ch1<=90)
		{
			ch1=ch1-65;
		}
		k=key[i%strlen(key)]-65;
		temp=(ch1-k+26)%26;
		temp=temp+65;
		fputc(temp,fp1);
		fputc(ch2,fp2);
		i++;
	}while(1);
	
}
int stegnog()
{
    int i;
    start:
    printf("choose form the following options\n");
    printf("\t1.encode\n");
    printf("\t2.decode\n");
    scanf("%d",&i);
    if(i==1){
        encrypt();
    }
    else if(i==2)
    {
        decrypt();
    }
    else{
        printf("choose a valid option");
        goto start;
    }
}

void writerule(){
	char source[20],action[10],channel[10],stmt[70],ch;int i;
	opwr:	
	printf("choose the channel in which you want to add rules:\n");
	printf("\t1.INPUT\n");
	printf("\t2.OUTPUT\n");
	scanf("%d",&i);
	if(i==1) strcpy(channel,"INPUT");
	else strcpy(channel,"OUTPUT");
	printf("enter the Source IP/Destination IP you want to work on:\n\t");
	scanf("%s",source);
	acwr:
	printf("choose the action that will happen when a packet is encountered:\n\t");
	printf("1.Accept\n");
	printf("\t2.Drop\n");
	scanf("%d",&i);
	if(i==1) strcpy(action,"ACCEPT");
	else if(i==2) strcpy(action,"DROP");
	else {
		printf("enter the valid option\n");
		goto acwr;
	}
	strcpy(stmt,"iptables -A ");
	strcat(stmt,channel);
	strcat(stmt," -s ");
	strcat(stmt,source);
	strcat(stmt," -j ");
	strcat(stmt,action);
	system(stmt);
	printf("rule added....\n");
	printf("The Current iptables state is:");
	system("iptables -L");
	printf("do you want to add more rules?y/n");
	scanf(" %c",&ch);
	if(ch=='y'||ch=='Y')
		{ 
			goto opwr;
		}
	
}

void deleteruleall()
{
	char ch1[10],stmt[50];
	int i=0;
	delete:
	printf("Choose which channel rules you want to flush\n");
	printf("/t 1.INPUT\n");
	printf("/t 2.OUTPUT\n");
	printf("/t 3. ALL\n");
	scanf("%d",&i);
	if(i==1)
	{
		system("iptables -F INPUT");	
	}
	else if(i==2)
	{
		system("iptables -F OUTPUT");	
	}
	else if(i==3)
	{
		system("iptables -F");	
	}
	else
	{
		printf("choose a valid option\n");
		goto delete;	
	}
	
	
}

void deleteruleindex()
{
	char ch1[10],ch2[4],stmt[50];
	char i;
	dri:
	printf("Which channel rule you want to delete:\n");
	printf("\t1. INPUT\n");
	printf("\t2. OUTPUT\n"); 
	scanf(" %c",&i);
	if(i=='1')
	{
		strcpy(ch1,"INPUT");
	}
	else if(i=='2')
	{
		strcpy(ch1,"OUTPUT");	
	}
	else
	{
		printf("Choose a valid option\n");
		goto dri;
	}
	printf("choose the line number form the table\n");
	strcpy(stmt,"iptables -L ");strcat(stmt,ch1);strcat(stmt," --line-numbers");
	system(stmt);
	scanf("%s",ch2);
	strcpy(stmt,"iptables -D ");strcat(stmt,ch1);strcat(stmt," ");strcat(stmt,ch2);
	system(stmt);
	printf("do you want to delete more rules(y/n)?\n");
	scanf(" %c",&i);
	if(i=='y'||i=='Y')
		{
			goto dri;
		}

}

void defaultpolicy()
{
	char ch1[10],ch2[10],stmt[50],c;
	int i=0;
	policy:
	printf("Which default policy you want to change:\n");
	printf("\t1. INPUT\n");
	printf("\t2. OUTPUT\n"); 
	scanf("%d",&i);
	if(i==1)
	{
		strcpy(ch1,"INPUT");
	}
	else if(i==2)
	{
		strcpy(ch1,"OUTPUT");	
	}
	else
	{
		printf("Choose a valid option\n");
		goto policy;	
	}
	action:
	printf("Choose the policy that you want to apply over the channel\n");
	printf("\t1.DROP\n\t2.ACCEPT");
	scanf("%d",&i);
	if(i==1)
	{
		strcpy(ch2,"DROP");
	}
	else if(i==2)
	{
		strcpy(ch2,"ACCEPT");	
	}
	else
	{
		printf("Choose a valid option\n");
		goto action;	
	}
	strcpy(stmt,"iptables -P ");strcat(stmt,ch1);strcat(stmt," ");strcat(stmt,ch2);
	system(stmt);
	printf("do you want to change more policy?(y/n)\n");
	scanf("%c",&c);
	if(c=='y') goto policy;
	
}
int firewall()
{
	int ch;
	printf("Welcome to the firewall module\n");
	printf("Here you can choose from the following options to change the working of Firewall\n");
	init:
	
	printf("choose from the following options\n");
	
	printf("\t1. Write your own rules\n");
	printf("\t2. Change the default policy of channels\n");
	printf("\t3. Delete Firewall Rules one by one\n");
    printf("\t4. Delete all Rules\n");
	scanf("%d",&ch);
	
	switch(ch)
	{
		case 1: 
		writerule();
		goto init;
		break;
		case 2: 
		defaultpolicy();
		goto init;
		break;
		case 3: 
		deleteruleindex();
		goto init;
		break;
		case 4: 
		deleteruleall();
		goto init;
		break;
		default:
		printf("enter a valid option");
		goto init;
		break;

		}

	return 0;
}
/*
int usbblock()     //usb block main function
{
  char * allow_rule;
  ruid = getuid();
  euid = geteuid();

  
  // rule to allow usb drives for a predefined amount of time
  char rule2[] = 
    "#tmp allows all USB devices\n"
    "ACTION==\"add\", DRIVERS==\"usb\"\n";

  allow_rule = rule2;
    
  int choice;
  printf("Please input choice number\n");
  printf("1. Block USB ports\n");
  printf("2. Unblock USB ports\n");
  scanf("%d", &choice);
  if(choice==2)
  {
	unblock();
  }
  else 
  {
      
    // restore the udev rule always
    if (signal(SIGTERM, sig_handler) == SIG_ERR) 
    {
	return 88;         // mount error signal
    }
    if (signal(SIGINT, sig_handler) == SIG_ERR) 
    {
	return 88;
    }
    if (signal(SIGUSR1, sig_handler) == SIG_ERR) 
    {
	return 88;
    }
    atexit(make_file); //atexit helps us register a function that can be called at process termination.
      
      FILE *fp;
      do_setuid();
      fp= fopen(fname, "r+"); // opening in r+ mode
      undo_setuid();
      if (fp)
      {
      fprintf(fp, "%s", allow_rule); // for modifications in the rules file
      if (ftruncate(fileno(fp), strlen(allow_rule)) != 0) 
      {
	return 27;
      }
      fclose(fp);
      printf("Temp allow rule added, sleeping\n");
      sleep(wait);

      }
  return 0;
}
  }
void unblock()
{
  system("rm -rf /etc/udev/rules.d/11-to_rule_all.rules");
}

void sig_handler(int signo)
{
  if (signo == SIGUSR1) 
  {
	printf("received SIGUSR1\n");
  }
  else if (signo == SIGTERM) 
  {
	printf("received SIGSTERM\n");
  }
  else if (signo == SIGINT) 
  {
	printf("\nreceived SIGINT\n");
  }
  make_file();			//calling makefile function to create file
}

void make_file()
{
  // printf("making the file now.\n");
  FILE *fp;
  do_setuid();
  if (( fp = fopen(fname, "w") ))
  {
    fprintf(fp, "%s", no_usb);
    printf("Block all new USB rule added\n");
  }
  else
  {
    fprintf(stderr, "ERROR: could not make the udev rules\n");
  }
  undo_setuid();
}

void do_setuid (void)
{
   int status;
   #ifdef _POSIX_SAVED_IDS
   status = seteuid(euid);
   #else
   status = setreuid(ruid, euid);
   #endif
   if (status < 0)
   {
     fprintf(stderr, "Couldn't set uid.\n");
     exit(status);
   }
}

void undo_setuid(void) 
{
   int status;
   #ifdef _POSIX_SAVED_IDS
   status = seteuid(ruid);
   #else
   status = setreuid(euid, ruid);
   #endif
   if (status < 0)
   {
     fprintf(stderr, "Couldn't set uid.\n");
     exit(status);
   }

 */

int main()
{
    int qwe;
    /* code */
    init:
    printf("\n\t\t\tWelcome to the ARGUS Security Toolkit\n\n");
    printf("Choose a module to run from the list below:\n");
    printf("\n1.\tSecure Code Analyzer\n");
    printf("2.\tSteganography\n");
    printf("3.\tFirewall Module\n");
    printf("4. \t Usb Blocker\n");
    scanf("%d",&qwe);
    if (qwe == 1)
    {
        secode();goto init;
    }
    else if (qwe == 2)
    {
        stegnog();goto init;
    }
    else if (qwe == 3)
    {
        firewall();goto init;
    }
    else if(qwe=4)
    {
    	system("gcc block.c -o block.out");
	    system("./block.out");
		goto init;
	}
    else
    {
    	printf("select a valid option \n");goto init;
	}
    return 0;
}
