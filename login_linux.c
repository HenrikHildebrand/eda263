/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include <errno.h>
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler_2() {
  // printf("Ctrl-C\n");
}
void sighandler_20() {
  // printf("Ctrl-Z\n");
}
void sighandler_3() {
  // printf("Ctrl-\\\n");
}

void sighandler() {
	signal(2, sighandler_2);
	signal(20, sighandler_20);
	signal(3, sighandler_3);
}

int main(int argc, char *argv[]) {

	struct mypwent* pwdata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**\0";
	char user[LENGTH];
	char important2[LENGTH] = "**IMPORTANT 2**\0";
	char prompt[] = "password: ";
	char tempSalt[LENGTH];
	char *user_pass;
	char *c_pass;

	sighandler();

	system("/usr/bin/clear");
	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
		important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
		important2);
		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */
		if (fgets(user, LENGTH, stdin) == NULL){
			exit(0); /*  overflow attacks*/
		}

		/*
		Must add null terminator in end because fgets doesn't
		*/
		user[strlen(user)-1] = '\0';

		if(!strcmp(user, "exit")){
			exit(0);
		} else if (!strcmp(user, "genpass")){
			printf("Enter password to encrypt: ");
			if(fgets(user, LENGTH, stdin) == NULL){
				exit(0);
			}
			printf("Enter salt: ");
			if(fgets(tempSalt, LENGTH, stdin) == NULL){
				exit(0);
			}
			printf("%s\n", crypt(user, tempSalt));
		} else { // Login with password
			/* check to see if important variable is intact after input of login name - do not remove */
			printf("Value of variable 'important 1' after input of login name: %*.*s\n",
			LENGTH - 1, LENGTH - 1, important1);
			printf("Value of variable 'important 2' after input of login name: %*.*s\n",
			LENGTH - 1, LENGTH - 1, important2);
			pwdata = mygetpwnam(user);
			if (pwdata != NULL) { // User exists
				user_pass = getpass(prompt);
				c_pass = crypt(user_pass, pwdata->passwd_salt);
				if (!strcmp(c_pass, pwdata->passwd)) {
					system("/usr/bin/clear");
					printf(" You're in !\n");
					sleep(1);
					/*  check UID, see setuid(2) */
					pwdata->pwfailed = 0;
					pwdata->pwage++;
					if(!mysetpwent(user, pwdata) < 0){
						printf("Failed writing to password database\n");
					}
					printf("UID: %d\n", pwdata->uid);
					if(setuid(pwdata->uid) < 0){
						printf("Could not set uid: %s\n", strerror(errno));
					}
					else {
						if (system("/bin/sh") < 0){
						printf("Could not run bash\n");
						}
					}
					//system("/usr/bin/clear");
					/*  start a shell, use execve(2) */
				}	 else {
					system("/usr/bin/clear");
					printf("Wrong password...\n");
					pwdata->pwfailed++;
					if(mysetpwent(user, pwdata) < 0){
						printf("Failed writing to password database\n");
					}
					if(pwdata->pwfailed > 2){
						printf("Too many failed attempts... Try again in a moment...\n");
						sleep(5);
					}
				}
			} else{
				system("/usr/bin/clear");
				printf("Login Incorrect, User dont exists \n");

			}
		}
	}
	return 0;
}
