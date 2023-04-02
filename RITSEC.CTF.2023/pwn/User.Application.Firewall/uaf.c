#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>


char * rules[32];
int freed[32];

int created = 0;

void handler() {
	puts("Your session has expired.");
	exit(-1);
}


void menu() {
	puts("---Choose your option:---");
	puts("1. Create a firewall rule");
	puts("2. View a firewall rule");
	puts("3. Edit a firewall rule");
	puts("4. Delete a firewall rule");
	puts("5. Exit");
}

void create() {
	if(created >= 32) {
		puts("You have reached the max number of firewall rules.");
		return;
	}
	int index;
	for(index = 0; index < 32; index++) {
		if(rules[index] == 0 || freed[index] != 0) {
			break;
		}
	}
	rules[index] = malloc(255);
	puts("Firewall rule set. Enter your firewall rule here:");
	read(0, rules[index], 255);
	printf("Your firewall rule ID is: %d\n", index);
	freed[index] = 0;
	created++;
}

void view() {
	char val[8] = {0};
	int index;
	int choice = -1;
	for(index = 0; index < 32; index++) {
		if(rules[index] == 0) {
			break;
		}
	}
	while(choice < 0 || choice >= index) {
		puts("Enter the firewall ID which you want to view:");
		fgets(val, 8, stdin);
		choice = atoi(val);
		if(choice < 0 || choice >= index) {
			puts("Unknown firewall rule ID.");
			return;
		} 
	}
	printf("Your rule: %s\n", rules[choice]);
}

void edit() {
	char val[8] = {0};
	int index;
	int choice = -1;
        for(index = 0; index < 32; index++) {
                if(rules[index] == 0) {
                        break;
                }
        }
        while(choice < 0 || choice >= index) {
                puts("Enter the firewall ID which you want to edit:");
                fgets(val, 8, stdin);
                choice = atoi(val);
                if(choice < 0 || choice >= index) {
                        puts("Unknown firewall rule ID.");
			return;
                }
        }
	puts("Edit your new firewall rule here:");
	read(0, rules[choice], 255);
	puts("Your firewall rule has been updated");
}

void del() {
        char val[8] = {0};
        int index;
        int choice = -1;
        for(index = 0; index < 32; index++) {
                if(rules[index] == 0 || freed[index] != 0) {
                        break;
                }
        }
        while(choice < 0 || choice >= index || freed[choice] != 0) {
                puts("Enter the firewall ID which you want to delete:");
                fgets(val, 8, stdin);
                choice = atoi(val);
                if(choice < 0 || choice >= index || freed[choice] != 0) {
                        puts("Unknown firewall rule ID.");
			return;
                }
        }
	free(rules[choice]);
	freed[choice] = 1;
	puts("Rule deleted");
	created--;

}
void bye() {
	puts("Thanks for using the User Application Firewall!");
	exit(0);
}

int main() {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	signal(SIGALRM, handler);
	alarm(60);
	puts("Welcome to our User Application Firewall (UAF)!");
	unsigned int option;
	char val[8] = { 0 };
	while (1) {
		menu();
		printf("> ");
		fgets(val, 8, stdin);
		option = atoi(val);
		switch(option) {
			case 1:
				create();
				break;
			case 2:
				view();
				break;
			case 3:
				edit();
				break;
			case 4:
				del();
				break;
			case 5:
				bye();
				break;
			default:
				puts("Invalid option!");
				break;
		}
	}
}

