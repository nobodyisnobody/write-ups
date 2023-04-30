#include "openssl/sha.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#define TIMEOUT       120 // in seconds

char encrypted[] = "8f75456b574439e191ae14f3e95a80a881a7216c2ac69b9c342aa62f8a048e0e";

struct Robot {
    char name[16];
    void (*makeNoise)();
    void (*move)();
};

struct RobotUserGuide {
    char guide[32];
};

void
timeout(int sig)
{
    exit(EXIT_FAILURE);
}


void bleep(struct Robot *d)
{
    for (int i=0; i<3; i++) {
        puts ("Bip !");
        usleep (500000);
    }
    printf ("La discussion avec %s est un peu ennuyeuse...\n", d->name);
}

void roll(struct Robot *d)
{
    printf ("%s se déplace en grinçant !\n", d->name);
}

void* newRobot(char *s)
{
    printf ("Vous construisez un nouveau robot. %s est un très joli nom pour un robot !\n", s);
    struct Robot *newrobot = malloc (sizeof(struct Robot));
    strncpy (newrobot->name, s, 15);
    newrobot->makeNoise = bleep;
    newrobot->move = roll;
    return (void*) newrobot;
}

void admin(char *pwd)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char    result[65];

    SHA256((const unsigned char *) pwd, strlen(pwd), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(result + (i * 2), "%02x", hash[i]);
    }

    if (strcmp(result, encrypted) == 0) {
        execl("/bin/cat", "/bin/cat", "flag.txt", NULL);
        perror("execl");
        exit(2);
    } else {
        puts("ERROR: wrong password!");
    }
}

int main()
{
    struct Robot  *robot = NULL;
    struct RobotUserGuide *userGuide = NULL;
    char ordre = -1;
    char input[64] = {0};

    // Install challenge timeout
    signal(SIGALRM, timeout);
    alarm(TIMEOUT);

    while (1) {
        /* Menu */
        puts ("Que faites-vous ?");
        puts ("1: Construire un robot\t\t4: Rédiger le mode d'emploi");
        puts ("2: Le faire parler\t\t5: Afficher le mode d'emploi");
        puts ("3: Jouer avec le robot\t\t6: Admin");
        puts ("0: Quitter");
        printf ("> ");

        /* Ordre */
        ordre = (char) getc (stdin);
        if (ordre == '\n')
            continue;
        getc (stdin); /* Enlève \n */

        /* Exécution de l'ordre */
        switch (ordre) {
            case '1':
                printf ("Comment vous l'appelez ?\n> ");
                fgets (input, 64, stdin);
                for (int i=0; i<64; i++) {
                    if (input[i] == '\n')
                        input[i] = 0;
                }
                robot = newRobot(input);
                break;

            case '2':
                if (robot)
                    robot->makeNoise(robot);
                else
                    puts ("Vous n'avez pas de robot !");
                break;

            case '3':
                if (robot) {
                    printf ("Vous allumez le robot. ");
                    robot->move(robot);
                    printf ("De la fumée commence à apparaître, puis des étincelles... %s prend feu !!!\n", robot->name);
                    printf ("%s est complètement détruit\n", robot->name);
                    free (robot);
                } else {
                    puts ("Vous n'avez pas de robot !");
                }
                break;

            case '4':
                userGuide = malloc (sizeof (struct RobotUserGuide));
                printf ("Vous commencez à rédiger le mode d'emploi...\n> ");
                fgets (userGuide->guide, 32, stdin);
                break;

            case '5':
                if (userGuide) {
                    for (int i=0; i<32; i++) {
                        char c = userGuide->guide[i];
                        putchar (c);
                    }
                    fflush (stdout);
                } else {
                    puts ("Il n'y a pas de mode d'emploi");
                }
                break;

            case '6':
                printf ("Enter admin password\n> ");
                fgets (input, 64, stdin);
                for (int i=0; i<64; i++) {
                    if (input[i] == '\n')
                        input[i] = 0;
                }
                admin (input);
                break;

            case '0':
                puts ("Au revoir !");
                exit (0);
                break;

            default:
                puts ("Commande non reconnue");
                break;
        }
        putchar ('\n');
    }

    return 0;
}
