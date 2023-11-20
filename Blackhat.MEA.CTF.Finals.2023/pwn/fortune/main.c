#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char custom_fortune[100] = "Embrace the bugs, for in their code lies the beauty of endless possibilities.\n - ChatGPT (GPT-3.5)\n";

static const char *fortunes[] = {
  "Vulnerability sounds like faith and looks like courage.\n - Brene Brown\n",
  "Turn your wounds into wisdom.\n - Oraph Winfrey\n",
  "I never dreamed about success.\nI worked for it.\n - Estee Lauder\n",
  "You are not what you've done.\nYou are what you keep doing.\n - Jack Butcher\n",
  custom_fortune
};

int main() {
  int choice;

  puts("1. Get a fortune cookie" "\n"
       "2. Set a custom message" "\n"
       "x. Exit");

  while (1) {
    printf("> ");
    if (scanf("%d%*c", &choice) != 1)
      exit(1);

    switch (choice) {
      case 1: {
        printf("Which fortune cookie? [0-4]: ");
        if (scanf("%d%*c", &choice) != 1)
          exit(1);
        if (choice > 4) {
          puts("Invalid choice.");
          break;
        }
        putchar('\n');
        printf(fortunes[choice]);
        putchar('\n');
        break;
      }

      case 2: {
        printf("Your message: ");
        if (scanf("%99[^\n]s", custom_fortune) != 1)
          exit(1);
        custom_fortune[strcspn(custom_fortune, "%")] = '\0';
        break;
      }

      default:
        puts("Goodbye.");
        exit(0);
    }
  }
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  alarm(60);
}
