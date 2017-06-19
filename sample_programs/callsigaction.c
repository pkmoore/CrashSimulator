#include <stdio.h>
#include <signal.h>

void print_sigaction(struct sigaction* act) {
  printf("Sigaction address: %p \n", act);
  //printf("Sigaction handler address: %p\n" &(act->sa_handler));

  
  printf("Handler: %p at %p \n", act->sa_handler, &(act->sa_handler));
  printf("Flags: %d at %p \n", act->sa_flags, &(act->sa_flags));
  printf("Mask: at %p \n", &(act->sa_mask));
  printf("Contains Signal 14 %d \n", sigismember(&(act->sa_mask), 14));
  printf("Contains Signal 8 %d \n", sigismember(&(act->sa_mask), 8));
  // printf("Mask: %lu \n", act->sa_mask);
  //printf("Restorer: %p \n", act.sa_restorer);
}

void sig_handler(int sig) {

}

int main(void) {
  int signum = 13;



  struct sigaction act;
  act.sa_handler = (void*) -1;
  act.sa_flags = 3;
  
  sigemptyset(&(act.sa_mask));
  sigaddset(&(act.sa_mask), 14);
  sigaddset(&(act.sa_mask), 8);


  struct sigaction act2;
  act2.sa_handler = (void*)sig_handler;
  act2.sa_flags = 1;
  
  sigemptyset(&(act2.sa_mask));
  sigaddset(&(act2.sa_mask), 8);

  
  struct sigaction oldact;
  oldact.sa_handler = (void*) 1;
  oldact.sa_flags = 2;

  sigemptyset(&(act.sa_mask));
  sigaddset(&(act.sa_mask), 14);
  sigaddset(&(act.sa_mask), 8);
  
  

  struct sigaction empty_oldact;

  printf("Test 1 \n");
  sigaction(signum, &act, 0);
  sigaction(signum, 0, &empty_oldact);
  print_sigaction(&empty_oldact);
  
  printf("Test 2\n");
  sigaction(signum, 0, &oldact);
  print_sigaction(&oldact);
  
  printf("Test 3\n");
  sigaction(signum, &act2, &oldact);
  sigaction(signum, 0, &empty_oldact);
  print_sigaction(&empty_oldact);
  
  printf("Test 4\n");
  sigaction(signum, 0, 0);
  sigaction(signum, 0, &empty_oldact);
  print_sigaction(&empty_oldact);
  
  
  return 0;
}

