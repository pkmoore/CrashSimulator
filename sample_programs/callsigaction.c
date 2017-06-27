#include <stdio.h>
#include <signal.h>

void print_sigaction(struct sigaction* act) {
    
  printf("Handler: %p \n", act->sa_handler);
  printf("Flags: %d \n", act->sa_flags);
  printf("Mask: %x \n", (act->sa_mask));
  
  int i;
  for(i = 1; i < 33; i++) {
    int containsSignal = sigismember(&(act->sa_mask), i);
    if (containsSignal == 1) {
       printf("Mask Contains Signal %d \n", i);
    }
  }
  
  printf("Restorer: %p \n", act->sa_restorer);
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
  sigaddset(&(act.sa_mask), 4);
  sigaddset(&(act.sa_mask), 24);
  sigaddset(&(act.sa_mask), 1);
  sigaddset(&(act.sa_mask), 19);
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
  sigaddset(&(act.sa_mask), 11);
  sigaddset(&(act.sa_mask), 5);

  struct sigaction empty_oldact;

  // test setting new sigaction then asking for it
  printf("Test 1 \n");
  sigaction(signum, &act, 0);
  sigaction(signum, 0, &empty_oldact);
  print_sigaction(&empty_oldact);

  // test asking for same sigaction again after overwriting an unrelated sigaction
  printf("Test 2 \n");
  sigaction(signum, 0, &oldact);
  print_sigaction(&oldact);

  // test setting a scond sigaction and asking for it
  printf("Test 3 \n");
  sigaction(signum, &act2, &oldact);
  sigaction(signum, 0, &empty_oldact);
  print_sigaction(&empty_oldact);

  // test 
  printf("Test 4 \n");
  sigaction(signum, 0, 0);
  sigaction(signum, 0, &empty_oldact);
  print_sigaction(&empty_oldact);
  
  return 0;
}

