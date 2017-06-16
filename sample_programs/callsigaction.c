#include <stdio.h>
#include <signal.h>

void print_sigaction(struct sigaction act) {
  printf("Sigaction address: %p \n", &act);
  printf("Handler: %p at %p \n", act.sa_handler, &(act.sa_handler));
  //  printf("Other Handler: %p at %p \n", act.sa_sigaction, &(act.sa_sigaction));
  //  unsigned long* m = (unsigned long*) (&(act.sa_handler) & 0x4);
  //printf("Mask?: %lu at %p \n", (*m), m);
  printf("Mask: %lu at %p \n", act.sa_mask, (void *)(act.sa_mask));
  printf("Flags: %d at %p \n", act.sa_flags, &(act.sa_flags));
  printf("Restorer: %p \n", act.sa_restorer);
}

int main(void) {
  int signum = 13;

  sigset_t mask1;
  sigemptyset(&mask1);
  sigaddset(&mask1, 14);
  sigaddset(&mask1, 8);

  sigset_t mask2;
  sigemptyset(&mask2);
  sigaddset(&mask2, 5);


  struct sigaction act;
  act.sa_handler = (void*) -1;
  act.sa_mask = mask1;
  act.sa_flags = 3;
  
  struct sigaction oldact;
  oldact.sa_handler = (void*) 1;
  oldact.sa_mask = mask2;
  oldact.sa_flags = 2;

  struct sigaction empty_oldact;

  printf("Test 1 \n");
  sigaction(signum, &act, 0);
  sigaction(signum, 0, &empty_oldact);
  
  print_sigaction(empty_oldact);

  
  /* printf("Test 2\n"); */
  /* sigaction(signum, 0, &oldact); */
  /* printf("Test 3\n"); */
  /* sigaction(signum, &act, &oldact); */
  /* printf("Test 4\n"); */
  /* sigaction(signum, 0, 0); */
  
  
  return 0;
}

