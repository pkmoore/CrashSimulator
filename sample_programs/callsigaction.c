#include <signal.h>
#include <stdio.h>

int main(void) {
  int signum = 13;

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, 14);
  sigaddset(&mask, 8);

  struct sigaction act;
  act.sa_handler = (void*) -1;
  act.sa_mask = mask;
  act.sa_flags = 3;
  
  struct sigaction oldact;
  oldact.sa_handler = (void*) 1;
  oldact.sa_mask = mask;
  oldact.sa_flags = 2;

  printf("Test 1\n");
  sigaction(signum, &act, 0);
  printf("Test 2\n");
  sigaction(signum, 0, &oldact);
  printf("Test 3\n");
  sigaction(signum, &act, &oldact);
  printf("Test 4\n");
  sigaction(signum, 0, 0);
  
  
  return 0;
}
