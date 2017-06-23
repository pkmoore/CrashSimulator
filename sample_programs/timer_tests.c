#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>


void
timer_handler (int signum)
{
  static int count = 0;
  printf ("timer expired %d times\n", ++count);
}

static int
make_timer_signal(timer_t *timerid, int interval_s) {
  struct sigevent         sigev;
  
  struct itimerspec       timerspec;
  int                     sigNo = SIGRTMIN;

  /* Set up signal handler. */
  //  sa.sa_flags = SA_SIGINFO;

  struct sigaction sa;
    
  sa.sa_handler = &timer_handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(sigNo, &sa, NULL) == -1) {
    fprintf(stderr," Failed to setup signal handling.\n");
    return(-1);
  }
  
  /* Set and enable alarm */
  sigev.sigev_notify = SIGEV_SIGNAL;
  sigev.sigev_signo = sigNo;
  sigev.sigev_value.sival_ptr = timerid;
  
  timer_create(CLOCK_REALTIME, &sigev, timerid);

  timerspec.it_value.tv_sec = interval_s; 
  timerspec.it_interval.tv_sec = interval_s;

  timer_settime(*timerid, 0, &timerspec, NULL);

  return(0);
}


void test_use_attach_to_signal() {
  timer_t    timerid;
  int        interval = 1;

  printf("Starting timer test: attach to signal \n");

  make_timer_signal(&timerid, interval);
  int i;
  for (i = 0; i < 2000000000; i++) {}
  timer_delete(timerid);
  
  printf("Ending timer test: attach to signal \n");
}


static int
make_timer_simple(timer_t *timerid, int interval_s) {
  struct sigevent     sigev;
  struct itimerspec   timerspec;
  struct itimerspec   old_value;

  sigev.sigev_notify = SIGEV_NONE;

  timer_create(CLOCK_REALTIME, &sigev, timerid);

  timerspec.it_value.tv_sec = interval_s;
  timerspec.it_interval.tv_sec = 0;

  timer_settime(*timerid, 0, &timerspec, NULL);
}

void test_use_simple() {
  timer_t   timerid;
  int       interval = 5;

  printf("Starting timer test: simple \n");
  make_timer_simple(&timerid, interval);

  sleep(3);

  struct itimerspec   time_results;

  timer_gettime(timerid, &time_results);

  printf("Time results: %lu s %lu ns \n", time_results.it_value.tv_sec, time_results.it_value.tv_nsec);

  timer_delete(timerid);
  printf("Ending timer test: simple \n");
}


void test_timer_create() {
  printf("Starting timer test: timer_create \n");
  
  //timer_create(CLOCK_REALTIME, &sigev, timerid);

  timer_t good_id;
  const timer_t bad_id;
  struct sigevent good_sigev;
  good_sigev.sigev_notify = SIGEV_NONE;
  struct sigevent bad_sigev;
  bad_sigev.sigev_notify = SIGEV_SIGNAL;
  bad_sigev.sigev_signo = -1;
  bad_sigev.sigev_value.sival_ptr = (void *)0;
  
  // try invalid arguments
  // first two work, 3rd is irrelevant
  //timer_create(0, 0, 0);
  //timer_create(CLOCK_REALTIME, &bad_sigev, good_id);
  timer_create(CLOCK_REALTIME, &good_sigev, bad_id);

  
  printf("Ending timer test: timer_create \n");
}



int main(void) {

  //test_use_simple();
  //test_timer_create();
  //test_use_attach_to_signal();
  
  return 0;
}
