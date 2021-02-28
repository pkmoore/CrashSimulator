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
  // currently the feature this tests is not supported so don't use
  struct sigevent         sigev;

  struct itimerspec       timerspec;
  int                     sigNo = SIGRTMIN;

  /* Set up signal handler. */
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

  sigev.sigev_notify = SIGEV_NONE;

  timer_create(CLOCK_REALTIME, &sigev, timerid);

  timerspec.it_value.tv_sec = interval_s;
  timerspec.it_interval.tv_sec = 0;

  timer_settime(*timerid, 0, &timerspec, NULL);

  struct itimerspec   old_value;
  timer_settime(*timerid, 0, &timerspec, &old_value);

  printf("Old itimerspec value: it_interval: {%d, %d} \n", (int) old_value.it_interval.tv_sec, (int) old_value.it_interval.tv_nsec);

  printf("Old itimerspec value: it_value: {%d, %d} \n",(int) old_value.it_value.tv_sec,(int) old_value.it_value.tv_nsec);  
}

void test_use_simple() {
  timer_t   timerid;
  int       interval = 2;

  printf("Starting timer test: simple \n");
  make_timer_simple(&timerid, interval);

  sleep(1);

  struct itimerspec   time_results;

  timer_gettime(timerid, &time_results);

  printf("Time results: %lu s %lu ns \n", time_results.it_value.tv_sec, time_results.it_value.tv_nsec);

  timer_delete(timerid);
  printf("Ending timer test: simple \n");
}

void test_timer_create() {
  printf("Starting timer test: timer_create \n");
  
  timer_t good_id;
  struct sigevent good_sigev;  
  good_sigev.sigev_notify = SIGEV_NONE;

  // try different clock types
  timer_create(CLOCK_REALTIME, &good_sigev, &good_id);
  timer_delete(good_id);
  timer_create(CLOCK_MONOTONIC, &good_sigev, &good_id);
  timer_delete(good_id);
  timer_create(CLOCK_PROCESS_CPUTIME_ID, &good_sigev, &good_id);
  timer_delete(good_id);
  timer_create(CLOCK_THREAD_CPUTIME_ID, &good_sigev, &good_id);
  timer_delete(good_id);
  timer_create(CLOCK_BOOTTIME, &good_sigev, &good_id);
  timer_delete(good_id);

  struct sigevent bad_sigev;
  bad_sigev.sigev_notify = SIGEV_SIGNAL;
  bad_sigev.sigev_signo = SIGRTMIN;
  bad_sigev.sigev_value.sival_ptr = &good_id;

  // these types of create calls are not supported
  /* timer_create(CLOCK_REALTIME, &bad_sigev, &good_id); */
  /* timer_delete(good_id); */

  /* timer_create(CLOCK_REALTIME, NULL, &good_id); */
  /* timer_delete(good_id); */
  

  // these two externally fail, must have CAP_WAKE_ALARM capability
  /* timer_create(CLOCK_REALTIME_ALARM, &good_sigev, &good_id); */
  /* timer_delete(good_id); */
  /* timer_create(CLOCK_BOOTTIME_ALARM, &good_sigev, &good_id); */
  /* timer_delete(good_id); */

  
  printf("Ending timer test: timer_create \n");
}

int main(void) {

  test_timer_create();
  test_use_simple();

  // signal attaching functionality is not yet supported
  // test_use_attach_to_signal();
  
  return 0;
}
