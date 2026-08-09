#ifndef OBSERVER_IMPLEMENTAION
#define OBSERVER_IMPLEMENTAION

#include <sys/user.h>
#include <sys/wait.h>

void observer_loop(pid_t pid, int status, struct user_regs_struct regs, char* logfile);

#endif