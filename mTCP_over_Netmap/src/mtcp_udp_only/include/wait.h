#ifndef __WAIT_H
#define __WAIT_H

#include <pthread.h>

/* simulating thread blocking(used for _accept(), _read(), _recv()) */
struct mtcp_wait {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int notified;		/* log whether wait is waken up already */
	int dead;		/* for safe exiting wait state */
	int sleep;
};

int wake_up(struct mtcp_wait *w);
int sleep_on(struct mtcp_wait *w);
void wait_init(struct mtcp_wait *w);
void wait_exit(struct mtcp_wait *w);

#endif	/* wait.h */
