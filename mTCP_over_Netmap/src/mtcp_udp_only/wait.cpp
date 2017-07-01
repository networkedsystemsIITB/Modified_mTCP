#include "wait.h"

/*
 * 1. @notified avoid double calling of wake_up()
 * 2. If wake_up() is called before sleep_on(),
 *    @notified can skip next waiting of sleep_on().
 */
int wake_up(struct mtcp_wait *w)
{
	pthread_mutex_lock(&w->mutex);
	pthread_cond_signal(&w->cond);
	pthread_mutex_unlock(&w->mutex);
	return 0;
}

int sleep_on(struct mtcp_wait *w)
{
	pthread_mutex_lock(&w->mutex);
	pthread_cond_wait(&w->cond, &w->mutex);
	pthread_mutex_unlock(&w->mutex);
	return 0;
}

void wait_init(struct mtcp_wait *w)
{
	/* XXX: Should it need error checking? */
	pthread_cond_init(&w->cond, NULL);
	pthread_mutex_init(&w->mutex, NULL);
	w->dead = 0;
	w->notified = 0;
	w->sleep = 0;
}

void wait_exit(struct mtcp_wait *w)
{
	pthread_mutex_lock(&w->mutex);
	if (w->dead)
		goto unlock;
	w->dead = 1;
	if (w->sleep)
		pthread_cond_broadcast(&w->cond);
unlock:
	pthread_mutex_unlock(&w->mutex);
}
