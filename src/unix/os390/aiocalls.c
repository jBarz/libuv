#include <sys/msg.h>         /* msg queue structures              */
#include <sys/ipc.h>

#define _AIO_OS390           /* Expose z/OS Extensions            */
#include <aio.h>             /* Async I/O Stuff                   */

int aio_cancel(int fd)
{
	struct aiocb cb;
	int rv,rc,rsn;         /* BPX1AIO Return Value, Code, and Reason  */
	memset(&cb, 0, sizeof(struct aiocb));
	cb.aio_fildes = fd;
	cb.aio_cmd = AIO_CANCEL;
	BPX1AIO( sizeof(cb), cb, &rv, &rc, &rsn ); 
	printf("JBAR: sent aio cancel Errno= %d, Reason= %X\n", rc, rsn);
	return rv;
}
