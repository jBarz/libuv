#include "os390-syscalls.h"
#include <poll.h>
#include <errno.h>

int	_number_of_epolls;
struct _epoll_list* _global_epoll_list[MAX_EPOLL_INSTANCES];

static int _removefd(struct _epoll_list *lst, int fd)
{
        int deletion_point = lst->size;                         
        for (int i = 0; i < lst->size; ++i)                     
        {                                                                  
            if(lst->fds[i] == fd)                                            
            {                                                              
                deletion_point = i;                                        
                break;                                                     
            }                                                              
        }                                                                  

        if (deletion_point < lst->size)                         
        {                                                                  
            for (int i = deletion_point; i < lst->size; ++i)    
            {                                                              
                lst->fds[i] = lst->fds[i+1];                                         
            }                                                              
            --(lst->size);                                        
            return 1;
        }                                                                  
        else
            return 0;
}

static int _doesExist(struct _epoll_list *lst, int fd, int *index)
{

        for (int i = 0; i < lst->size; ++i)                     
        {                                                                  
            if(lst->fds[i] == fd)                                            
            {
                *index=i;
                return 1;
            }
        }                                                                  
        return 0;
}

int epoll_create1(int flags)
{
    struct _epoll_list* p = (void*)malloc(sizeof(struct _epoll_list) * MAX_ITEMS_PER_EPOLL);
    _global_epoll_list[_number_of_epolls++] = p;
    return (unsigned)p; 
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    struct _epoll_list *lst = (struct _epoll_list*)epfd;

    if(op == EPOLL_CTL_DEL){
        if(!_removefd(lst, fd))
            return ENOENT;
            //printf("log: removed fd %d\n", fd);
    }

    else if(op == EPOLL_CTL_ADD)
    {
        int index;
        if( _doesExist(lst, fd, &index) )
        {
            //printf("log: will not add fd %d, already exists\n", fd);
            errno = EEXIST;
            return -1;
        }
        //printf("log: adding fd %d\n", fd);
        lst->fds[lst->size] = fd;
        lst->epollev[lst->size++] = *event;
    }
    else if(op == EPOLL_CTL_MOD)
    {
        int index;
        if( !_doesExist(lst, fd, &index) )
        {
            //printf("log: will not add fd %d, already exists\n", fd);
            errno = ENOENT;
            return -1;
        }
        //printf("log: adding fd %d\n", fd);
        lst->epollev[index] = *event;
    }
    else 
    {
        //printf("epoll error %d\n", op);
        abort();
    }
    return 0;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    struct _epoll_list *lst = (struct _epoll_list*)epfd;

    struct pollfd pfds[lst->size];
    for (int i = 0; i < lst->size; ++i)                     
    {
        pfds[i].fd = lst->fds[i];
        pfds[i].events = 0;
        if(lst->epollev[i].events & EPOLLIN)
            pfds[i].events |= POLLIN; 
        if(lst->epollev[i].events & EPOLLOUT)
            pfds[i].events |= POLLOUT; 
        if(lst->epollev[i].events & EPOLLHUP)
            pfds[i].events |= POLLHUP; 
        //printf("log: added fd %d:%d for polling\n", lst->fds[i], pfds[i].events);
    }
    
    //printf("log: poll args %d, %d \n", lst->size, timeout);
    int returnval = poll( pfds, lst->size, timeout );
    if(returnval == -1)
        return returnval;
    else
        returnval = _NFDS(returnval);
    //printf("log: poll args %d, %d returns %d errno %d\n", lst->size, timeout, returnval, errno);

    int reventcount=0;
    for (int i = 0; i < lst->size && i < maxevents; ++i)                     
    {
        struct epoll_event ev = { 0, 0 };
        //printf("log: fd=%d revents=%d\n", pfds[i].fd, pfds[i].revents);
        ev.data.fd = pfds[i].fd;
        if(!pfds[i].revents)
            continue;

        if(pfds[i].revents & POLLIN)
        {
            ev.events = ev.events | EPOLLIN;
            //printf("log: ev.events=%d\n", ev.events);
            //printf("log: ready for reading data on fd %d\n", ev.data.fd);
        }
        
        if(pfds[i].revents & POLLOUT)
        {
            ev.events = ev.events | EPOLLOUT;
            //printf("log: ready to write data on fd %d\n", ev.data.fd);
        }

        if(pfds[i].revents & POLLHUP)
        {
            ev.events = ev.events | EPOLLHUP;
            _removefd(lst, ev.data.fd);
            //printf("log: fd %d not available anymore\n", ev.data.fd);
        }

        events[reventcount++] = ev; 
            
    }

    return reventcount;
}

int epoll_file_close(int fd)
{
	//printf("log: %d removing fd=%d\n", __LINE__, fd);
	for( int i = 0; i < _number_of_epolls; ++i )
	{
	//printf("log: %d removing fd=%d\n", __LINE__, fd);
		struct _epoll_list *lst = _global_epoll_list[i];
		int index;
		if(_doesExist(lst, fd, &index) )
		{
		//printf("log: really removing fd=%d\n", fd);
			_removefd(lst, fd);
		}
	}
	return 0;
}
