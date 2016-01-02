#include "os390-syscalls.h"
#include <errno.h>

int	_number_of_epolls;
struct _epoll_list* _global_epoll_list[MAX_EPOLL_INSTANCES];

static int _removefd(struct _epoll_list *lst, int fd)
{
        int deletion_point = lst->size;                         
        for (int i = 0; i < lst->size; ++i)                     
        {                                                                  
            if(lst->items[i].fd == fd)                                            
            {                                                              
                deletion_point = i;                                        
                break;                                                     
            }                                                              
        }                                                                  

        if (deletion_point < lst->size)                         
        {                                                                  
            for (int i = deletion_point; i < lst->size; ++i)    
            {                                                              
                lst->items[i] = lst->items[i+1];
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
            if(lst->items[i].fd == fd)                                            
            {
                *index=i;
                return 1;
            }
        }                                                                  
        return 0;
}

static void _modify(struct _epoll_list *lst, int index, struct epoll_event events)
{
	struct pollfd *i = &lst->items[index];
        if(events.events & EPOLLIN)
            i->events |= POLLIN; 
        if(events.events & EPOLLOUT)
            i->events |= POLLOUT; 
        if(events.events & EPOLLHUP)
            i->events |= POLLHUP; 
    //printf("log: events = %d\n", i->events);

}

static int _append(struct _epoll_list *lst, int fd, struct epoll_event events)
{
	if (lst->size == MAX_ITEMS_PER_EPOLL)
		return ENOMEM;
	lst->items[lst->size].fd = fd;
	_modify(lst, lst->size, events); 
	++lst->size;
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
	return _append(lst, fd, *event);
    }
    else if(op == EPOLL_CTL_MOD)
    {
        int index;
        if( !_doesExist(lst, fd, &index) )
        {
            //printf("log: does not exist fd=%d \n", fd);
            errno = ENOENT;
            return -1;
        }
        //printf("log: modifying fd %d\n", fd);
	_modify(lst, index, *event);
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

    //printf("log: poll args %d, %d \n", lst->size, timeout);
    struct pollfd *pfds = lst->items;
    //for (int i = 0; i < lst->size && i < maxevents; ++i)                     
        //printf("log: fd=%d events=%d\n", pfds[i].fd, pfds[i].events);
    int returnval = poll( pfds, lst->size, timeout );
    //printf("log: poll args %d, %d returns %d errno %d\n", lst->size, timeout, returnval, errno);
    if(returnval == -1)
        return returnval;
    else
        returnval = _NFDS(returnval);

    int reventcount=0;
    for (int i = 0; i < lst->size && i < maxevents; ++i)                     
    {
        struct epoll_event ev = { 0, 0 };
        //printf("log: fd=%d revents=%d\n", pfds[i].fd, pfds[i].revents);
        ev.data.fd = pfds[i].fd;
        if(!pfds[i].revents)
            continue;

        if(pfds[i].revents & POLLRDNORM)
        {
            ev.events = ev.events | EPOLLIN;
            //printf("log: ev.events=%d\n", ev.events);
            //printf("log: ready for reading data on fd %d\n", ev.data.fd);
        }
        
        if(pfds[i].revents & POLLWRNORM)
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
