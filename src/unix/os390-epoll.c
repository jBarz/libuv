#include "os390-syscalls.h"
#include <errno.h>

int	_number_of_epolls;
struct _epoll_list* _global_epoll_list[MAX_EPOLL_INSTANCES];

static int _removefd(struct _epoll_list *lst, int fd)
{
        int deletion_point = lst->size + 1;                         
        for (int i = 0; i < lst->size + 1; ++i)                     
        {                                                                  
            if(lst->items[i].fd == fd)                                            
            {                                                              
                deletion_point = i;                                        
                break;                                                     
            }                                                              
        }                                                                  

        if (deletion_point < lst->size + 1)                         
        {                                                                  
            for (int i = deletion_point; i < lst->size + 1; ++i)    
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
        i->events = 0;
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
	if (lst->size == MAX_ITEMS_PER_EPOLL - 1)
		return ENOMEM;

	// remember, lst->size contains the msgq
	lst->items[lst->size+1].fd = lst->items[lst->size].fd;
	lst->items[lst->size+1].events = lst->items[lst->size].events; 

	lst->items[lst->size].fd = fd;
	_modify(lst, lst->size, events); 
	++lst->size;

	return 0;
}

int epoll_create1(int flags)
{
    struct _epoll_list* p = (void*)calloc(1, sizeof(struct _epoll_list));
    _global_epoll_list[_number_of_epolls++] = p;
    if (pthread_mutex_init(&p->lock, NULL) != 0) {
        errno = ENOLCK;
        return -1;
    }
    p->size = 0;
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
    else if(op == EPOLL_CTL_ADD_MSGQ)
    {
	pthread_mutex_lock(&lst->lock);
	lst->items[lst->size].fd = fd;
	lst->items[lst->size].events = POLLIN ;
	pthread_mutex_unlock(&lst->lock);
	return 0;
    }
    else if(op == EPOLL_CTL_ADD)
    {
        int index;
	pthread_mutex_lock(&lst->lock);
        if( _doesExist(lst, fd, &index) )
        {
            //printf("log: will not add fd %d, already exists\n", fd);
	    pthread_mutex_unlock(&lst->lock);
            errno = EEXIST;
            return -1;
        }
        //printf("log: adding fd %d\n", fd);
	int retval = _append(lst, fd, *event);
	pthread_mutex_unlock(&lst->lock);
	return retval;
    }
    else if(op == EPOLL_CTL_MOD)
    {
        int index;
	pthread_mutex_lock(&lst->lock);
        if( !_doesExist(lst, fd, &index) )
        {
            //printf("log: does not exist fd=%d \n", fd);
	    pthread_mutex_lock(&lst->lock);
            errno = ENOENT;
            return -1;
        }
        //printf("log: modifying fd %d\n", fd);
	_modify(lst, index, *event);
	pthread_mutex_unlock(&lst->lock);
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

    unsigned int size;
    _SET_FDS_MSGS(size, 1, lst->size);
    //printf("log: poll args size=%u, timeout=%d \n", size, timeout);

    struct pollfd *pfds = lst->items;
    //for (int i = 0; i < lst->size + 1 && i < maxevents; ++i)
      //printf("log: fd=%d events=%d\n", pfds[i].fd, pfds[i].events);
    int returnval = poll( pfds, size, timeout );
    //printf("log: poll args size %u, %d returns %d errno %d\n", size, timeout, returnval, errno);
    if(returnval == -1)
        return returnval;
    else
        returnval = _NFDS(returnval) + _NMSGS(returnval);

    int reventcount=0;
    // size + 1 will include the msgq
    for (int i = 0; i < lst->size + 1 && i < maxevents; ++i)                     
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
	    pthread_mutex_lock(&lst->lock);
            _removefd(lst, ev.data.fd);
	    pthread_mutex_unlock(&lst->lock);
            //printf("log: fd %d not available anymore\n", ev.data.fd);
        }

	pfds[i].revents = 0;
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
	        pthread_mutex_lock(&lst->lock);
		if(_doesExist(lst, fd, &index) )
		{
		//printf("log: really removing fd=%d\n", fd);
			_removefd(lst, fd);
		}
	        pthread_mutex_unlock(&lst->lock);
	}
	return 0;
}

