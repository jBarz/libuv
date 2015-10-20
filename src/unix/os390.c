/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "uv.h"
#include "internal.h"
#include "CSRSIC.H"
#include "os390-syscalls.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include <utmpx.h>

#include <poll.h>

#include <ctype.h>
#ifdef HAVE_SYS_AHAFS_EVPRODS_H
#include <sys/ahafs_evProds.h>
#endif

#include <limits.h>
#include <strings.h>

#define RDWR_BUF_SIZE   4096
#define EQ(a,b)         (strcmp(a,b) == 0)


#define CVT_PTR ((char**) 0x10)
#define CVTEXT2_OFFSET 0x148
#define CVTLDTO_OFFSET 0x38
static int MAX_JOBS = 1024;
#define ASCB_OFFSET 0x234
#define EPOCH_CONVERTER 2208988800ll                   /* MVS TOD is in 1/4096 usecs since 1900. UTC is since 1970. This is the conversion number in seconds */

#define PROC_STR_OFFSET 0xAC
#define INIT_STR_OFFSET 0xB0
#define ASCBEJST_OFFSET 0x40
#define ASCBEATT_OFFSET 0x128
#define ASCBSRBT_OFFSET 0xC8
#define NEXT_ASCB_OFFSET 0x04
#define CPU_COUNT_OFFSET 0x0A
#define MEMORY_OFFSET 0x358

#define ASCBASSB_OFFSET        0x150           /* POINTER TO ADDRESS SPACE SECONDARY BLOCK */
#define ASSBASST_OFFSET        0x160           /* Additional SRB Service Time. CPU time is accumulated here for this address space's Preemptable SRBs and for Client Related SRBs for which this address space is the client. Format: TOD Clock */

#define CVTASMVT_OFFSET       0x2C0
#define ASMSLOTS_OFFSET       0x70             /* Count of total local slots in all open local page data sets: signed int on 4 */
#define ASMVSC_OFFSET         0x74             /* Count of total local slots allocated to VIO private area pages: signed int on 4 bytes */
#define ASMNVSC_OFFSET        0x78             /* Count of total local slots allocated to non-VIO private area pages: signed int on 4 bytes */
#define ASMERRS_OFFSET        0x7C             /* Count of bad slots found on local data sets during normal operations */
#define ASCMTCBPT_OFFSET      0xA4             /* Address of ASM TCB */
#define ASMTASCB_OFFSET       0xB4             /* Address of ASCB for address space in which ILRTMRLG is running */
#define ASMLSYSI_OFFSET       0x490            /* System token for last dataset that protection was bypassed for during IPL */



#define CVTRCEP_OFFSET         0x490           /* "V(IARMRRCE)" - ADDRESS OF THE RSM CONTROL AND ENUMERATION AREA. */
#define RCEPOOL_OFFSET         0x4             /* NUMBER OF FRAMES CURRENTLY AVAILABLE TO SYSTEM. EXCLUDED ARE FRAMES BACKING PERM STORAGE, FRAMES OFFLINE, AND BAD FRAMES */
#define RCEBELPL_OFFSET        0x8             /* THE SAME AS RCEPOOL EXCEPT THAT ONLY FRAMES BELOW 16M REAL ARE COUNTED. */
#define RCETOTPI_OFFSET        0x44            /* TOTAL NUMBER OF PAGES PAGED-IN EXCLUDING SWAP-IN, VIO, AND HIPERSPACE PAGE-INS. */
#define RCEVIOPI_OFFSET        0x54            /* TOTAL NUMBER OF VIO PAGES PAGED-IN EXCLUDING SWAP-IN. */
#define RCETOTPO_OFFSET        0x58            /* TOTAL NUMBER OF PAGES PAGED-OUT EXCLUDING SWAP-OUT, VIO PAGE-OUT, VIO MOVEOUT, AND HIPERSPACE PAGES */
#define RCEVIOPO_OFFSET        0x64            /* TOTAL NUMBER OF VIO PAGES (EXCLUDES SWAP-OUT) MOVED-OUT OR PAGED-OUT. */
#define RCEAFC_OFFSET          0x88            /* TOTAL NUMBER OF FRAMES CURRENTLY ON ALL AVAILABLE FRAME QUEUES. */
#define RCEHSPRW_OFFSET        0x1FC           /* TOTAL NUMBER OF HIPERSPACE PAGES WRITTEN TO REAL STORAGE */


#define CSD_OFFSET                             0x294
#define CSD_CPU_ALIVE                          0x18                    /* CPU alive data on double word boundary for compare and swap */
#define CSD_CPUS_MANIPULATED_BY_WLM            0x28                    /* CSD_CPUS_MANIPULATED_BY_WLM */
#define CSD_NUMBER_ONLINE_CPUS                 0xD4                    /* 32-bit count of alive CPUs. This includes both CPs and IFAs */
#define CSD_NUMBER_ONLINE_IFAS                 0x104                   /* IFAs online */
#define CVTOSLV3_OFFSET                        0x4F3                   /* Indicates the presence of some hardware functions */
#define CVTLPARC_MASK                          0x20                    /* Mask for finding out whether the machine is part of an LPAR cluster or not */


#define CVTOPCTP_OFFSET                        0x25C                   /* ADDRESS OF SYSTEM RESOURCES MANAGER (SRM) CONTROL TABLE */
#define RMCTRCT_OFFSET                         0xE4                    /* Address of the RCT table */
#define RCVAFQA_OFFSET                         0x3C                    /* Available frame average */
#define RCVFXIOP_OFFSET                        0x80                    /* AVG % OF TOTAL FRAMES THAT ARE FIXED OR IN I/O */
#define RCVAFQC_OFFSET                         0x54                    /* Available frame accumulator */
#define RCVCTMC_OFFSET                         0x34                    /* Sample intervals count */
#define RCVCPUA_OFFSET                         0x38                    /* CPU USAGE AVERAGE */
#define RCVCPUAA_OFFSET                        0x40                    /* CP+IFA usage average */
#define RCVCPUAC_OFFSET                        0x44                    /* RCVCPUAC CP+IFA usage accumulator */
#define RCVCPUC_OFFSET                         0x4C                    /* CPU USAGE ACCUMULATOR */

#define RCVSRBS_OFFSET                         0xB8                    /* Accumulated Workload Management SRB Service for entire system. It is accumulated by WM1 and reset and used by RM3 */
#define RCVTCBS_OFFSET                         0xBC                    /* Accumulated Workload Management TCB Service for entire system. It is accumulated by WM1 and reset and used by RM3 */
#define RCTLACS_OFFSET                         0xC4                    /* Long-term average CPU service used by this logical partition, in millions of service units per hour. If this value is above the partition's defined capacity, the partition will be capped. It is calculated using the physical CPU adjustment factor (RCTPCPUA) so it may not match other measures of service which are based on the logical CPU adjustment factor. It is available if the hardware supports LPAR cluster */
#define RCTPCPUA_OFFSET                        0xD4                    /* Physical CPU adjustment factor (i.e. adjustment factor for converting CPU time to equivalent service in basic-mode with all processors online). */


typedef struct _SystemProcessorInfo
{
	unsigned long int mask_cpu_alive;               /* CSD_CPU_ALIVE */
	unsigned long int mask_cpu_wlm;                 /* CSD_CPUS_MANIPULATED_BY_WLM */
	int               online_cpus;                  /* CSD_NUMBER_ONLINE_CPUS */
	int               online_ifas;                  /* CSD_NUMBER_ONLINE_IFAS */
	int               lpar_clustering;              /* TRUE IF LPAR CLUSTERING IS PRESENT. FALSE OTHERWISE */

	short int         sample_intervals_count;       /* RCVCTMC_OFFSET */
	short int         frame_average;                /* RCVAFQA_OFFSET */
	int               frame_accumulator;            /* RCVAFQC_OFFSET */
	short int         io_fixed_percentage;          /* RCVFXIOP_OFFSET */
	short int         cpu_usage_average;            /* RCVCPUA_OFFSET */
	short int         cpu_ifa_usage_average;        /* RCVCPUAA_OFFSET */
	int               cpu_usage_accumulator;        /* RCVCPUC_OFFSET */
	int               cpu_ifa_usage_accumulator;    /* RCVCPUAC_OFFSET */

	int               srb_service;                  /* RCVSRBS_OFFSET */
	int               tcb_service;                  /* RCVTCBS_OFFSET */
	int               lpar_service;                 /* RCTLACS_OFFSET */
	double            lpar_capacity;                /* calculated     */
	int               phy_cpu_factor;               /* RCTPCPUA_OFFSET */
	double            utilization;                  /* calculated     */


} SystemProcessorInfo;

void getSystemProcessorInfo(SystemProcessorInfo *result, char * cvt)
{
	char status_word;
	char * ptr = *((char **) (cvt + CSD_OFFSET));
	result->mask_cpu_alive = *((int*) (ptr + CSD_CPU_ALIVE));
	result->mask_cpu_wlm   = *((int*) (ptr + CSD_CPUS_MANIPULATED_BY_WLM));
	result->online_cpus    = *((int*) (ptr + CSD_NUMBER_ONLINE_CPUS));
	result->online_ifas    = *((int*) (ptr + CSD_NUMBER_ONLINE_IFAS));

	status_word = *((char*) (cvt + CVTOSLV3_OFFSET));
	if (status_word & CVTLPARC_MASK) result->lpar_clustering = 1;
	else result->lpar_clustering = 0;

	ptr = *((char **) (cvt + CVTOPCTP_OFFSET));
	ptr = *((char **) (ptr + RMCTRCT_OFFSET));
	result->sample_intervals_count           = *((unsigned short int*) (ptr + RCVCTMC_OFFSET));
	result->cpu_usage_average               = *((unsigned short int*) (ptr + RCVCPUA_OFFSET));
	result->cpu_ifa_usage_average           = *((unsigned short int*) (ptr + RCVCPUAA_OFFSET));
	result->cpu_usage_accumulator           = *((int*) (ptr + RCVCPUC_OFFSET));
	result->cpu_ifa_usage_accumulator       = *((int*) (ptr + RCVCPUAC_OFFSET));

	result->frame_average                   = *((unsigned short int*) (ptr + RCVAFQA_OFFSET));
	result->frame_accumulator               = *((int*) (ptr + RCVAFQC_OFFSET));
	result->io_fixed_percentage             = *((unsigned short int*) (ptr + RCVFXIOP_OFFSET));

	result->srb_service                     = *((int*) (ptr + RCVSRBS_OFFSET));
	result->tcb_service                     = *((int*) (ptr + RCVTCBS_OFFSET));
	result->lpar_service                    = *((int*) (ptr + RCTLACS_OFFSET));
	result->phy_cpu_factor                  = *((int*) (ptr + RCTPCPUA_OFFSET));

	result->lpar_capacity                   = 16000000/result->phy_cpu_factor;
	result->lpar_capacity                   = result->lpar_capacity*(result->online_cpus + result->online_ifas);
	result->lpar_capacity                   = result->lpar_capacity*3600.0/1000000.0;
	result->utilization                     = (result->lpar_service/result->lpar_capacity)*100;
}

static int getIndividualCapabilities(char * buffer, int proc_nr)
{
	int i;
	unsigned short int cap;
	buffer += 2*proc_nr;
	memcpy(&cap,buffer,2);
	return cap;
}


static int getZOSCPUCapability(si22v1 *result, int cpu_nr)
{
	int si22v1cpucapability;
	int individual_cpucapability;
	memcpy(&(si22v1cpucapability),result->si22v1cpucapability,4);

	individual_cpucapability =  getIndividualCapabilities((char *)&(result->si22v1mpcpucapafs),cpu_nr);

	return (si22v1cpucapability + individual_cpucapability);
}


static int invokesiv1v2(siv1v2 *info)
{

	CSRSI_calltype* CSRSIC;

	CSRSIC = (CSRSI_calltype *) fetch("CSRSI"); /* load module ERBSMFI */

	if (CSRSIC == NULL)
	{
		printf("ERROR: fetch failed\n");
		return 0;
	}
	else
	{
		siv1v2 info;
		int ret_code;
		int request = CSRSI_REQUEST_V2CPC_LPAR | CSRSI_REQUEST_V1CPC_MACHINE;
		memset(&info,'\x0',sizeof(info));

		(*CSRSIC)(request,
				0x1040,
				&info,
				&ret_code);

		if (ret_code == CSRSI_BADINFOAREALEN)
		{
			memset(&info,'\x0',sizeof(info));
			(*CSRSIC)(request,
					0x2040,
					&info,
					&ret_code);
		}

		if (ret_code == CSRSI_BADINFOAREALEN)
		{
			memset(&info,'\x0',sizeof(info));
			(*CSRSIC)(request,
					0x3040,
					&info,
					&ret_code);
		}

		if (ret_code == CSRSI_BADINFOAREALEN)
		{
			memset(&info,'\x0',sizeof(info));
			(*CSRSIC)(request,
					0x4040,
					&info,
					&ret_code);
		}


		if (ret_code != CSRSI_SUCCESS)
		{
			memset(&info,'\x0',sizeof(info));
			return 0;
		}
	}

	return 1;

}

int uv__platform_loop_init(uv_loop_t* loop) {
	int fd;

	fd = uv__epoll_create1(UV__EPOLL_CLOEXEC);

	/* epoll_create1() can fail either because it's not implemented (old kernel)
	 * or because it doesn't understand the EPOLL_CLOEXEC flag.
	 */
	if (fd == -1 && (errno == ENOSYS || errno == EINVAL)) {
		fd = uv__epoll_create(256);

		if (fd != -1)
			uv__cloexec(fd, 1);
	}

	loop->backend_fd = fd;
	loop->inotify_fd = -1;
	loop->inotify_watchers = NULL;

	if (fd == -1)
		return -errno;

	return 0;
}



void uv__platform_loop_delete(uv_loop_t* loop) {
	if (loop->inotify_fd == -1) return;
	uv__io_stop(loop, &loop->inotify_read_watcher, UV__POLLIN);
	uv__close(loop->inotify_fd);
	loop->inotify_fd = -1;
}


uint64_t uv__hrtime(uv_clocktype_t type) {
	struct timeval t;
	gettimeofday(&t, NULL);
	uint64_t s = t.tv_sec ;
	s *= 1000000000;
	s += (t.tv_usec*1000);
	return s;
}


/*
 * We could use a static buffer for the path manipulations that we need outside
 * of the function, but this function could be called by multiple consumers and
 * we don't want to potentially create a race condition in the use of snprintf.
 * There is no direct way of getting the exe path in AIX - either through /procfs
 * or through some libc APIs. The below approach is to parse the argv[0]'s pattern
 * and use it in conjunction with PATH environment variable to craft one.
 */
int uv_exepath(char* buffer, size_t* size) {
	int res;
	char args[PATH_MAX];
	char abspath[PATH_MAX];
	size_t abspath_size;

	if (buffer == NULL || size == NULL || *size == 0)
		return -EINVAL;

	//pi.pi_pid = getpid();
	//res = getargs(&pi, sizeof(pi), args, sizeof(args));
	//if (res < 0) 
	//return -EINVAL;
	char *exe_path=__getenv("EXE_PATH");
	if (exe_path == NULL) 
		return -EINVAL;
	strncpy(args,  exe_path, PATH_MAX-1);

	/*
	 * Possibilities for args:
	 * i) an absolute path such as: /home/user/myprojects/nodejs/node
	 * ii) a relative path such as: ./node or ../myprojects/nodejs/node
	 * iii) a bare filename such as "node", after exporting PATH variable 
	 *     to its location.
	 */

	/* Case i) and ii) absolute or relative paths */
	if (strchr(args, '/') != NULL) {
		if (realpath(args, abspath) != abspath) 
			return -errno;

		abspath_size = strlen(abspath);

		*size -= 1;
		if (*size > abspath_size)
			*size = abspath_size;

		memcpy(buffer, abspath, *size);
		buffer[*size] = '\0';

		return 0;
	} else {
		/* Case iii). Search PATH environment variable */ 
		char trypath[PATH_MAX];
		char *clonedpath = NULL;
		char *token = NULL;
		char *path = getenv("PATH");

		if (path == NULL)
			return -EINVAL;

		clonedpath = uv__strdup(path);
		if (clonedpath == NULL)
			return -ENOMEM;

		token = strtok(clonedpath, ":");
		while (token != NULL) {
			snprintf(trypath, sizeof(trypath) - 1, "%s/%s", token, args);
			if (realpath(trypath, abspath) == abspath) { 
				/* Check the match is executable */
				if (access(abspath, X_OK) == 0) {
					abspath_size = strlen(abspath);

					*size -= 1;
					if (*size > abspath_size)
						*size = abspath_size;

					memcpy(buffer, abspath, *size);
					buffer[*size] = '\0';

					uv__free(clonedpath);
					return 0;
				}
			}
			token = strtok(NULL, ":");
		}
		uv__free(clonedpath);

		/* Out of tokens (path entries), and no match found */
		return -EINVAL;
	}
}


uint64_t uv_get_free_memory(void) {
	return -1;
}


uint64_t uv_get_total_memory(void) {
	return -1;
}


void uv_loadavg(double avg[3]) {
	avg[0] = 0;
	avg[1] = 0;
	avg[2] = 0;
}


#ifdef HAVE_SYS_AHAFS_EVPRODS_H
static char *uv__rawname(char *cp) {
	static char rawbuf[FILENAME_MAX+1];
	char *dp = rindex(cp, '/');

	if (dp == 0)
		return 0;

	*dp = 0;
	strcpy(rawbuf, cp);
	*dp = '/';
	strcat(rawbuf, "/r");
	strcat(rawbuf, dp+1);
	return rawbuf;
}


/* 
 * Determine whether given pathname is a directory
 * Returns 0 if the path is a directory, -1 if not
 *
 * Note: Opportunity here for more detailed error information but
 *       that requires changing callers of this function as well
 */
static int uv__path_is_a_directory(char* filename) {
	struct stat statbuf;

	if (stat(filename, &statbuf) < 0)
		return -1;  /* failed: not a directory, assume it is a file */

	if (S_ISDIR(statbuf.st_mode) != 0)
		return 0;

	return -1;
}


/* 
 * Check whether AHAFS is mounted.
 * Returns 0 if AHAFS is mounted, or an error code < 0 on failure
 */
static int uv__is_ahafs_mounted(void){
	int rv, i = 2;
	struct vmount *p;
	int size_multiplier = 10;
	size_t siz = sizeof(struct vmount)*size_multiplier;
	struct vmount *vmt;
	const char *dev = "/aha";
	char *obj, *stub;

	p = uv__malloc(siz);
	if (p == NULL)
		return -errno;

	/* Retrieve all mounted filesystems */
	rv = mntctl(MCTL_QUERY, siz, (char*)p);
	if (rv < 0)
		return -errno;
	if (rv == 0) {
		/* buffer was not large enough, reallocate to correct size */
		siz = *(int*)p;
		uv__free(p);
		p = uv__malloc(siz);
		if (p == NULL)
			return -errno;
		rv = mntctl(MCTL_QUERY, siz, (char*)p);
		if (rv < 0)
			return -errno;
	}

	/* Look for dev in filesystems mount info */
	for(vmt = p, i = 0; i < rv; i++) {
		obj = vmt2dataptr(vmt, VMT_OBJECT);     /* device */
		stub = vmt2dataptr(vmt, VMT_STUB);      /* mount point */

		if (EQ(obj, dev) || EQ(uv__rawname(obj), dev) || EQ(stub, dev)) {
			uv__free(p);  /* Found a match */
			return 0;
		}
		vmt = (struct vmount *) ((char *) vmt + vmt->vmt_length);
	}

	/* /aha is required for monitoring filesystem changes */
	return -1;
}

/*
 * Recursive call to mkdir() to create intermediate folders, if any
 * Returns code from mkdir call
 */
static int uv__makedir_p(const char *dir) {
	char tmp[256];
	char *p = NULL;
	size_t len;
	int err;

	snprintf(tmp, sizeof(tmp),"%s",dir);
	len = strlen(tmp);
	if (tmp[len - 1] == '/')
		tmp[len - 1] = 0;
	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			err = mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
			if(err != 0)
				return err;
			*p = '/';
		}
	}
	return mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
}

/* 
 * Creates necessary subdirectories in the AIX Event Infrastructure
 * file system for monitoring the object specified.
 * Returns code from mkdir call
 */
static int uv__make_subdirs_p(const char *filename) {
	char cmd[2048];
	char *p;
	int rc = 0;

	/* Strip off the monitor file name */
	p = strrchr(filename, '/');

	if (p == NULL)
		return 0;

	if (uv__path_is_a_directory((char*)filename) == 0) {
		sprintf(cmd, "/aha/fs/modDir.monFactory");
	} else {
		sprintf(cmd, "/aha/fs/modFile.monFactory");
	}

	strncat(cmd, filename, (p - filename));
	rc = uv__makedir_p(cmd);

	if (rc == -1 && errno != EEXIST){
		return -errno;
	}

	return rc;
}


/*
 * Checks if /aha is mounted, then proceeds to set up the monitoring
 * objects for the specified file.
 * Returns 0 on success, or an error code < 0 on failure
 */
static int uv__setup_ahafs(const char* filename, int *fd) {
	int rc = 0;
	char mon_file_write_string[RDWR_BUF_SIZE];
	char mon_file[PATH_MAX];
	int file_is_directory = 0; /* -1 == NO, 0 == YES  */

	/* Create monitor file name for object */
	file_is_directory = uv__path_is_a_directory((char*)filename);

	if (file_is_directory == 0)
		sprintf(mon_file, "/aha/fs/modDir.monFactory");
	else
		sprintf(mon_file, "/aha/fs/modFile.monFactory");

	if ((strlen(mon_file) + strlen(filename) + 5) > PATH_MAX)
		return -ENAMETOOLONG;

	/* Make the necessary subdirectories for the monitor file */
	rc = uv__make_subdirs_p(filename);
	if (rc == -1 && errno != EEXIST)
		return rc;

	strcat(mon_file, filename);
	strcat(mon_file, ".mon");

	*fd = 0; errno = 0;

	/* Open the monitor file, creating it if necessary */
	*fd = open(mon_file, O_CREAT|O_RDWR);
	if (*fd < 0)
		return -errno;

	/* Write out the monitoring specifications.
	 * In this case, we are monitoring for a state change event type
	 *    CHANGED=YES
	 * We will be waiting in select call, rather than a read:
	 *    WAIT_TYPE=WAIT_IN_SELECT
	 * We only want minimal information for files:
	 *      INFO_LVL=1
	 * For directories, we want more information to track what file
	 * caused the change
	 *      INFO_LVL=2
	 */

	if (file_is_directory == 0)
		sprintf(mon_file_write_string, "CHANGED=YES;WAIT_TYPE=WAIT_IN_SELECT;INFO_LVL=2");
	else
		sprintf(mon_file_write_string, "CHANGED=YES;WAIT_TYPE=WAIT_IN_SELECT;INFO_LVL=1");

	rc = write(*fd, mon_file_write_string, strlen(mon_file_write_string)+1);
	if (rc < 0)
		return -errno;

	return 0;
}

/*
 * Skips a specified number of lines in the buffer passed in.
 * Walks the buffer pointed to by p and attempts to skip n lines.
 * Returns the total number of lines skipped
 */
static int uv__skip_lines(char **p, int n) {
	int lines = 0;

	while(n > 0) {
		*p = strchr(*p, '\n');
		if (!p)
			return lines;

		(*p)++;
		n--;
		lines++;
	}
	return lines;
}


/*
 * Parse the event occurrence data to figure out what event just occurred
 * and take proper action.
 * 
 * The buf is a pointer to the buffer containing the event occurrence data
 * Returns 0 on success, -1 if unrecoverable error in parsing
 *
 */
static int uv__parse_data(char *buf, int *events, uv_fs_event_t* handle) {
	int    evp_rc, i;
	char   *p;
	char   filename[PATH_MAX]; /* To be used when handling directories */

	p = buf;
	*events = 0;

	/* Clean the filename buffer*/
	for(i = 0; i < PATH_MAX; i++) {
		filename[i] = 0;
	}
	i = 0;

	/* Check for BUF_WRAP */
	if (strncmp(buf, "BUF_WRAP", strlen("BUF_WRAP")) == 0) {
		assert(0 && "Buffer wrap detected, Some event occurrences lost!");
		return 0;
	}

	/* Since we are using the default buffer size (4K), and have specified
	 * INFO_LVL=1, we won't see any EVENT_OVERFLOW conditions.  Applications
	 * should check for this keyword if they are using an INFO_LVL of 2 or
	 * higher, and have a buffer size of <= 4K
	 */

	/* Skip to RC_FROM_EVPROD */
	if (uv__skip_lines(&p, 9) != 9)
		return -1;

	if (sscanf(p, "RC_FROM_EVPROD=%d\nEND_EVENT_DATA", &evp_rc) == 1) {
		if (uv__path_is_a_directory(handle->path) == 0) { /* Directory */
			if (evp_rc == AHAFS_MODDIR_UNMOUNT || evp_rc == AHAFS_MODDIR_REMOVE_SELF) {
				/* The directory is no longer available for monitoring */
				*events = UV_RENAME;
				handle->dir_filename = NULL;
			} else {
				/* A file was added/removed inside the directory */
				*events = UV_CHANGE;

				/* Get the EVPROD_INFO */
				if (uv__skip_lines(&p, 1) != 1)
					return -1;

				/* Scan out the name of the file that triggered the event*/
				if (sscanf(p, "BEGIN_EVPROD_INFO\n%sEND_EVPROD_INFO", filename) == 1) {
					handle->dir_filename = uv__strdup((const char*)&filename);
				} else
					return -1;
			}
		} else { /* Regular File */
			if (evp_rc == AHAFS_MODFILE_RENAME)
				*events = UV_RENAME;
			else
				*events = UV_CHANGE;
		}
	}
	else
		return -1;

	return 0;
}


/* This is the internal callback */
static void uv__ahafs_event(uv_loop_t* loop, uv__io_t* event_watch, unsigned int fflags) {
	char   result_data[RDWR_BUF_SIZE];
	int bytes, rc = 0;
	uv_fs_event_t* handle;
	int events = 0;
	int  i = 0;
	char fname[PATH_MAX];
	char *p;

	handle = container_of(event_watch, uv_fs_event_t, event_watcher);

	/* Clean all the buffers*/
	for(i = 0; i < PATH_MAX; i++) {
		fname[i] = 0;
	}
	i = 0;

	/* At this point, we assume that polling has been done on the
	 * file descriptor, so we can just read the AHAFS event occurrence
	 * data and parse its results without having to block anything
	 */
	bytes = pread(event_watch->fd, result_data, RDWR_BUF_SIZE, 0);

	assert((bytes <= 0) && "uv__ahafs_event - Error reading monitor file");

	/* Parse the data */
	if(bytes > 0)
		rc = uv__parse_data(result_data, &events, handle);

	/* For directory changes, the name of the files that triggered the change
	 * are never absolute pathnames
	 */
	if (uv__path_is_a_directory(handle->path) == 0) {
		p = handle->dir_filename;
		while(*p != NULL){
			fname[i]= *p;
			i++;
			p++;
		}
	} else {
		/* For file changes, figure out whether filename is absolute or not */
		if (handle->path[0] == '/') {
			p = strrchr(handle->path, '/');
			p++;

			while(*p != NULL) {
				fname[i]= *p;
				i++;
				p++;
			}
		}
	}

	/* Unrecoverable error */
	if (rc == -1)
		return;
	else /* Call the actual JavaScript callback function */
		handle->cb(handle, (const char*)&fname, events, 0);
}
#endif


int uv_fs_event_init(uv_loop_t* loop, uv_fs_event_t* handle) {
	uv__handle_init(loop, (uv_handle_t*)handle, UV_FS_EVENT);
	return 0;
}


int uv_fs_event_start(uv_fs_event_t* handle,
		uv_fs_event_cb cb,
		const char* filename,
		unsigned int flags) {
#ifdef HAVE_SYS_AHAFS_EVPRODS_H
	int  fd, rc, i = 0, res = 0;
	char cwd[PATH_MAX];
	char absolute_path[PATH_MAX];
	char fname[PATH_MAX];
	char *p;

	/* Clean all the buffers*/
	for(i = 0; i < PATH_MAX; i++) {
		cwd[i] = 0;
		absolute_path[i] = 0;
		fname[i] = 0;
	}
	i = 0;

	/* Figure out whether filename is absolute or not */
	if (filename[0] == '/') {
		/* We have absolute pathname, create the relative pathname*/
		sprintf(absolute_path, filename);
		p = strrchr(filename, '/');
		p++;
	} else {
		if (filename[0] == '.' && filename[1] == '/') {
			/* We have a relative pathname, compose the absolute pathname */
			sprintf(fname, filename);
			snprintf(cwd, PATH_MAX-1, "/proc/%lu/cwd", (unsigned long) getpid());
			res = readlink(cwd, absolute_path, sizeof(absolute_path) - 1);
			if (res < 0)
				return res;
			p = strrchr(absolute_path, '/');
			p++;
			p++;
		} else {
			/* We have a relative pathname, compose the absolute pathname */
			sprintf(fname, filename);
			snprintf(cwd, PATH_MAX-1, "/proc/%lu/cwd", (unsigned long) getpid());
			res = readlink(cwd, absolute_path, sizeof(absolute_path) - 1);
			if (res < 0)
				return res;
			p = strrchr(absolute_path, '/');
			p++;
		}
		/* Copy to filename buffer */
		while(filename[i] != NULL) {
			*p = filename[i];
			i++;
			p++;
		}
	}

	if (uv__is_ahafs_mounted() < 0)  /* /aha checks failed */
		return UV_ENOSYS;

	/* Setup ahafs */
	rc = uv__setup_ahafs((const char *)absolute_path, &fd);
	if (rc != 0)
		return rc;

	/* Setup/Initialize all the libuv routines */
	uv__handle_start(handle);
	uv__io_init(&handle->event_watcher, uv__ahafs_event, fd);
	handle->path = uv__strdup((const char*)&absolute_path);
	handle->cb = cb;

	uv__io_start(handle->loop, &handle->event_watcher, UV__POLLIN);

	return 0;
#else
	return -ENOSYS;
#endif
}


int uv_fs_event_stop(uv_fs_event_t* handle) {
#ifdef HAVE_SYS_AHAFS_EVPRODS_H
	if (!uv__is_active(handle))
		return 0;

	uv__io_close(handle->loop, &handle->event_watcher);
	uv__handle_stop(handle);

	if (uv__path_is_a_directory(handle->path) == 0) {
		uv__free(handle->dir_filename);
		handle->dir_filename = NULL;
	}

	uv__free(handle->path);
	handle->path = NULL;
	uv__close(handle->event_watcher.fd);
	handle->event_watcher.fd = -1;

	return 0;
#else
	return -ENOSYS;
#endif
}


void uv__fs_event_close(uv_fs_event_t* handle) {
#ifdef HAVE_SYS_AHAFS_EVPRODS_H
	uv_fs_event_stop(handle);
#else
	UNREACHABLE();
#endif
}


char** uv_setup_args(int argc, char** argv) {
	return argv;
}


int uv_set_process_title(const char* title) {
	return 0;
}


int uv_get_process_title(char* buffer, size_t size) {
	if (size > 0) {
		buffer[0] = '\0';
	}
	return 0;
}


int uv_resident_set_memory(size_t* rss) {

	return -EINVAL;
}


int uv_uptime(double* uptime) {
	struct utmpx u ;
	u.ut_type = BOOT_TIME;
	struct utmpx *v;
	v = getutxid(&u);
	if (v==NULL)
		return -1;
	time64_t t;
	*uptime = difftime64( time64(&t), v->ut_tv.tv_sec);
	return 0;
}


int uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count) {
	uv_cpu_info_t* cpu_info;
	int result, ncpus, idx = 0;


	siv1v2 info;
	char *cvt = *CVT_PTR;
	SystemProcessorInfo zos_proc;
	getSystemProcessorInfo(&zos_proc, cvt);
	if (!invokesiv1v2(&info))
		return -ENOSYS;

	*count = ncpus = zos_proc.online_cpus;

	*cpu_infos = (uv_cpu_info_t*) uv__malloc(ncpus * sizeof(uv_cpu_info_t));
	if (!*cpu_infos) {
		return -ENOMEM;
	}


	cpu_info = *cpu_infos;
	while (idx < ncpus) {

		cpu_info->speed = (int)(getZOSCPUCapability(&(info.siv1v2si22v1),idx) / 1000000);
		cpu_info->model = "ec12";
		cpu_info->cpu_times.user = 0;
		cpu_info->cpu_times.sys = 0;
		cpu_info->cpu_times.idle = 0;
		cpu_info->cpu_times.irq = 0;
		cpu_info->cpu_times.nice = 0;
		cpu_info++;
		idx++;
	}

	return 0;
}


void uv_free_cpu_info(uv_cpu_info_t* cpu_infos, int count) {
	int i;

	for (i = 0; i < count; ++i) {
		uv__free(cpu_infos[i].model);
	}

	uv__free(cpu_infos);
}


int uv_interface_addresses(uv_interface_address_t** addresses,
		int* count) {
	uv_interface_address_t* address;
	int sockfd, size = 1;
	struct ifconf ifc;
	struct ifreq *ifr, *p, flg;

	*count = 0;

	if (0 > (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))) {
		return -errno;
	}

	ifc.ifc_req = (struct ifreq*)uv__malloc(size);
	ifc.ifc_len = 16384;

#define MAX(a,b) (((a)>(b))?(a):(b))
#define ADDR_SIZE(p) MAX((p).sa_len, sizeof(p))

	/* Count all up and running ipv4/ipv6 addresses */
	ifr = ifc.ifc_req;
	while ((char*)ifr < (char*)ifc.ifc_req + ifc.ifc_len) {
		p = ifr;
		ifr = (struct ifreq*)
			((char*)ifr + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

		if (!(p->ifr_addr.sa_family == AF_INET6 ||
					p->ifr_addr.sa_family == AF_INET))
			continue;

		memcpy(flg.ifr_name, p->ifr_name, sizeof(flg.ifr_name));
		if (ioctl(sockfd, SIOCGIFFLAGS, &flg) == -1) {
			SAVE_ERRNO(uv__close(sockfd));
			return -errno;
		}

		if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
			continue;

		(*count)++;
	}

	/* Alloc the return interface structs */
	*addresses = (uv_interface_address_t*)
		uv__malloc(*count * sizeof(uv_interface_address_t));
	if (!(*addresses)) {
		uv__close(sockfd);
		return -ENOMEM;
	}
	address = *addresses;

	ifr = ifc.ifc_req;
	while ((char*)ifr < (char*)ifc.ifc_req + ifc.ifc_len) {
		p = ifr;
		ifr = (struct ifreq*)
			((char*)ifr + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

		if (!(p->ifr_addr.sa_family == AF_INET6 ||
					p->ifr_addr.sa_family == AF_INET))
			continue;

		memcpy(flg.ifr_name, p->ifr_name, sizeof(flg.ifr_name));
		if (ioctl(sockfd, SIOCGIFFLAGS, &flg) == -1) {
			uv__close(sockfd);
			return -ENOSYS;
		}

		if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
			continue;

		/* All conditions above must match count loop */

		address->name = uv__strdup(p->ifr_name);

		if (p->ifr_addr.sa_family == AF_INET6) {
			address->address.address6 = *((struct sockaddr_in6*) &p->ifr_addr);
		} else {
			address->address.address4 = *((struct sockaddr_in*) &p->ifr_addr);
		}

		/* TODO: Retrieve netmask using SIOCGIFNETMASK ioctl */

		address->is_internal = flg.ifr_flags & IFF_LOOPBACK ? 1 : 0;

		address++;
	}

#undef ADDR_SIZE

	uv__close(sockfd);
	return 0;
}


void uv_free_interface_addresses(uv_interface_address_t* addresses,
		int count) {
	int i;

	for (i = 0; i < count; ++i) {
		uv__free(addresses[i].name);
	}

	uv__free(addresses);
}

void uv__platform_invalidate_fd(uv_loop_t* loop, int fd) {
	struct uv__epoll_event* events;
	struct uv__epoll_event dummy;
	uintptr_t i;
	uintptr_t nfds;

	assert(loop->watchers != NULL);

	events = (struct uv__epoll_event*) loop->watchers[loop->nwatchers];
	nfds = (uintptr_t) loop->watchers[loop->nwatchers + 1];
	if (events != NULL)
		/* Invalidate events with same file descriptor */
		for (i = 0; i < nfds; i++)
			if ((int) events[i].data == fd)
				events[i].data = -1;

	/* Remove the file descriptor from the epoll.
	 * This avoids a problem where the same file description remains open
	 * in another process, causing repeated junk epoll events.
	 *
	 * We pass in a dummy epoll_event, to work around a bug in old kernels.
	 */
	if (loop->backend_fd >= 0) {
		/* Work around a bug in kernels 3.10 to 3.19 where passing a struct that
		 * has the EPOLLWAKEUP flag set generates spurious audit syslog warnings.
		 */
		memset(&dummy, 0, sizeof(dummy));
		uv__epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_DEL, fd, &dummy);
	}
}

void uv__io_poll(uv_loop_t* loop, int timeout) {
	/* A bug in kernels < 2.6.37 makes timeouts larger than ~30 minutes
	 * effectively infinite on 32 bits architectures.  To avoid blocking
	 * indefinitely, we cap the timeout and poll again if necessary.
	 *
	 * Note that "30 minutes" is a simplification because it depends on
	 * the value of CONFIG_HZ.  The magic constant assumes CONFIG_HZ=1200,
	 * that being the largest value I have seen in the wild (and only once.)
	 */
	static const int max_safe_timeout = 1789569;
	static int no_epoll_pwait;
	static int no_epoll_wait;
	struct uv__epoll_event events[1024];
	struct uv__epoll_event* pe;
	struct uv__epoll_event e;
	int real_timeout;
	QUEUE* q;
	uv__io_t* w;
	sigset_t sigset;
	uint64_t sigmask;
	uint64_t base;
	int nevents;
	int count;
	int nfds;
	int fd;
	int op;
	int i;

	if (loop->nfds == 0) {
		assert(QUEUE_EMPTY(&loop->watcher_queue));
		return;
	}

	while (!QUEUE_EMPTY(&loop->watcher_queue)) {
		q = QUEUE_HEAD(&loop->watcher_queue);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);

		w = QUEUE_DATA(q, uv__io_t, watcher_queue);
		assert(w->pevents != 0);
		assert(w->fd >= 0);
		assert(w->fd < (int) loop->nwatchers);

		e.events = w->pevents;
		e.data = w->fd;

		//printf("JBAR executing watcher_queue fd=%d\n", e.data);

		if (w->events == 0)
			op = UV__EPOLL_CTL_ADD;
		else
			op = UV__EPOLL_CTL_MOD;

		/* XXX Future optimization: do EPOLL_CTL_MOD lazily if we stop watching
		 * events, skip the syscall and squelch the events after epoll_wait().
		 */
		if (uv__epoll_ctl(loop->backend_fd, op, w->fd, &e)) {
			if (errno != EEXIST)
				abort();

			assert(op == UV__EPOLL_CTL_ADD);

			/* We've reactivated a file descriptor that's been watched before. */
			if (uv__epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_MOD, w->fd, &e))
				abort();
		}

		w->events = w->pevents;
	}

	sigmask = 0;
	if (loop->flags & UV_LOOP_BLOCK_SIGPROF) {
		sigemptyset(&sigset);
		sigaddset(&sigset, SIGPROF);
		sigmask |= 1 << (SIGPROF - 1);
	}

	assert(timeout >= -1);
	base = loop->time;
	count = 48; /* Benchmarks suggest this gives the best throughput. */
	real_timeout = timeout;

	for (;;) {
		/* See the comment for max_safe_timeout for an explanation of why
		 * this is necessary.  Executive summary: kernel bug workaround.
		 */
		if (sizeof(int32_t) == sizeof(long) && timeout >= max_safe_timeout)
			timeout = max_safe_timeout;

		if (sigmask != 0 && no_epoll_pwait != 0)
			if (pthread_sigmask(SIG_BLOCK, &sigset, NULL))
				abort();

		if (no_epoll_wait != 0 || (sigmask != 0 && no_epoll_pwait == 0)) {
			nfds = uv__epoll_pwait(loop->backend_fd,
					events,
					ARRAY_SIZE(events),
					timeout,
					sigmask);
			if (nfds == -1 && errno == ENOSYS)
				no_epoll_pwait = 1;
		} else {
			nfds = uv__epoll_wait(loop->backend_fd,
					events,
					ARRAY_SIZE(events),
					timeout);
			if (nfds == -1 && errno == ENOSYS)
				no_epoll_wait = 1;
		}

		if (sigmask != 0 && no_epoll_pwait != 0)
			if (pthread_sigmask(SIG_UNBLOCK, &sigset, NULL))
				abort();

		/* Update loop->time unconditionally. It's tempting to skip the update when
		 * timeout == 0 (i.e. non-blocking poll) but there is no guarantee that the
		 * operating system didn't reschedule our process while in the syscall.
		 */
		SAVE_ERRNO(uv__update_time(loop));

		if (nfds == 0) {
			assert(timeout != -1);

			timeout = real_timeout - timeout;
			if (timeout > 0)
				continue;

			return;
		}

		if (nfds == -1) {
			if (errno == ENOSYS) {
				/* epoll_wait() or epoll_pwait() failed, try the other system call. */
				assert(no_epoll_wait == 0 || no_epoll_pwait == 0);
				continue;
			}

			if (errno != EINTR)
				abort();

			if (timeout == -1)
				continue;

			if (timeout == 0)
				return;

			/* Interrupted by a signal. Update timeout and poll again. */
			goto update_timeout;
		}

		nevents = 0;

		assert(loop->watchers != NULL);
		loop->watchers[loop->nwatchers] = (void*) events;
		loop->watchers[loop->nwatchers + 1] = (void*) (uintptr_t) nfds;
		for (i = 0; i < nfds; i++) {
			pe = events + i;
			fd = pe->data;

			/* Skip invalidated events, see uv__platform_invalidate_fd */
			if (fd == -1)
				continue;

			assert(fd >= 0);
			assert((unsigned) fd < loop->nwatchers);

			w = loop->watchers[fd];

			if (w == NULL) {
				/* File descriptor that we've stopped watching, disarm it.
				 *
				 * Ignore all errors because we may be racing with another thread
				 * when the file descriptor is closed.
				 */
				uv__epoll_ctl(loop->backend_fd, UV__EPOLL_CTL_DEL, fd, pe);
				continue;
			}

			/* Give users only events they're interested in. Prevents spurious
			 * callbacks when previous callback invocation in this loop has stopped
			 * the current watcher. Also, filters out events that users has not
			 * requested us to watch.
			 */
			pe->events &= w->pevents | UV__POLLERR | UV__POLLHUP;

			/* Work around an epoll quirk where it sometimes reports just the
			 * EPOLLERR or EPOLLHUP event.  In order to force the event loop to
			 * move forward, we merge in the read/write events that the watcher
			 * is interested in; uv__read() and uv__write() will then deal with
			 * the error or hangup in the usual fashion.
			 *
			 * Note to self: happens when epoll reports EPOLLIN|EPOLLHUP, the user
			 * reads the available data, calls uv_read_stop(), then sometime later
			 * calls uv_read_start() again.  By then, libuv has forgotten about the
			 * hangup and the kernel won't report EPOLLIN again because there's
			 * nothing left to read.  If anything, libuv is to blame here.  The
			 * current hack is just a quick bandaid; to properly fix it, libuv
			 * needs to remember the error/hangup event.  We should get that for
			 * free when we switch over to edge-triggered I/O.
			 */
			if (pe->events == UV__EPOLLERR || pe->events == UV__EPOLLHUP)
				pe->events |= w->pevents & (UV__EPOLLIN | UV__EPOLLOUT);

			if (pe->events != 0) {
				w->cb(loop, w, pe->events);
				nevents++;
			}
		}
		loop->watchers[loop->nwatchers] = NULL;
		loop->watchers[loop->nwatchers + 1] = NULL;

		if (nevents != 0) {
			if (nfds == ARRAY_SIZE(events) && --count != 0) {
				/* Poll for more events but don't block this time. */
				timeout = 0;
				continue;
			}
			return;
		}

		if (timeout == 0)
			return;

		if (timeout == -1)
			continue;

update_timeout:
		assert(timeout > 0);

		real_timeout -= (loop->time - base);
		if (real_timeout <= 0)
			return;

		timeout = real_timeout;
	}
}
