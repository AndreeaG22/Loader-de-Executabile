/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include "exec_parser.h"
#include <unistd.h>
#include <fcntl.h>
static so_exec_t *exec;
static int fd;

so_seg_t *verify_segments(siginfo_t *info, int signum)
{

	so_seg_t *segment;
	so_seg_t *array_of_segments = exec->segments;
	void *fault_address = info->si_addr;

	for (int i = 0; i < exec->segments_no; i++) {
		segment = &array_of_segments[i];
		void *beginning_of_segment = (void *)segment->vaddr;
		void *end_of_segment = beginning_of_segment + segment->mem_size;

		if (beginning_of_segment <= fault_address && fault_address <= end_of_segment)
			return segment;
	}
	return NULL;
}

void write_into_memory(so_seg_t *fault_segment, void *map_result, int len, int index)
{

	if (lseek(fd, fault_segment->offset + index, SEEK_SET) < 0) {
		perror("lseek");
		exit(-1);
	}
	if (read(fd, map_result, len) < 0) {
		perror("read");
		exit(-1);
	}
	int page_size = getpagesize();

	if (mprotect(map_result, page_size, fault_segment->perm) < 0) {
		perror("mprotect");
		exit(-1);
	}
}

void * page_map(so_seg_t *fault_segment, siginfo_t *info)
{

	void *segment_beginning = (void *)fault_segment->vaddr;
	int page_size = getpagesize();
	void *fault_address = info->si_addr;
	int page_index = (fault_address - segment_beginning) / page_size;
	int index = page_index * page_size;
	void *map_address = segment_beginning + index;

	char *map_result = mmap(map_address, page_size, PROT_WRITE, MAP_ANON | MAP_SHARED | MAP_FIXED, -1, 0);

	if (map_result == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	void *file_address = segment_beginning + fault_segment->file_size;
	int len = page_size;

	len = (map_address + len) > file_address ? map_address < file_address ? (file_address - map_address) : 0 : page_size;

	write_into_memory(fault_segment, map_result, len, index);

	((int *)fault_segment->data)[page_index] = 1;

	return NULL;
}


static void segv_handler(int signum, siginfo_t *info, void *context)
{
	/* actual loader implementation */
	if (signum != SIGSEGV) {
		signal(signum, SIG_DFL);
		return;
	}


	so_seg_t *fault_segment = verify_segments(info, signum);
	int page_size = getpagesize();
	int page_index = ((int)info->si_addr - (int)fault_segment->vaddr) / page_size;

	if (fault_segment->data == NULL) {
		fault_segment->data = malloc(sizeof(int) * fault_segment->mem_size / page_size);
		memset(fault_segment->data, 0, sizeof(int) * fault_segment->mem_size / page_size);
	}
	if (((int *)(fault_segment->data))[page_index] == 1) {
		signal(signum, SIG_DFL);
		return;
	}
	if (fault_segment == NULL) {
		signal(signum, SIG_DFL);
		return;
	}
	page_map(fault_segment, info);
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return fd;
	so_start_exec(exec, argv);
	close(fd);
	return -1;
}
