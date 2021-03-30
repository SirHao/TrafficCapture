#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <sys/time.h>

inline static uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
    return (((uint64_t) hi << 32) | lo);
}

double get_cycles_per_sec() {
    static double cps = 0;
    if (cps != 0) {
        return cps;
    }

    struct timeval start_time, stop_time;
    uint64_t start_cycles, stop_cycles, micros;
    double old_cps;


    old_cps = 0;
    while (1) {
        if (gettimeofday(&start_time, NULL) != 0) {
            printf("count_cycles_per_sec couldn't read clock: %s",
                   strerror(errno));

            exit(1);
        }
        start_cycles = rdtsc();
        while (1) {
            if (gettimeofday(&stop_time, NULL) != 0) {
                printf("count_cycles_per_sec couldn't read clock: %s",
                       strerror(errno));
                exit(1);
            }
            stop_cycles = rdtsc();
            micros = (stop_time.tv_usec - start_time.tv_usec) +
                     (stop_time.tv_sec - start_time.tv_sec) * 1000000;
            if (micros > 10000) {
                cps = (double) (stop_cycles - start_cycles);
                cps = 1000000.0 * cps / (double) (micros);
                break;
            }
        }
        double delta = cps / 1000.0;
        if ((old_cps > (cps - delta)) && (old_cps < (cps + delta))) {
            return cps;
        }
        old_cps = cps;
    }
}

double to_seconds(uint64_t cycles) {
    return ((double) (cycles)) / get_cycles_per_sec();
}


#define SLIMX_SET 1003200
#define SLIMX_GET 1003201
#define SLIMX_DEL 1003202



typedef struct{
	__u32 dst_ip;
	__u16 dst_port;
	__u16 src_port;
	unsigned long pkg_num;
} slimx_get_arg;

typedef struct{
	__u32 dst_ip;
	__u16 dst_port;
	__u16 src_port;
} slimx_set_arg;

typedef struct{
	__u32 dst_ip;
	__u16 dst_port;
	__u16 src_port;
} slimx_del_arg;

#define IOCTL_DRIVER_NAME "/dev/slimx"

int open_driver(const char* driver_name);
void close_driver(const char* driver_name, int fd_driver);

int open_driver(const char* driver_name) {

    printf("* Open Driver\n");

    int fd_driver = open(driver_name, O_RDWR);
    if (fd_driver == -1) {
        printf("ERROR: could not open \"%s\".\n", driver_name);
        printf("    errno = %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

	return fd_driver;
}

void close_driver(const char* driver_name, int fd_driver) {

    printf("* Close Driver\n");

    int result = close(fd_driver);
    if (result == -1) {
        printf("ERROR: could not close \"%s\".\n", driver_name);
        printf("    errno = %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}


int main(void) {
    __u32 dst_ip=16777343;
	__u16 dst_port=8888;
	__u16 src_port=55190;


    int fd_ioctl = open_driver(IOCTL_DRIVER_NAME);
    slimx_set_arg slimx_set_req;
    slimx_set_req.src_port=src_port;
    slimx_set_req.dst_ip=dst_ip;
    slimx_set_req.dst_port=dst_port;

    uint64_t start, dur;
    int ret=0;


    start = rdtsc();
    ret=ioctl(fd_ioctl, SLIMX_SET, &slimx_set_req);
    dur=rdtsc()-start;
    double average = to_seconds(dur);
    printf("[00]:%8.2f\n", average * 1e06);


	if ( ret< 0) {
			perror("Error ioctl PL_AXI_DMA_set_NUM_DEVICES");
			exit(EXIT_FAILURE);
	}
    sleep(3);

    slimx_get_arg slimx_get_req;
    slimx_get_req.src_port=src_port;
    slimx_get_req.dst_ip=dst_ip;
    slimx_get_req.dst_port=dst_port;
    while(1){
        start = rdtsc();
        ret=ioctl(fd_ioctl, SLIMX_GET, &slimx_get_req);
        dur=rdtsc()-start;
        average = to_seconds(dur);
        if ( ret < 0) {
			perror("Error ioctl PL_AXI_DMA_set_NUM_DEVICES");
			exit(EXIT_FAILURE);
	    }
        printf("the packge num:%lu and time cost is %8.2fus\n",slimx_get_req.pkg_num,average);
        sleep(2);
    }
    

  

  

	return EXIT_SUCCESS;
}


