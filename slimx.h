#ifndef LISTENER_H
#define LISTENER_H

#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/ktime.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <asm/atomic.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/cdev.h>	
#include <linux/audit.h>
#include <linux/list.h>
#include <linux/sched/signal.h>
#include <linux/jiffies.h> //jiffies
#include <asm/param.h> //HZ
#define DEBUG_MODE 1

//--------netfilter hook
/* Install Netfilter hooks */
extern bool nf_cpt_init(void);
/* Uninstall Netfilter hooks */
extern void nf_cpt_exit(void);


//--------ioctl 
#define SLIMX_SET 1003200
#define SLIMX_GET 1003201
#define SLIMX_DEL 1003202
typedef struct{
	atomic_t available;
	struct semaphore sem;
	struct cdev cdev;
} pkg_info_dev;

typedef struct{
	u32 dst_ip;
	u16 dst_port;
	u16 src_port;
	u64 pkg_num;
} slimx_get_arg;

typedef struct{
	u32 dst_ip;
	u16 dst_port;
	u16 src_port;
} slimx_set_arg;

typedef struct{
	u32 dst_ip;
	u16 dst_port;
	u16 src_port;
} slimx_del_arg;

int pkg_info_open(struct inode *inode, struct file *filp);
int pkg_info_release(struct inode *inode, struct file *filp);
long pkg_info_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

//-------hashtable-----
#define SLIMX_LISTEN_BUCKETS 2048
typedef struct{
	u32 dst_ip;
	u16 dst_port;
	u16 src_port;
	u64 cur_pkg;
	u64 cur_second;
	u64 lst_pkg;
	u64 lst_second;
	
} slimx_coninfo;

typedef struct {
	struct mutex write_lock;
	struct hlist_head buckets[SLIMX_LISTEN_BUCKETS];
}slimx_conhtable;

typedef struct {
	/* Must be the first element of the struct! */
	struct hlist_node hash_links;
	slimx_coninfo *con;
}slimx_connode;

static inline int slimx_target_hash(__u32 remote_ip,__u16 remote_port)
{
	// int result=(remote_ip+remote_port) & (SLIMX_LISTEN_BUCKETS - 1);
	// printk(KERN_INFO "HASH:%d",result);
	// return result;
	return (remote_ip+remote_port) & (SLIMX_LISTEN_BUCKETS - 1);
}

typedef struct{
	slimx_conhtable contab;
}Slimx;





#endif