#include "slimx.h"
Slimx slimx;







//===========slimx htable========


void slimx_con_init(slimx_conhtable *conhtable)
{
	int i;
	mutex_init(&conhtable->write_lock);
	for (i = 0; i < SLIMX_LISTEN_BUCKETS; i++) {
		INIT_HLIST_HEAD(&conhtable->buckets[i]);
	}
	printk(KERN_INFO "[hashtable init]init suc\n");
}

slimx_coninfo *slimx_con_find(slimx_conhtable *contab, __u32 rip, __u16 rport, __u16 sport)
{
	slimx_connode *node;
	slimx_coninfo *result = NULL;
	hlist_for_each_entry(node, &contab->buckets[slimx_target_hash(rip,rport)],hash_links) {
		slimx_coninfo *cur=node->con;
		if ((cur->dst_ip == rip) && (cur->dst_port == rport) &&(cur->src_port==sport)) {
			result = cur;
			break;
		}
		
	}
	return result;
}
int slimx_con_update(slimx_conhtable *contab, __u32 rip, __u16 rport,__u32 sip, __u16 sport)
{
	slimx_connode *node;
	int result=-1;
	hlist_for_each_entry_rcu(node, &contab->buckets[slimx_target_hash(rip,rport)],hash_links) {
		slimx_coninfo *cur=node->con;
		if ((cur->dst_ip == rip) && (cur->dst_port == rport) &&(cur->src_port==sport)) {
			printk(KERN_INFO "[slimx update]find this con %llu %llu %llu %llu\n",cur->lst_pkg,cur->lst_second,cur->cur_pkg,cur->cur_second);
			if((jiffies-cur->cur_second) > HZ){
				cur->lst_pkg=cur->cur_pkg;
				cur->lst_second=cur->cur_second;
				cur->cur_pkg=0;
				cur->cur_second=jiffies;
				result=1;
			}else{
				cur->cur_pkg=cur->cur_pkg+1;
				result=2;
			}
			break;
		}
		
	}
	return result;
}



int slimx_con_add(slimx_conhtable *contab,slimx_connode* node)
{
	slimx_coninfo *exist_info=slimx_con_find(contab,node->con->dst_ip,node->con->dst_port,node->con->src_port);
	if(exist_info){
		printk(KERN_INFO "[slimx_con_add]warn:exist a info and can not add again!\n");
		return -1;
	}else{
		hlist_add_head_rcu(&node->hash_links, &contab->buckets[slimx_target_hash(node->con->dst_ip,node->con->dst_port)]);
		printk(KERN_INFO "[slimx_con_add]add a con!\n");
		return 0;
	}
}
int slimx_con_del(slimx_conhtable *contab, __u32 rip, __u16 rport, __u16 sport)
{
	slimx_connode *node;
	int result=-1;
	hlist_for_each_entry(node, &contab->buckets[slimx_target_hash(rip,rport)],hash_links) {
		slimx_coninfo *con = node->con;
		if ((con->dst_ip == rip) && (con->dst_port == rport) &&(con->src_port==sport)) {
			
			hlist_del_rcu(&node->hash_links);
			result=1;
			break;
		}
	}
	if (result>0){
		printk(KERN_INFO "[slimx_con_del] find and del\n");
	}else{
		printk(KERN_INFO "[slimx_con_del] warn:nothing to del\n");
	}
	return result;
}



//============util code===============
void count_trans_packet(struct sk_buff *skb){
    struct iphdr *iph = NULL;       //IP  header
    struct tcphdr *tcph = NULL;     //TCP header 
    u32 local_ip;       //Local IP address
    u32 remote_ip;      //Remote IP address
    u16 local_port;     //Local TCP port
    u16 remote_port;    //Remote TCP port
	int result;

    iph = ip_hdr(skb);
    if (unlikely(!iph)) return ;
    else if (iph->protocol == IPPROTO_TCP){
        tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
        local_ip = iph->saddr;
        remote_ip = iph->daddr;
        local_port = (u16)ntohs(tcph->source);
        remote_port = (u16)ntohs(tcph->dest);

#ifdef  DEBUG_MODE       
        printk(KERN_INFO "[pkgcpt]  packet info: src %u:%hu ||| dst %u:%hu\n",local_ip,local_port,remote_ip,remote_port);
#endif 
		result=slimx_con_update(&slimx.contab,remote_ip,remote_port,local_ip,local_port);
		
    }
}


//===========netfilter hook===========

static struct nf_hook_ops nf_hook_pakcet_out;
static struct nf_hook_ops nf_hook_pakcet_in;


unsigned int nf_pakcet_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (!(state->out))
        return NF_ACCEPT;
    count_trans_packet(skb);
    
    return NF_ACCEPT;
}

/* Hook function for incoming packets */
unsigned int nf_pakcet_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (!(state->out))
        return NF_ACCEPT;
    count_trans_packet(skb);
    
    return NF_ACCEPT;
}

/* Install Netfilter hooks. Return true if it succeeds */
bool nf_cpt_init(void)
{
    nf_hook_pakcet_out.hook = nf_pakcet_out;
    nf_hook_pakcet_out.hooknum = NF_INET_POST_ROUTING;
    nf_hook_pakcet_out.pf = PF_INET;
    nf_hook_pakcet_out.priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, &nf_hook_pakcet_out))
    {
        printk(KERN_INFO "Cannot register Netfilter hook at NF_INET_POST_ROUTING\n");
        return false;
    }

    //Register incoming Netfilter hook
    nf_hook_pakcet_in.hook = nf_pakcet_in;
    nf_hook_pakcet_in.hooknum = NF_INET_PRE_ROUTING;
    nf_hook_pakcet_in.pf = PF_INET;
    nf_hook_pakcet_in.priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, &nf_hook_pakcet_in))
    {
        printk(KERN_INFO "Cannot register Netfilter hook at NF_INET_PRE_ROUTING\n");
        return false;
    }

    return true;
}

/* Uninstall Netfilter hooks */
void nf_cpt_exit(void)
{
    nf_unregister_net_hook(&init_net, &nf_hook_pakcet_in);
    nf_unregister_net_hook(&init_net, &nf_hook_pakcet_out);
}






//=======ioctl  with user========

/* store the major number extracted by dev_t */
int pkg_info_major = 0;
int pkg_info_minor = 0;

#define DEVICE_NAME "slimx"
char* pkg_info_name = DEVICE_NAME;

pkg_info_dev pkg_info;

struct file_operations pkg_info_fops = {
	.owner = THIS_MODULE,
	.read = NULL,
	.write = NULL,
	.open = pkg_info_open,
	.unlocked_ioctl = pkg_info_ioctl,
	.release = pkg_info_release
};

/* Private API */
static int pkg_info_dev_init(pkg_info_dev* pkg_info);
static void pkg_info_dev_del(pkg_info_dev* pkg_info);
static int pkg_info_setup_cdev(pkg_info_dev* pkg_info);

static bool pkg_info_init(void);
static void pkg_info_exit(void);

static int pkg_info_dev_init(pkg_info_dev * pkg_info)
{
	int result = 0;
	memset(pkg_info, 0, sizeof(pkg_info_dev));
	atomic_set(&pkg_info->available, 1);
	sema_init(&pkg_info->sem, 1);

	return result;
}

static void pkg_info_dev_del(pkg_info_dev * pkg_info) {}

static int pkg_info_setup_cdev(pkg_info_dev * pkg_info)
{
  int error = 0;
	dev_t devno = MKDEV(pkg_info_major, pkg_info_minor);

	cdev_init(&pkg_info->cdev, &pkg_info_fops);
	pkg_info->cdev.owner = THIS_MODULE;
	pkg_info->cdev.ops = &pkg_info_fops;
	error = cdev_add(&pkg_info->cdev, devno, 1);

	return error;
}

static bool pkg_info_init(void)
{
	dev_t           devno = 0;
	int             result = 0;

	result=pkg_info_dev_init(&pkg_info);


	/* register char device
	 * we will get the major number dynamically this is recommended see
	 * book : ldd3
	 */
	result = alloc_chrdev_region(&devno, pkg_info_minor, 1, pkg_info_name);
	pkg_info_major = MAJOR(devno);
	if (result < 0) {
		printk(KERN_WARNING "[pkg_info] can't get major number %d\n", pkg_info_major);
		goto fail;
	}

	result = pkg_info_setup_cdev(&pkg_info);
	if (result < 0) {
		printk(KERN_WARNING "[pkg_info] error %d adding pkg_info", result);
		goto fail;
	}

	printk(KERN_INFO "[pkg_info] module loaded\n");
	return true;

fail:
	pkg_info_exit();
	return false;
}

static void pkg_info_exit(void)
{
	dev_t devno = MKDEV(pkg_info_major, pkg_info_minor);

	cdev_del(&pkg_info.cdev);
	unregister_chrdev_region(devno, 1);
	pkg_info_dev_del(&pkg_info);

	printk(KERN_INFO "[pkg_info] module unloaded\n");
}

/* Public API */
int pkg_info_open(struct inode *inode, struct file *filp)
{
	pkg_info_dev *pkg_info;

	pkg_info = container_of(inode->i_cdev, pkg_info_dev, cdev);
	filp->private_data = pkg_info;

	if (!atomic_dec_and_test(&pkg_info->available)) {
		atomic_inc(&pkg_info->available);
		printk(KERN_ALERT "open pkg_info : the device has been opened by some other device, unable to open lock\n");
		return -EBUSY;		/* already open */
	}

	return 0;
}

int pkg_info_release(struct inode *inode, struct file *filp)
{
	pkg_info_dev *pkg_info = filp->private_data;
	atomic_inc(&pkg_info->available);	/* release the device */
	return 0;
}

int slimx_get_pkg(long arg){
    slimx_get_arg slimx_get_req;
	slimx_coninfo *coninfo;
	
    if (unlikely(copy_from_user(&slimx_get_req, (void *) arg, sizeof(slimx_get_req))))
		return -EFAULT;
	printk(KERN_INFO "[pkg_info]get called : %u:%hu,local:%hu\n",slimx_get_req.dst_ip,slimx_get_req.dst_port,slimx_get_req.src_port);
    
	
	coninfo=slimx_con_find(&slimx.contab,slimx_get_req.dst_ip,slimx_get_req.dst_port,slimx_get_req.src_port);
	
	if(coninfo){
		if(jiffies - coninfo->lst_second > 2*HZ)
			slimx_get_req.pkg_num=0;
		else
			slimx_get_req.pkg_num=coninfo->lst_pkg;
		
	}else{
		slimx_get_req.pkg_num=0;
		printk(KERN_INFO "[pkg_info] get :nothing find");
	}
	if (copy_to_user((slimx_get_arg*) arg, &slimx_get_req, sizeof(slimx_get_req))){
			return -EFAULT;
		}
	
    return 0;
}

int slimx_set_target(long arg){
    slimx_set_arg slimx_set_req;

	slimx_connode *node;
	slimx_coninfo *info;
	slimx_coninfo *addre;
	node=kmalloc(sizeof(*node),GFP_KERNEL);
	info=kmalloc(sizeof(*info),GFP_KERNEL);

    if (unlikely(copy_from_user(&slimx_set_req, (void *) arg, sizeof(slimx_set_req))))
		return -EFAULT;
	
	info->dst_ip=slimx_set_req.dst_ip;
	info->dst_port=slimx_set_req.dst_port;
	info->src_port=slimx_set_req.src_port;
	info->lst_pkg=0;
	info->lst_second=jiffies-HZ;
	info->cur_pkg=0;
	info->cur_second=jiffies;
	node->con=info;
	slimx_con_add(&slimx.contab,node);
	addre=slimx_con_find(&slimx.contab,slimx_set_req.dst_ip,slimx_set_req.dst_port,slimx_set_req.src_port);
	if(addre){
		printk(KERN_INFO "[slimx_set_target]add succ");
	}else{
		printk(KERN_INFO "[slimx_set_target]add failed");
	}


    printk(KERN_INFO "[pkg_info]set: %u:%hu,local:%hu\n",slimx_set_req.dst_ip,slimx_set_req.dst_port,slimx_set_req.src_port);
    return 0;
}

int slimx_del_target(long arg){
    slimx_del_arg slimx_del_req;
	slimx_coninfo *coninfo;
    if (unlikely(copy_from_user(&slimx_del_req, (void *) arg, sizeof(slimx_del_req))))
		return -EFAULT;
	coninfo=slimx_con_find(&slimx.contab,slimx_del_req.dst_ip,slimx_del_req.dst_port,slimx_del_req.src_port);
	if(coninfo){
		return 2;
	}
    printk(KERN_INFO "[pkg_info]del: %u:%hu,local:%hu\n",slimx_del_req.dst_ip,slimx_del_req.dst_port,slimx_del_req.src_port);
     
    return 0;
}

long pkg_info_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int result;
	switch (cmd) {
        case SLIMX_GET:
            result = slimx_get_pkg(arg);
            break;
        case SLIMX_SET:
            result = slimx_set_target(arg);
            break;
        case SLIMX_DEL:
            result = slimx_del_target(arg);
            break;
        default:
            printk(KERN_NOTICE "[pkg_info] ioctl:Unknown ioctl: %d\n", cmd);
            result = -1;
            break;
        }
	return result;
}





//==============main=============

static int slimx_init(void)
{
	slimx_con_init(&slimx.contab);
	if (nf_cpt_init()&&pkg_info_init()){
		printk(KERN_INFO "[slimx]:start capture packges and reg iovtl success\n");
		return 0;
	}else return -1;
}

static void slimx_exit(void)
{
	nf_cpt_exit();
    pkg_info_exit();

	printk(KERN_INFO "[pkgcpt]: stop working\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("coderlh@qq.com");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("capture packet in kernel");

module_init(slimx_init);
module_exit(slimx_exit);
