#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/elmac.h>
#include <linux/mcst_elmac.h>
#include <linux/security.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/netlabel.h>
#include <linux/netfilter/x_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("adyan.imkenov@gmail.com");

int debug_val = 0;
extern int security_mcst_elmac;
/**
 * Classification level cod (1 bytes), default Unclassified (0xAB).
 * 
 */
#define IPSO_CLASS_LEVEL			0xab
#define IPSO_CLASS_LEVEL_LEN			0x1

/** Length of the base IPSO option, this includes the option type (1 byte), the
 * option length (1 byte), classification level(1 bytes) and protection field
 * (max 11 bytes).
 */
#define IPSO_V4_LEN				0x1
#define IPSO_TYPE_LEN				0x1
#define IPSO_V4_HDR_LEN				IPSO_TYPE_LEN + IPSO_V4_LEN + \
						IPSO_CLASS_LEVEL_LEN
#define IPSO_PROTECTION_LEVEL_MAX_LEN		0x1
#define IPSO_PROTECTION_CATEGORY_MAX_LEN	0xa
#define IPSO_PROTECTION_MAX_LEN			IPSO_PROTECTION_LEVEL_MAX_LEN + \
						IPSO_PROTECTION_CATEGORY_MAX_LEN
#define IPSO_V4_OPT_LEN_MAX			IPSO_V4_HDR_LEN + \
						IPSO_PROTECTION_MAX_LEN
#define IPSO_PROTECTION_SHIFT			0x3


static int decode_bit_list(void *i_buff, elmac_label_t *o_buff,
				int len)
{
	int i, k, j, o_len = 0;
	__u8 *s_ptr;
	__u8 *t_ptr;
	//__u8 *t_buff;

	if (debug_val == ELMAC_DEBUG_NET ||
	    debug_val == ELMAC_DEBUG_ALL) {
		printk( "%s(%d)\n"
			"len: %i\n"
			"o_buff->level: %x \n"
			"o_buff->category: %llx \n",
			__FUNCTION__, __LINE__,
			len,
			o_buff->level,
			VAL64_TO_CPU(o_buff->category));
	}
#if 0
	t_buff = (__u8 *) kzalloc(len, GFP_KERNEL);
	
	if (t_buff == NULL)
		return -ENOMEM;
	t_ptr = (__u8 *) t_buff;
#endif
	s_ptr = (__u8 *) i_buff;
	t_ptr = (__u8 *) o_buff;
	
	j = 0;
	*t_ptr = 0;
	
	for (k = 0; k < len; k ++, s_ptr ++)
		for (i = 1; i != 0x100; i <<= 1) {
			if (i > 1) {
				*t_ptr |= ((*s_ptr & i) ? 1 : 0) << j;
				j ++;
			}
			
			if (debug_val == ELMAC_DEBUG_NET ||
			    debug_val == ELMAC_DEBUG_ALL) {
				printk("%s(%d) i: %d j: %d s_ptr: %x "
					"t_ptr: %x\n",
					__FUNCTION__, __LINE__,
					i, j, *s_ptr, *t_ptr);
			}
			
			if (j == 8) {
				j = 0;
				t_ptr ++;
				*t_ptr = 0;
				o_len ++;
			}
		}

	if (j)
		o_len ++;

	if (o_len > sizeof(elmac_label_t))
		return -ERANGE;
	
	//unconv(o_buff, t_buff, sizeof(elmac_label_t));

	if (debug_val == ELMAC_DEBUG_NET ||
	    debug_val == ELMAC_DEBUG_ALL) {
		printk("%s(%d)\n"
			"len: %i\n"
			"o_buff->level: %x\n"
			"o_buff->category: %llx\n",
			__FUNCTION__, __LINE__,
			o_len,
			o_buff->level,
			VAL64_TO_CPU(o_buff->category));
	}
	return o_len;
}

int skbuff_getattr(const struct sk_buff *skb,
			    elmac_label_t *secattr)
{
	unsigned char *optptr = skb_network_header(skb) + sizeof(struct iphdr);
	struct ip_options * opt = &(IPCB(skb)->opt);
	int  l = opt->optlen;
	int  optlen;

	if (debug_val == ELMAC_DEBUG_NET ||
	    debug_val == ELMAC_DEBUG_ALL)
		printk( "%s(%d)\n"
			"MAC recieve parse skb len: %d.\n",
		       __FUNCTION__, __LINE__, l);

	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return 0;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen < 2 || optlen > l)
			return -EINVAL;
		if (debug_val == ELMAC_DEBUG_NET ||
		    debug_val == ELMAC_DEBUG_ALL)
			printk( "%s(%d)\n"
				"MAC recieve *optptr: %x.\n",
				__FUNCTION__, __LINE__, *optptr);
		switch (*optptr) {
		case IPOPT_SEC:
			if (debug_val == ELMAC_DEBUG_NET ||
			    debug_val == ELMAC_DEBUG_ALL)
				printk( "%s(%d)\n"
					"MAC recieve IPOPT_SEC, "
					"len: %d.\n",
					__FUNCTION__, __LINE__,
					optptr[1]);
			if (decode_bit_list(optptr + IPSO_PROTECTION_SHIFT,
					secattr,
					optptr[1] - IPSO_PROTECTION_SHIFT) > 0)
				return 0;
			break;
		default:
			break;
		}
		l -= optlen;
		optptr += optlen;
	}
	/*
	 * Not IPOPT_SEC, packet unlabeling
	 */
	return 1;
}

static unsigned int
label_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	elmac_context_t *labelinfo = par->targinfo; 	
	elmac_context_t skb_label; 
			
	elmac_context_t *tcp_label, *port_label;
	char *s_label, *o_label;
		
	int rc = 0;
	memset(&skb_label, 0, sizeof(elmac_context_t));
		
	int ret_val = 0;
	ret_val = skbuff_getattr(skb, &skb_label.mac);
	
	s_label = (char*)&skb_label;
	o_label = (char*)labelinfo;
		
	tcp_label = (elmac_context_t*)&skb_label;
	port_label = (elmac_context_t*)labelinfo;
		
	rc = mac_access(s_label, o_label, MAY_READWRITE, NULL, 0);
		
	if(rc == 0) {
		return NF_ACCEPT;
	}
	else {
		return NF_DROP; 
	}
}

static struct xt_target label_tg_reg[] __read_mostly = {
	{
		.name 		= "LABEL",
		.revision 	= 0,
		.family 	= NFPROTO_IPV4,
		.table 		= "filter",
		.hooks		= (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_LOCAL_IN),
		.target 	= label_tg,
		.targetsize = sizeof(elmac_context_t),
		.me 		= THIS_MODULE,
	},
};

static int __init label_tg_init(void)
{
	if(security_mcst_elmac == 1)
		return xt_register_targets(label_tg_reg, ARRAY_SIZE(label_tg_reg));
	else 
	{
		printk("Elmac is disabled\n");
		return -EINVAL;
	}
}		
	
static void __exit label_tg_exit(void)
{
	xt_unregister_targets(label_tg_reg, ARRAY_SIZE(label_tg_reg));
}

module_init(label_tg_init);
module_exit(label_tg_exit);
