/*****************************************************/
/*   MODULE: xt_IPPORTS module                       */
/*   AUTHOR: Giuseppe Virzì <giuseppe.virzi@gxm.com> */
/*****************************************************/



#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/string.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_MARK.h>

MODULE_DESCRIPTION("Xtables: IPPORTS");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_ipports");

static unsigned int ipports_tg(struct sk_buff *skb, const struct xt_action_param *par)
{

   /*TCP Header*/
   struct tcphdr *tcph;
   
   /*IP Header*/
   struct iphdr *iph;
   
   /*UDP Header*/
   struct udphdr *udph;
   
   /*Parameters from user-space*/
   
   /*Packet Payload*/
   char * payload = 0;
   
   /*Payload size*/
   int payload_size;
   
   
   /*ports*/
   int sport = 0;
   int dport = 0;
   
   /*IP*/
   int soaddr;
   int deaddr;
   
   /*TCP and UDP header lenght*/
   int tcph_len;
   int udph_len;

   /*Get IP Header*/
   iph = ip_hdr(skb);
   soaddr = iph->saddr;
   deaddr = iph->daddr;
   

   /*Get Payload*/
   switch (iph->protocol) {
      case IPPROTO_TCP:
         tcph = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

         /*TCP header size*/
         tcph_len = tcph->doff*4;

         /*get tcp payload*/
         payload = (char *)tcph + tcph_len;
         payload_size = ntohs(iph->tot_len) - ip_hdrlen(skb) - tcph_len;
         sport = tcph->source;
         dport = tcph->dest;
      break;

      case IPPROTO_UDP:
         udph = (struct udphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

         /*TCP header size*/
         udph_len = sizeof(struct udphdr);

         /*get tcp payload*/
         payload = (char *)udph + udph_len;
         payload_size = ntohs(udph->len) - udph_len;
         sport = udph->source;
         dport = udph->dest;
      break;
   }
      
   printk ("start ip is: %d \n", soaddr);
   printk ("dest ip is: %d \n", deaddr);
   printk ("start port is: %d \n", sport);
   printk ("dest port is: %d \n", dport);
   

   printk ("payload is: %c \n", payload);

   return XT_CONTINUE;   
 
}

static struct xt_target ipports_tg_reg __read_mostly = {

   .name = "IPPORTS",
   .revision = 0,
   .family = NFPROTO_UNSPEC,
   .target = ipports_tg,
   //.targetsize = sizeof(struct xt_ipports_info),
   .table = "mangle",
   .me = THIS_MODULE,
};

static int __init ipports_tg_init(void)
{
   return xt_register_target(&ipports_tg_reg);
}

static void __exit ipports_tg_exit(void)
{
   xt_unregister_target(&ipports_tg_reg);
}

module_init(ipports_tg_init);
module_exit(ipports_tg_exit);
