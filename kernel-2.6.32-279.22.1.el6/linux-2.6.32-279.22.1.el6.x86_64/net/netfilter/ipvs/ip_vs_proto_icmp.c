/*
 * ip_vs_proto_icmp.c:	ICMP load balancing support for IPVS
 *
 * Authors:     yu bo <yubo@xiaomi.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Changes:
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>

#include <net/ip_vs.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>

static struct ip_vs_conn *icmp_conn_in_get(int af, const struct sk_buff *skb,
					  struct ip_vs_protocol *pp,
					  const struct ip_vs_iphdr *iph,
					  unsigned int proto_off, int inverse,
					  int *res_dir)
{
	struct ip_vs_conn *cp;
	__be16 _ports[2], *pptr;

	pptr = skb_header_pointer(skb, proto_off, sizeof(_ports), _ports);
	if (pptr == NULL)
		return NULL;

	if (likely(!inverse)) {
		cp = ip_vs_conn_get(af, iph->protocol,
				    &iph->saddr, pptr[0],
				    &iph->daddr, pptr[1], res_dir);
	} else {
		cp = ip_vs_conn_get(af, iph->protocol,
				    &iph->daddr, pptr[1],
				    &iph->saddr, pptr[0], res_dir);
	}

	return cp;
}

static struct ip_vs_conn *icmp_conn_out_get(int af, const struct sk_buff *skb,
					   struct ip_vs_protocol *pp,
					   const struct ip_vs_iphdr *iph,
					   unsigned int proto_off, int inverse,
					   int *res_dir)
{
	struct ip_vs_conn *cp;
	__be16 _ports[2], *pptr;

	pptr = skb_header_pointer(skb, proto_off, sizeof(_ports), _ports);
	if (pptr == NULL)
		return NULL;

	if (likely(!inverse)) {
		cp = ip_vs_conn_get(af, iph->protocol,
				    &iph->saddr, pptr[0],
				    &iph->daddr, pptr[1], res_dir);
	} else {
		cp = ip_vs_conn_get(af, iph->protocol,
				    &iph->daddr, pptr[1],
				    &iph->saddr, pptr[0], res_dir);
	}

	return cp;
}

static int
icmp_conn_schedule(int af, struct sk_buff *skb, struct ip_vs_protocol *pp,
		  int *verdict, struct ip_vs_conn **cpp)
{
	struct ip_vs_service *svc;
	struct icmphdr _icmph, *uh;
	struct ip_vs_iphdr iph;
	

	ip_vs_fill_iphdr(af, skb_network_header(skb), &iph);

	uh = skb_header_pointer(skb, iph.len, sizeof(_icmph), &_icmph);
	if (uh == NULL) {
		*verdict = NF_DROP;
		return 0;
	}


	svc = ip_vs_service_get(af, skb->mark, iph.protocol,
			&iph.daddr, uh->dest);
	
	if (svc) {
		if (ip_vs_todrop()) {
			/*
			 * It seems that we are very loaded.
			 * We have to drop this packet :(
			 */
			ip_vs_service_put(svc);
			*verdict = NF_DROP;
			return 0;
		}

		/*
		 * Let the virtual server select a real server for the
		 * incoming connection, and create a connection entry.
		 */
		*cpp = ip_vs_schedule(svc, skb, 0);
		if (!*cpp) {
			*verdict = ip_vs_leave(svc, skb, pp);
			return 0;
		}
		ip_vs_service_put(svc);
	}
	return 1;
}

static inline void
icmp_fast_csum_update(int af, struct icmphdr *uhdr,
		     const union nf_inet_addr *oldip,
		     const union nf_inet_addr *newip,
		     __be16 oldport, __be16 newport)
{
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		uhdr->check =
		    csum_fold(ip_vs_check_diff16(oldip->ip6, newip->ip6,
						 ip_vs_check_diff2(oldport,
								   newport,
								   ~csum_unfold
								   (uhdr->
								    check))));
	else
#endif
		uhdr->check =
		    csum_fold(ip_vs_check_diff4(oldip->ip, newip->ip,
						ip_vs_check_diff2(oldport,
								  newport,
								  ~csum_unfold
								  (uhdr->
								   check))));
	if (!uhdr->check)
		uhdr->check = CSUM_MANGLED_0;
}

static inline void
icmp_partial_csum_update(int af, struct icmphdr *uhdr,
			const union nf_inet_addr *oldip,
			const union nf_inet_addr *newip,
			__be16 oldlen, __be16 newlen)
{
#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		uhdr->check =
		    csum_fold(ip_vs_check_diff16(oldip->ip6, newip->ip6,
						 ip_vs_check_diff2(oldlen,
								   newlen,
								   ~csum_unfold
								   (uhdr->
								    check))));
	else
#endif
		uhdr->check =
		    csum_fold(ip_vs_check_diff4(oldip->ip, newip->ip,
						ip_vs_check_diff2(oldlen,
								  newlen,
								  ~csum_unfold
								  (uhdr->
								   check))));
}

static int
icmp_snat_handler(struct sk_buff *skb,
		 struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct icmphdr *icmph;
	unsigned int icmphoff;
	int oldlen;

#ifdef CONFIG_IP_VS_IPV6
	if (cp->af == AF_INET6)
		icmphoff = sizeof(struct ipv6hdr);
	else
#endif
		icmphoff = ip_hdrlen(skb);
	oldlen = skb->len - icmphoff;

	/* csum_check requires unshared skb */
	if (!skb_make_writable(skb, icmphoff + sizeof(*icmph)))
		return 0;

	if (unlikely(cp->app != NULL)) {
		/* Some checks before mangling */
		if (pp->csum_check && !pp->csum_check(cp->af, skb, pp))
			return 0;

		/*
		 *      Call application helper if needed
		 */
		if (!ip_vs_app_pkt_out(cp, skb))
			return 0;
	}

	icmph = (void *)skb_network_header(skb) + icmphoff;
	icmph->source = cp->vport;
	icmph->dest = cp->cport;

	/*
	 *      Adjust ICMP checksums
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		icmp_partial_csum_update(cp->af, icmph, &cp->daddr, &cp->vaddr,
					htons(oldlen),
					htons(skb->len - icmphoff));
		icmp_partial_csum_update(cp->af, icmph, &cp->laddr, &cp->caddr,
					htons(oldlen),
					htons(skb->len - icmphoff));
	} else if (!cp->app && (icmph->check != 0)) {
		/* Only port and addr are changed, do fast csum update */
		icmp_fast_csum_update(cp->af, icmph, &cp->daddr, &cp->vaddr,
				     cp->dport, cp->vport);
		icmp_fast_csum_update(cp->af, icmph, &cp->laddr, &cp->caddr,
				     cp->lport, cp->cport);
		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->ip_summed = CHECKSUM_NONE;
	} else {
		/* full checksum calculation */
		icmph->check = 0;
		skb->csum = skb_checksum(skb, icmphoff, skb->len - icmphoff, 0);
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			icmph->check = csum_ipv6_magic(&cp->vaddr.in6,
						      &cp->caddr.in6,
						      skb->len - icmphoff,
						      cp->protocol, skb->csum);
		else
#endif
			icmph->check = csum_tcpicmp_magic(cp->vaddr.ip,
							cp->caddr.ip,
							skb->len - icmphoff,
							cp->protocol,
							skb->csum);
		if (icmph->check == 0)
			icmph->check = CSUM_MANGLED_0;
		IP_VS_DBG(11, "O-pkt: %s O-csum=%d (+%zd)\n",
			  pp->name, icmph->check,
			  (char *)&(icmph->check) - (char *)icmph);
	}
	return 1;
}

static int
icmp_dnat_handler(struct sk_buff *skb,
		 struct ip_vs_protocol *pp, struct ip_vs_conn *cp)
{
	struct icmphdr *icmph;
	unsigned int icmphoff;
	int oldlen;

#ifdef CONFIG_IP_VS_IPV6
	if (cp->af == AF_INET6)
		icmphoff = sizeof(struct ipv6hdr);
	else
#endif
		icmphoff = ip_hdrlen(skb);
	oldlen = skb->len - icmphoff;

	/* csum_check requires unshared skb */
	if (!skb_make_writable(skb, icmphoff + sizeof(*icmph)))
		return 0;

	if (unlikely(cp->app != NULL)) {
		/* Some checks before mangling */
		if (pp->csum_check && !pp->csum_check(cp->af, skb, pp))
			return 0;

		/*
		 *      Attempt ip_vs_app call.
		 *      It will fix ip_vs_conn
		 */
		if (!ip_vs_app_pkt_in(cp, skb))
			return 0;
	}

	icmph = (void *)skb_network_header(skb) + icmphoff;
	icmph->source = cp->lport;
	icmph->dest = cp->dport;

	/*
	 *      Adjust ICMP checksums
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		icmp_partial_csum_update(cp->af, icmph, &cp->vaddr, &cp->daddr,
					htons(oldlen),
					htons(skb->len - icmphoff));
		icmp_partial_csum_update(cp->af, icmph, &cp->caddr, &cp->laddr,
					htons(oldlen),
					htons(skb->len - icmphoff));
	} else if (!cp->app && (icmph->check != 0)) {
		/* Only port and addr are changed, do fast csum update */
		icmp_fast_csum_update(cp->af, icmph, &cp->vaddr, &cp->daddr,
				     cp->vport, cp->dport);
		icmp_fast_csum_update(cp->af, icmph, &cp->caddr, &cp->laddr,
				     cp->cport, cp->lport);
		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->ip_summed = CHECKSUM_NONE;
	} else {
		/* full checksum calculation */
		icmph->check = 0;
		skb->csum = skb_checksum(skb, icmphoff, skb->len - icmphoff, 0);
#ifdef CONFIG_IP_VS_IPV6
		if (cp->af == AF_INET6)
			icmph->check = csum_ipv6_magic(&cp->caddr.in6,
						      &cp->daddr.in6,
						      skb->len - icmphoff,
						      cp->protocol, skb->csum);
		else
#endif
			icmph->check = csum_tcpicmp_magic(cp->caddr.ip,
							cp->daddr.ip,
							skb->len - icmphoff,
							cp->protocol,
							skb->csum);
		if (icmph->check == 0)
			icmph->check = CSUM_MANGLED_0;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	return 1;
}

static int
icmp_csum_check(int af, struct sk_buff *skb, struct ip_vs_protocol *pp)
{
	struct icmphdr _icmph, *uh;
	unsigned int icmphoff;

#ifdef CONFIG_IP_VS_IPV6
	if (af == AF_INET6)
		icmphoff = sizeof(struct ipv6hdr);
	else
#endif
		icmphoff = ip_hdrlen(skb);

	uh = skb_header_pointer(skb, icmphoff, sizeof(_icmph), &_icmph);
	if (uh == NULL)
		return 0;

	if (uh->check != 0) {
		switch (skb->ip_summed) {
		case CHECKSUM_NONE:
			skb->csum = skb_checksum(skb, icmphoff,
						 skb->len - icmphoff, 0);
		case CHECKSUM_COMPLETE:
#ifdef CONFIG_IP_VS_IPV6
			if (af == AF_INET6) {
				if (csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
						    &ipv6_hdr(skb)->daddr,
						    skb->len - icmphoff,
						    ipv6_hdr(skb)->nexthdr,
						    skb->csum)) {
					IP_VS_DBG_RL_PKT(0, pp, skb, 0,
							 "Failed checksum for");
					return 0;
				}
			} else
#endif
			if (csum_tcpicmp_magic(ip_hdr(skb)->saddr,
						      ip_hdr(skb)->
						      daddr,
						      skb->len -
						      icmphoff,
						      ip_hdr(skb)->
						      protocol, skb->csum)) {
				IP_VS_DBG_RL_PKT(0, pp, skb, 0,
						 "Failed checksum for");
				return 0;
			}
			break;
		default:
			/* No need to checksum. */
			break;
		}
	}
	return 1;
}

/*
 *	Note: the caller guarantees that only one of register_app,
 *	unregister_app or app_conn_bind is called each time.
 */

#define	ICMP_APP_TAB_BITS	4
#define	ICMP_APP_TAB_SIZE	(1 << ICMP_APP_TAB_BITS)
#define	ICMP_APP_TAB_MASK	(ICMP_APP_TAB_SIZE - 1)

static struct list_head icmp_apps[ICMP_APP_TAB_SIZE];
static DEFINE_SPINLOCK(icmp_app_lock);

static inline __u16 icmp_app_hashkey(__be16 port)
{
	return (((__force u16) port >> ICMP_APP_TAB_BITS) ^ (__force u16) port)
	    & ICMP_APP_TAB_MASK;
}

static int icmp_register_app(struct ip_vs_app *inc)
{
	struct ip_vs_app *i;
	__u16 hash;
	__be16 port = inc->port;
	int ret = 0;

	hash = icmp_app_hashkey(port);

	spin_lock_bh(&icmp_app_lock);
	list_for_each_entry(i, &icmp_apps[hash], p_list) {
		if (i->port == port) {
			ret = -EEXIST;
			goto out;
		}
	}
	list_add(&inc->p_list, &icmp_apps[hash]);
	atomic_inc(&ip_vs_protocol_icmp.appcnt);

      out:
	spin_unlock_bh(&icmp_app_lock);
	return ret;
}

static void icmp_unregister_app(struct ip_vs_app *inc)
{
	spin_lock_bh(&icmp_app_lock);
	atomic_dec(&ip_vs_protocol_icmp.appcnt);
	list_del(&inc->p_list);
	spin_unlock_bh(&icmp_app_lock);
}

static int icmp_app_conn_bind(struct ip_vs_conn *cp)
{
	int hash;
	struct ip_vs_app *inc;
	int result = 0;

	/* Default binding: bind app only for NAT */
	if (IP_VS_FWD_METHOD(cp) != IP_VS_CONN_F_MASQ)
		return 0;

	/* Lookup application incarnations and bind the right one */
	hash = icmp_app_hashkey(cp->vport);

	spin_lock(&icmp_app_lock);
	list_for_each_entry(inc, &icmp_apps[hash], p_list) {
		if (inc->port == cp->vport) {
			if (unlikely(!ip_vs_app_inc_get(inc)))
				break;
			spin_unlock(&icmp_app_lock);

			IP_VS_DBG_BUF(9, "%s(): Binding conn %s:%u->"
				      "%s:%u to app %s on port %u\n",
				      __func__,
				      IP_VS_DBG_ADDR(cp->af, &cp->caddr),
				      ntohs(cp->cport),
				      IP_VS_DBG_ADDR(cp->af, &cp->vaddr),
				      ntohs(cp->vport),
				      inc->name, ntohs(inc->port));

			cp->app = inc;
			if (inc->init_conn)
				result = inc->init_conn(inc, cp);
			goto out;
		}
	}
	spin_unlock(&icmp_app_lock);

      out:
	return result;
}

static int icmp_timeouts[IP_VS_ICMP_S_LAST + 1] = {
	[IP_VS_ICMP_S_NORMAL] = 5 * 60 * HZ,
	[IP_VS_ICMP_S_LAST] = 2 * HZ,
};

static const char *const icmp_state_name_table[IP_VS_ICMP_S_LAST + 1] = {
	[IP_VS_ICMP_S_NORMAL] = "ICMP",
	[IP_VS_ICMP_S_LAST] = "BUG!",
};

static int icmp_set_state_timeout(struct ip_vs_protocol *pp, char *sname, int to)
{
	return ip_vs_set_state_timeout(pp->timeout_table, IP_VS_ICMP_S_LAST,
				       icmp_state_name_table, sname, to);
}

static const char *icmp_state_name(int state)
{
	if (state >= IP_VS_ICMP_S_LAST)
		return "ERR!";
	return icmp_state_name_table[state] ? icmp_state_name_table[state] : "?";
}

static int
icmp_state_transition(struct ip_vs_conn *cp, int direction,
		     const struct sk_buff *skb, struct ip_vs_protocol *pp)
{
	cp->timeout = pp->timeout_table[IP_VS_ICMP_S_NORMAL];
	return 1;
}

static void icmp_init(struct ip_vs_protocol *pp)
{
	IP_VS_INIT_HASH_TABLE(icmp_apps);
	pp->timeout_table = icmp_timeouts;
}

static void icmp_exit(struct ip_vs_protocol *pp)
{
}




static void
ip_vs_icmp_debug_packet_v4(struct ip_vs_protocol *pp, const struct sk_buff *skb,
		       int offset, const char *msg)
{
	char buf[256];
	struct iphdr *iph;
	struct icmphdr _icmph, *ic;


	iph = ip_hdr(skb);
	offset = ihl = iph->ihl * 4;
	ic = skb_header_pointer(skb, offset, sizeof(_icmph), &_icmph);
	if (ic == NULL)
		sprintf(buf, "%s TRUNCATED", pp->name);
	else
		sprintf(buf, "%s ICMP (%d,%d) %pI4->%pI4", ic->type, ntohs(icmp_id(ic)), 
			&iph->saddr, &iph->daddr);

	pr_debug("%s: %s\n", msg, buf);
}

#ifdef CONFIG_IP_VS_IPV6
static void
ip_vs_icmp_debug_packet_v6(struct ip_vs_protocol *pp, const struct sk_buff *skb,
		       int offset, const char *msg)
{
	char buf[256];
	struct ipv6hdr *iph;
	struct icmp6hdr _icmph, *ic;

	iph = ipv6_hdr(skb);
	offset = sizeof(struct ipv6hdr);
	ic = skb_header_pointer(skb, offset, sizeof(_icmph), &_icmph);
	if (ic == NULL)
		sprintf(buf, "%s TRUNCATED", pp->name);
	else
		sprintf(buf, "%s ICMPv6 (%d,%d) %pI6->%pI6", pp->name, ic->icmp6_type,
			ntohs(icmpv6_id(ic)), &iph->saddr, &iph->daddr);
	pr_debug("%s: %s\n", msg, buf);
}
#endif




static void
ip_vs_icmp_debug_packet(struct ip_vs_protocol *pp, const struct sk_buff *skb,
		    int offset, const char *msg)
{
#ifdef CONFIG_IP_VS_IPV6
	if (skb->protocol == htons(ETH_P_IPV6))
		ip_vs_icmp_debug_packet_v6(pp, skb, offset, msg);
	else
#endif
		ip_vs_icmp_debug_packet_v4(pp, skb, offset, msg);
}


struct ip_vs_protocol ip_vs_protocol_icmp = {
	.name = "ICMP",
	.protocol = IPPROTO_ICMP,
	.num_states = IP_VS_ICMP_S_LAST,
	.dont_defrag = 0,
	.init = icmp_init,
	.exit = icmp_exit,
	.conn_schedule = icmp_conn_schedule,
	.conn_in_get = icmp_conn_in_get,
	.conn_out_get = icmp_conn_out_get,
	.snat_handler = icmp_snat_handler,
	.dnat_handler = icmp_dnat_handler,
	.csum_check = icmp_csum_check,
	.state_transition = icmp_state_transition,
	.state_name = icmp_state_name,
	.register_app = icmp_register_app,
	.unregister_app = icmp_unregister_app,
	.app_conn_bind = icmp_app_conn_bind,
	.debug_packet = ip_vs_icmp_debug_packet,
	.timeout_change = NULL,
	.set_state_timeout = icmp_set_state_timeout,
};
