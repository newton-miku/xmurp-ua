#include <linux/module.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/random.h>

MODULE_AUTHOR("Haonan Chen");
MODULE_DESCRIPTION("Modify UA in HTTP for anti-detection of router in XPU.Modified By nEwt0n_m1ku");
MODULE_LICENSE("GPL");
#define ONLY80 0 // 是否只处理80端口
static struct nf_hook_ops nfho;

enum char_scan_enum
{
    next,
    modified_and_next,
    scan_finish,
    reset,
};

enum skb_scan_ret
{
    need_next_frag = 1,
    ua_modified = 2,
};
const char str_ua[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64 And Fxck Away) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36";
// 根据得到的指针尝试扫描，发现结尾或发现UA或更改UA后返回对应结果。
// 输入零指针则为重置状态。
inline u_int8_t char_scan(char *data)
{
    const char str_ua_head[] = "User-Agent: ",
               str_end[] = "\r\n\r\n";
    // 不算'\0'，长度分别为12、125、4
    static enum {
        nothing_matching,
        ua_head_matching,
        ua_modifying,
        end_matching,
    } status = nothing_matching;
    static u_int8_t covered_length;

    if (data == 0)
    {
        status = nothing_matching;
        covered_length = 0;
        return reset;
    }

    while (true)
    {
        if (status == nothing_matching)
        {
            if (*data == str_ua_head[0])
            {
                status = ua_head_matching;
                covered_length = 1;
                return next;
            }
            else if (*data == str_end[0])
            {
                status = end_matching;
                covered_length = 1;
                return next;
            }
            else
                return next;
        }
        else if (status == ua_head_matching)
        {
            if (*data == str_ua_head[covered_length])
            {
                covered_length++;
                if (covered_length == 12)
                {
                    status = ua_modifying;
                    covered_length = 0;
                    return next;
                }
                else
                    return next;
            }
            else
                status = nothing_matching;
        }
        else if (status == ua_modifying)
        {
            if (*data == '\r')
            {
                status = nothing_matching;
                return scan_finish;
            }
            else
            {
                if (covered_length < strlen(str_ua) - 1)
                    *data = str_ua[covered_length];
                else
                    *data = ' ';
                covered_length++;
                return modified_and_next;
            }
        }
        else if (status == end_matching)
        {
            if (*data == str_end[covered_length])
            {
                covered_length++;
                if (covered_length == strlen(str_end) - 1)
                {
                    status = nothing_matching;
                    return scan_finish;
                }
                else
                    return next;
            }
            else
                status = nothing_matching;
        }
    }
}

// 将数据逐字节发送给下一层，根据下一层的结果（扫描到结尾、扫描到UA、已更改UA），确定是否扫描完毕，以及是否发生了改动，返回到上一层。
inline u_int8_t skb_scan(char *data_start, char *data_end)
{
    register char *i;
    register u_int8_t ret, modified = 0;
    for (i = data_start; i < data_end; i++)
    {
        ret = char_scan(i);
        if (ret == scan_finish)
            return modified;
        else if (ret == modified_and_next)
            modified = ua_modified;
    }
    return modified + need_next_frag;
}

// 捕获数据包，检查是否符合条件。如果符合，则送到下一层，并根据下一层返回的结果，如果必要的话，重新计算校验和以及继续捕获下一个分片。
// ip地址、端口号、iph->tot_len需要网络顺序到主机顺序的转换。校验和时，除长度字段外，不需要手动进行网络顺序和主机顺序的转换。
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
#else
unsigned int hook_funcion(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
#endif
{
    register struct tcphdr *tcph;
    register struct iphdr *iph;
    register char *data_start, *data_end;

    static u_int8_t catch_next_frag = 0;
    static u_int32_t saddr, daddr, seq;
    static u_int16_t sport, dport;

    static u_int32_t n_ua_modified = 0, n_ua_modify_faild = 0, n_not_modifible = 0, n_mark_matched = 0;
    static u_int32_t n_ua_modified_lastprint = 1;
    static u_int8_t mark_matched = 0, not_writable = 0;

    register u_int8_t jump_to_next_function = 0, ret;

    // 过滤发往外网的HTTP请求的包，且要求包的应用层内容不短于3字节
    if (skb == 0)
        return NF_ACCEPT;
    iph = ip_hdr(skb);
    if ((ntohl(iph->daddr) & 0xffff0000) == 0xc0a80000)
        return NF_ACCEPT;
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    tcph = tcp_hdr(skb);
    if (ONLY80)
    {
        if (ntohs(tcph->dest) != 80)
            return NF_ACCEPT;
    }
    data_start = (char *)tcph + tcph->doff * 4;
    data_end = (char *)tcph + ntohs(iph->tot_len) - iph->ihl * 4;
    if (data_end - data_start < 4)
        return NF_ACCEPT;
    if (skb->mark & 0x100)
    {
        if (!mark_matched)
        {
            mark_matched = 1;
            printk("xmurp-ua: Mark matched. Note that all packages with the mark will be ACCEPT without modification.\n");
            printk("xmurp-ua: If the mark is not set manually, it maybe a conflict there. "
                   "Find out which app is using the desired bit and let it use others, or modify and recompile me.\n");
        }
        n_mark_matched++;
        return NF_ACCEPT;
    }

    // 决定是否发送到下一层
    if (catch_next_frag && iph->saddr == saddr && iph->daddr == daddr &&
        tcph->seq == seq && tcph->source == sport && tcph->dest == dport)
        jump_to_next_function = 1;
    else if (data_end - data_start > 3)
        if (memcmp(data_start, "GET", 3) == 0 || memcmp(data_start, "POST", 4) == 0)
        {
            if (catch_next_frag)
            {
                n_ua_modify_faild++;
                char_scan(0);
                catch_next_frag = 0;
            }
            jump_to_next_function = 1;
        }
    if (!jump_to_next_function)
        return NF_ACCEPT;

        // 确保 skb 可以被修改，或者不可以被修改的话把它变得可修改
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    if (skb_ensure_writable(skb, (char *)data_end - (char *)skb->data) || skb == 0 || skb->data == 0)
#else
    if (!skb_make_writable(skb, (char *)data_end - (char *)skb->data) || skb == 0 || skb->data == 0)
#endif
    {
        if (!not_writable)
        {
            not_writable = 1;
            printk("xmurp-ua: There is a package not wirtable. Please make sure the router has enough memory.\n");
        }
        n_not_modifible++;
        n_ua_modify_faild++;
        catch_next_frag = 0;
        return NF_ACCEPT;
    }
    else
    {
        iph = ip_hdr(skb);
        tcph = tcp_hdr(skb);
        data_start = (char *)tcph + tcph->doff * 4;
        data_end = (char *)tcph + ntohs(iph->tot_len) - iph->ihl * 4;
    }

    // 发送到下一层，并回收数据
    ret = skb_scan(data_start, data_end);

    // 处理返回值
    if (ret & need_next_frag)
    {
        if (!catch_next_frag)
        {
            catch_next_frag = 1;
            saddr = iph->saddr;
            daddr = iph->daddr;
            sport = tcph->source;
            dport = tcph->dest;
        }
        seq = tcph->seq + (data_end - data_start);
    }
    else
        catch_next_frag = 0;
    if (ret & ua_modified)
    {
        n_ua_modified++;
        if (n_ua_modified == n_ua_modified_lastprint * 2)
        {
            printk("xmurp-ua: Successfully modified %u packages, faild to modify %u packages, %u packages matched mark, %u packages not modifiable.\n",
                   n_ua_modified, n_ua_modify_faild, n_mark_matched, n_not_modifible);
            n_ua_modified_lastprint *= 2;
        }
        tcph->check = 0;
        iph->check = 0;
        skb->csum = skb_checksum(skb, iph->ihl * 4, ntohs(iph->tot_len) - iph->ihl * 4, 0);
        iph->check = ip_fast_csum(iph, iph->ihl);
        tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, ntohs(iph->tot_len) - iph->ihl * 4, IPPROTO_TCP, skb->csum);
    }

    return NF_ACCEPT;
}

static int __init hook_init(void)
{
    int ret;

    nfho.hook = hook_funcion;
    nfho.pf = NFPROTO_IPV4;
    nfho.hooknum = NF_INET_POST_ROUTING;
    nfho.priority = NF_IP_PRI_FILTER;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    ret = nf_register_net_hook(&init_net, &nfho);
#else
    ret = nf_register_hook(&nfho);
#endif
    printk("xmurp-ua: Started, version %d.\n", VERSION);
    printk("xmurp-ua: nf_register_hook returnd %d.\n", ret);
    printk("xmurp-ua: 当前的目标UA为:%s\n", str_ua);

    // 格式化输出
    printk("\n");
    printk("|------------------------------------------------------------------------|\n");
    printk("|%-80s|\n", " ");
    printk("|%-80s|\n", "关于反对黑心商家的申明：");
    printk("|%-80s|\n", " ");
    printk("|%-80s|\n", "XMURP-UA 由我一人（厦门大学陈浩南）编写并维护，开源免费地提供给所");
    printk("|%-80s|\n", "有人使；相关教程也是我们写好并免费公开在网上的。我从来没有允许、并且");
    printk("|%-80s|\n", "**明确禁止**用于商业用途。但现实是，有人将我现成的结果安装到路由器中");
    printk("|%-80s|\n", "拿去售卖，并且价格不菲。");
    printk("|%-80s|\n", " ");
    printk("|*************************************************************************|\n");
    printk("|%-80s|\n", "非常感谢原作者，这里是nEwt0n_m1ku,我将此仓库fork后，做了一些细微修改");
    printk("|%-80s|\n", "修改了修改后的UA，使其更加真实，当然，您也可以修改我的源码，");
    printk("|%-80s|\n", "然后将其修改为您自己的UA，虽然我的学校的校园网建设初期我有给提过建议");
    printk("|%-80s|\n", "但是最终似乎管理的老师和技术公司还是上了对应的检测程序。");
    printk("|*************************************************************************|\n");
    printk("|%-80s|\n", " ");
    printk("|%-80s|\n", "如果您看到了这条消息，希望您能够从身边小事做起，拒绝黑心商家。如");
    printk("|%-80s|\n", "果您本人已经购买了这样的路由器，希望您能够退货、追回自己的损失；如果");
    printk("|%-80s|\n", "您身边有人推销或有意愿购买这样的路由器，请将真相告诉他们。");
    printk("|%-80s|\n", " ");
    printk("|%-80s|\n", "1. 商家会把廉价的路由器用高昂的售价出售。事实上，只要二三十块就可");
    printk("|%-80s|\n", "以在闲鱼买到基本够宿舍用的、可以破解校园网的路由器（极路由 1s）。");
    printk("|%-80s|\n", " ");
    printk("|%-80s|\n", "2. 商家不管售后，也无力售后。事实上，卖你路由器的人大多也是小白，");
    printk("|%-80s|\n", "无非看过我们写的教程；出了问题他们就推脱，是校园网的问题，是路由器坏");
    printk("|%-80s|\n", "了，殊不知一句命令就可以解决。");
    printk("|%-80s|\n", " ");
    printk("|%-80s|\n", "3. 商家不尊重我们，大规模商业使用我们的技术获利，甚至把我们的群当");
    printk("|%-80s|\n", "免费的售后，自己只顾收钱。");
    printk("|%-80s|\n", " ");
    printk("|%-80s|\n", "我今天十分气愤，因此写了这些内容。希望更多的人可以看见。");
    printk("|%-80s|\n", " ");
    printk("|------------------------------------------------------------------------|\n");
    printk("|%-80s|\n", " ");
    printk("|%-80s|\n", "在使用的过程中，如果需要帮助，可以加入我们的 QQ 群：748317786。付");
    printk("|%-80s|\n", "费购买路由器者，恕不提供任何帮助。");
    printk("|%-80s|\n", " ");
    printk("|------------------------------------------------------------------------|\n");
    printk("\n");
    // 似乎格式对齐问题没法解决

    return 0;
}

// 卸载模块
static void __exit hook_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hook(&init_net, &nfho);
#else
    nf_unregister_hook(&nfho);
#endif
    printk("xmurp-ua: Stopped.\n");
}

module_init(hook_init);
module_exit(hook_exit);