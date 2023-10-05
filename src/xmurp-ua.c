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
#include <linux/slab.h>
#include <linux/string.h>

MODULE_AUTHOR("Haonan Chen");
MODULE_DESCRIPTION("Modify UA in HTTP for anti-detection of router in XPU.Modified By nEwt0n_m1ku");
MODULE_LICENSE("GPL");

// 调试开关 非0为开启
#define ONLY80 0  // 只处理80端口
#define PRINTUA 0 // 打印UA，仅供调试使用

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
const char str_os[] = "Windows NT 10.0; Win64; x64 And Fxck Away";
char modified_ua[512] = "";
// 函数用于提取整个UA字符串，并查找操作系统信息
/*char *extractUserAgentAndOS(const char *input, char **ua)
{
    // 查找 "User-Agent: " 开头的部分
    const char *ua_start = strstr(input, "User-Agent: ");
    if (ua_start == NULL)
    {
        return NULL; // 未找到 "User-Agent: "
    }

    ua_start += strlen("User-Agent: "); // 跳过 "User-Agent: " 部分

    // 查找整个UA字符串（直到 "\r\n\r\n" 结束）
    const char *ua_end = strstr(ua_start, "\r\n");
    if (ua_end == NULL)
    {
        return NULL; // 未找到 "\r\n\r\n"
    }

    int ua_len = ua_end - ua_start;

    // 复制整个UA字符串
    char *ua_str = kmalloc(ua_len + 1, GFP_KERNEL);
    if (ua_str != NULL)
    {
        strncpy(ua_str, ua_start, ua_len);
        ua_str[ua_len] = '\0';

        // 在整个UA中查找操作系统信息
        char *start = strchr(ua_str, '(');
        if (start == NULL)
        {
            return NULL; // 未找到左括号
        }

        char *end = strchr(start, ')');
        if (end == NULL)
        {
            return NULL; // 未找到右括号
        }

        int len = end - start - 1; // 计算括号内内容的长度
        if (len <= 0)
        {
            return NULL; // 括号内没有内容
        }

        char *os = kmalloc(len + 1, GFP_KERNEL); // 使用kmalloc分配内核内存
        if (os != NULL)
        {
            strncpy(os, start + 1, len); // +1 跳过左括号
            os[len] = '\0';

            *ua = ua_str; // 将整个UA字符串返回

            return os; // 返回操作系统信息
        }
    }

    return NULL; // 内存分配失败
}*/

// 函数用于提取UA字符串，并查找操作系统信息，同时将UA分为前后两部分
char *extractUserAgentAndOS(const char *input, char **ua_before, char **ua_after)
{
    // 查找 "User-Agent: " 开头的部分
    const char *ua_start = strstr(input, "User-Agent: ");
    if (ua_start == NULL)
    {
        return NULL; // 未找到 "User-Agent: "
    }

    ua_start += strlen("User-Agent: "); // 跳过 "User-Agent: " 部分

    // 查找整个UA字符串（直到 "\r\n\r\n" 结束）
    const char *ua_end = strstr(ua_start, "\r\n");
    if (ua_end == NULL)
    {
        return NULL; // 未找到 "\r\n\r\n"
    }

    int ua_len = ua_end - ua_start;

    // 复制整个UA字符串
    char *ua_str = kmalloc(ua_len + 1, GFP_KERNEL);
    if (ua_str != NULL)
    {
        strncpy(ua_str, ua_start, ua_len);
        ua_str[ua_len] = '\0';

        // 在整个UA中查找操作系统信息
        char *start = strchr(ua_str, '(');
        if (start == NULL)
        {
            return NULL; // 未找到左括号
        }

        char *end = strchr(start, ')');
        if (end == NULL)
        {
            return NULL; // 未找到右括号
        }

        int len = end - start - 1; // 计算括号内内容的长度
        if (len <= 0)
        {
            return NULL; // 括号内没有内容
        }

        char *os = kmalloc(len + 1, GFP_KERNEL); // 使用kmalloc分配内核内存
        if (os != NULL)
        {
            strncpy(os, start + 1, len); // +1 跳过左括号
            os[len] = '\0';

            // 分割UA字符串为前后两部分
            int before_len = start - ua_str;
            *ua_before = kmalloc(before_len + 1, GFP_KERNEL);
            if (*ua_before != NULL)
            {
                strncpy(*ua_before, ua_str, before_len);
                (*ua_before)[before_len] = '\0';
            }
            else
            {
                printk("ua_before分配失败%d\t%d\t%d", before_len, (int)start, (int)ua_str);
            }

            // 后半部分是从 end 到 ua_end 之间的部分
            // 使用memcpy复制 ua_str 中第一个右括号至结尾的部分
            int after_len = ua_len - before_len - len;
            *ua_after = kmalloc(after_len + 1, GFP_KERNEL);
            if (*ua_after != NULL)
            {
                memcpy(*ua_after, end, after_len);
                (*ua_after)[after_len] = '\0';
            }
            else
            {
                printk("ua_after分配失败");
            }

            kfree(os);     // 使用 kfree 释放内核内存
            return ua_str; // 返回整个UA字符串
        }
    }

    return NULL; // 内存分配失败
}

// 根据得到的指针尝试扫描，发现结尾或发现UA或更改UA后返回对应结果。
// 输入零指针则为重置状态。
inline u_int8_t char_scan(char *data)
{
    const char str_ua_head[] = "User-Agent: ",
               str_end[] = "\r\n\r\n";
    // 不算'\0'，长度分别为12、4
    static enum {
        nothing_matching,
        ua_head_matching,
        ua_modifying,
        end_matching,
    } status = nothing_matching;    // 状态机的当前状态
    static u_int8_t covered_length; // 已经匹配的字符长度

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
            if (*data == str_ua_head[0]) // 如果当前字符与 "User-Agent: " 的第一个字符匹配
            {
                status = ua_head_matching; // 切换到匹配 User-Agent 头部的状态
                covered_length = 1;
                return next;
            }
            else if (*data == str_end[0]) // 如果当前字符与 "\r\n\r\n" 的第一个字符匹配
            {
                status = end_matching; // 切换到匹配结尾的状态
                covered_length = 1;
                return next;
            }
            else
                return next;
        }
        else if (status == ua_head_matching)
        {
            if (*data == str_ua_head[covered_length]) // 如果当前字符与 User-Agent 头部的下一个字符匹配
            {
                covered_length++;
                if (covered_length == 12) // 如果已经匹配了 User-Agent 头部的全部字符
                {
                    status = ua_modifying; // 切换到修改 User-Agent 的状态
                    covered_length = 0;
                    return next;
                }
                else
                    return next;
            }
            else
                status = nothing_matching; // 如果不匹配，则回到初始状态
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
                if (strlen(modified_ua) == 0) // 如果匹配浏览器没生效
                {
                    if (covered_length < strlen(str_ua) - 1)
                        *data = str_ua[covered_length]; // 替换当前字符为新的 User-Agent 部分的字符
                    else
                        *data = ' ';
                }
                else // 如果匹配浏览器生效
                {
                    if (covered_length < strlen(modified_ua) - 1)
                        *data = modified_ua[covered_length]; // 替换当前字符为新的 User-Agent 部分的字符
                    else
                        *data = ' ';
                }
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
    // char *ua = NULL;
    // char *os = extractUserAgentAndOS(data_start, &ua);
    // if (os != NULL)
    // {
    //     // 打印或处理提取的操作系统信息
    //     printk("Detected OS: %s\n", os);

    //     // 打印整个UA字符串
    //     if (ua != NULL)
    //     {
    //         printk("Full UA: %s\n", ua);
    //         kfree(ua); // 使用 kfree 释放内核内存
    //     }

    //     kfree(os); // 使用 kfree 释放内核内存
    // }
    char *ua_before = NULL;
    char *ua_after = NULL;
    char *ua = extractUserAgentAndOS(data_start, &ua_before, &ua_after);
    if (ua != NULL)
    {
        // 计算新字符串的长度
        int new_len = strlen(ua_before) + 1 + strlen(str_os) + strlen(ua_after) + 1;

        // 分配内核内存来存储新字符串
        char *mod_ua = kmalloc(new_len, GFP_KERNEL);
        if (mod_ua != NULL)
        {
            // 使用 sprintf 将三部分字符串拼凑到新字符串中
            sprintf(mod_ua, "%s(%s%s", ua_before, str_os, ua_after);

            // 打印新字符串
            if (PRINTUA)
                printk("Modified UA: %s\n", mod_ua);

            // 将新字符串复制到全局数组中
            strncpy(modified_ua, mod_ua, sizeof(modified_ua) - 1);
            // 释放内存
            kfree(mod_ua);
        }
        else
        {
            printk("Modified UA分配内存失败\n");
        }
        // 打印或处理提取的整个ua
        if (PRINTUA)
        {
            printk("Full UA: %s\n", ua);
        }

        // 打印前半部分UA
        if (ua_before != NULL)
        {
            if (PRINTUA)
            {
                printk("UA Before OS: %s\n", ua_before);
            }

            kfree(ua_before); // 使用 kfree 释放内核内存
        }

        // 打印后半部分UA
        if (ua_after != NULL)
        {
            if (PRINTUA)
                printk("UA After OS: %s\n", ua_after);
            kfree(ua_after); // 使用 kfree 释放内核内存
        }

        kfree(ua); // 使用 kfree 释放内核内存
    }
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