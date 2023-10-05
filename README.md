# [**xmurp-ua**](https://github.com/newton-miku/xmurp-ua)

这是一个修改UA的openwrt内核模块，目前可处理所有非加密的数据包

大家好，我是nEwt0n_m1ku，此项目fork自[xmurp-ua](https://github.com/CHN-beta/xmurp-ua)，感谢原项目的大佬的付出

本仓库是基于原仓库的master分支，由于我的学校XPU安装部署校园网时，我已经大四了，并没有太多时间来完善此项目，仅完成了一部分功能。

以下是已完成的功能

- 自定义UA
- 修改非80端口的数据包
- 仅修改设备类型（操作系统参数），而非整个UA

------

如果有一些包不希望被改 UA，只要在防火墙规则里将 MARK 的第九位设置为 1 就可以了。例如：

```
iptables -t mangle -A PREROUTING -p tcp -m tcp --dport 80 -m mac --mac-source f8:94:c2:85:e8:14 -j MARK --set-xmark 0x100/0x100
```

在之前的版本中，使用的是 `0x1/0x1` 位，但是与 luci-app-shadowsocks 冲突，所以改到了 `0x100/0x100`。

另外，不要在 luci 中启用 flow offloading（流量分载，即 nat 加速），否则这个模块会失效。可以通过下面的命令（二选一，不需要两句都写）来对不需要这个模块的流量启用。

```
iptables -t filter -I FORWARD -p tcp ! --dport 80 ! --sport 80 -m conntrack --ctstate RELATED,ESTABLISHED -j FLOWOFFLOAD --hw
iptables -t filter -I FORWARD -p tcp ! --dport 80 ! --sport 80 -m conntrack --ctstate RELATED,ESTABLISHED -j FLOWOFFLOAD
```

两句的区别的话，大概是前者用硬件，后者用软件。具体的东西我也不熟悉。

## Todo

- [x] 自定义UA
- [x] 修改非80端口的数据包
- [x] 仅修改设备类型（操作系统参数），而非整个UA
- [ ] more?