#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/7/29 11:30 下午
# @Author  : yyq
# @Site    : 
# @File    : syn.py
# @Software: PyCharm
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr

# 三次握手机制
# 1 客户端发送syn  2.服务端 发送syn/ack  3.客户端发送ack
# 如果服务器应答ack 标示端口开放
def tcp_scan(target_ip, start_port, end_sport):
    temp = sr(IP(dst=target_ip) /
              TCP(dport=(int(start_port), int(end_sport)), flags="S"),
              timeout=3, verbose=False)

    result = temp[0].res
    for i in range(len(result)):
        if result[i][1].haslayer(TCP):
            tcp_pack = result[i][1].getlayer(TCP).fields

            if tcp_pack["flags"] == 18:
                print(target_ip + " " + str(tcp_pack["sport"]) + " open")


if __name__ == '__main__':
    print("请输入ip")
    ip = input()
    '''49.233.216.156'''
    tcp_scan(ip, '1', '100')
