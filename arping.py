#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/7/28 10:54 下午
# @Author  : yyq
# @Site    :
# @File    : arping.py
# @Software: PyCharm
import os
import re
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, srp1


#arp 协议 广播，根据ip获取mac地址
#匹配mac地址正则
PATTERN="\w\w:\w\w:\w\w:\w\w:\w\w:\w\w"
UNKOWN_MAC = "ff:ff:ff:ff:ff:ff"
#寻找mac地址方法
def get_mac_address(network):
    temp = os.popen("ifconfig " + network)
    res =  temp.readlines()
    for item in res:
        #正则匹配
        condition = re.search(PATTERN , item)
        if condition:
            return condition.group(0)

#获取ip列表
def get_ip_list(ip):
    temp = str(ip).split(".")
    ip_list = []
    for i in range(1,255):
        ip_list.append(temp[0]+"."+temp[1]+"." +temp[2]+"." +str(i) )
    return ip_list

def arp_scan(local_ip ,  network = "en0"):
    mac = get_mac_address(network)
    ip_list = get_ip_list(local_ip)
    print(mac ,ip_list)
    # packet = Ether(src=mac , dst=UNKOWN_MAC) / ARP(op=1, pdst=ip_list, hwdst=local_ip)
    # response, _ = srp(packet, timeout=1, verbose=False)

    # #本地mac地址   目标mac地址      1代表请求2响应
    #报错sudo chmod  -R 777 bpf*
    temp = srp(Ether(src=mac , dst=UNKOWN_MAC)/
               ARP(op=1 , hwsrc=UNKOWN_MAC ,psrc=local_ip,pdst=ip_list),
               iface=network, timeout=1, verbose=True)
    res = temp[0].res
    res_list = []
    num = len(res)
    for i in range(num):
        #获取响应目标IP地址
        res_ip = res[i][1].getlayer(ARP).fields['psrc']
        #获取响应mac地址
        res_mac = res[i][1].getlayer(ARP).fields['hwsrc']
        res_list.append((res_ip,res_mac))
    return res_list

#发布arp广播，获取ip和mac对应关系
if __name__ == '__main__':
    print("请输入ip:")
    ip = input()
    print("请输入network")
    network = input()

    res=  arp_scan(ip,network)
    for i in res :
        print(i[0],i[1],"\n")


    # mac = get_mac_address("en0")
    # print(mac)
    # ip_list = get_ip_list("192.168.1.1")
    # print(ip_list)

