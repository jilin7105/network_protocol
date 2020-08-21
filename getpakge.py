#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/7/29 10:51 上午
# @Author  : yyq
# @Site    : 
# @File    : getpakge.py
# @Software: PyCharm

from scapy.all import *



#抓包
def get_packet(iface,type,filter =''):

    dpkt = sniff(filter=filter, iface=iface, prn=lambda x: x.summary(), count=10)

    if type == "1" :
        time.sleep(2)
        get_packet(iface, type, filter)




if __name__ == '__main__':
    print("输入监听协议类型")
    filter = input()
    print("输入监听网卡")
    iface = input()
    print("是否循环监听 1，循环， 2，不循环 ")
    type = input()
    get_packet(iface, type , filter)