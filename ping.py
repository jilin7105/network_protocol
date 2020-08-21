#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/7/29 12:36 上午
# @Author  : yyq
# @Site    : 
# @File    : ping.py
# @Software: PyCharm
import hashlib
import ipaddress

# CIDR
import multiprocessing
import time

SUCCESS = 100001
ERROR = 100002

from scapy.layers.inet import IP, ICMP
# 使用当前时间md5
from scapy.sendrecv import sr1


def random_str_byte():
    temp = hashlib.md5()
    temp.update(bytes(str(time.time()), encoding='utf-8'))
    res = temp.hexdigest()
    return bytes(res, encoding="utf-8")


def get_ip_list(ip):
    temp = ipaddress.ip_network(ip, False).hosts()
    ip_list = []
    for item in temp:
        ip_list.append(str(item))

    return ip_list


def ping(target_ip):
    '''使用ip协议'''
    package = IP(dst=target_ip)/ICMP()/random_str_byte()
    res = sr1(package, timeout=3, verbose=False)  # 发送并接收一个返回的数据包
    # 因为数据包没有返回数据就是失败
    if res:
        return target_ip, SUCCESS
    else:
        return target_ip, ERROR


def do_scan(target_ip, thread_num):
    print("多线程工作中......")
    ip_list = get_ip_list(target_ip)
    pool = multiprocessing.Pool(processes=int(thread_num))
    result = pool.map(ping, ip_list)
    pool.close()
    pool.join()
    for ip, res in result:
        if res == SUCCESS:
            print(ip, SUCCESS, "\n")


#ping 网段内所有ip
if __name__ == '__main__':
    print("请输入ip地址" , "192.168.199.1/24")
    ip = input()
    do_scan(ip ,1)

'''sudo python ping.py'''