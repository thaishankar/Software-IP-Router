CONTENTS
********
This tar package contains
1.header.h - (setting DYNAMIC flag to 1 allows dynamic routing)
2.routing.c - Has all functionalities related to routing table operations
3.func_util.c - general functions for libpcap
4.lab8_4node.ns (NS file for switch rate and throughput)
5.router.c - main file which creates threads for all interfaces
6.arptable.txt
7.routing_table.txt
8.makefile

COMPILATION PROCEDURE
**********************
- Untar the package using tar -zxvf package.tat.gz
- make all
- run sudo taskset -c 0,1,2,3 ./router 
- run iperf on all the nodes as mentioned in the topology 