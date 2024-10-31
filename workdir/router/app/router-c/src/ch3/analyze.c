/**
 * @file analyze.c
 * @brief Chapter 3-1 キャプチャのメイン処理 - サンプルソース2: パケット解析関数群
 * @details RAWソケットを使ってデータリンク層のパケットを受信, 標準出力にEthernetヘッダを表示する
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "checksum.h"
#include "print.h"

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

/**
 * @brief APRパケットの解析
 * @details 以下の処理を行う @n
 * 1. 構造体のサイズ分のデータがあるか確認 @n
 * 2. データポインタを構造体にキャストして代入 @n
 * 3. ARPパケットの表示用関数を呼び出す
 *
 * @param data : データ
 * @param size : データ長
 * @return 0 : 正常終了
 */
int AnalyzeArp(u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct ether_arp *arp;

    ptr = data;
    lest = size;

    if (lest < sizeof(struct ether_arp))
    {
        fprintf(stderr, "lest(%d) < sizeof(struct ether_arp)\n", lest);
        return -1;
    }

    arp = (struct ether_arp *)ptr;
    ptr += sizeof(struct ether_arp);
    lest -= sizeof(struct ether_arp);

    PrintArp(arp, stdout);

    return 0;
}

/**
 * @brief ICMPパケットの解析
 * @details 以下の処理を行う @n
 * 1. 構造体のサイズ分のデータがあるか確認 @n
 * 2. データポインタを構造体にキャストして代入 @n
 * 3. ICMPパケットの表示用関数を呼び出す
 *
 * @param data : データ
 * @param size : データ長
 * @return 0 : 正常終了
 */
int AnalyzeIcmp(u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct icmp *icmp;

    ptr = data;
    lest = size;

    if (lest < sizeof(struct icmp))
    {
        fprintf(stderr, "lest(%d) < sizeof(struct icmp)\n", lest);
        return -1;
    }

    icmp = (struct icmp *)ptr;
    ptr += sizeof(struct icmp);
    lest -= sizeof(struct icmp);

    PrintIcmp(icmp, stdout);

    return 0;
}

/**
 * @brief ICMPv6パケットの解析
 * @details 以下の処理を行う @n
 * 1. 構造体のサイズ分のデータがあるか確認 @n
 * 2. データポインタを構造体にキャストして代入 @n
 * 3. ICMPv6パケットの表示用関数を呼び出す
 *
 * @param data : データ
 * @param size : データ長
 * @return 0 : 正常終了
 */
int AnalyzeIcmp6(u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct icmp6_hdr *icmp6;

    ptr = data;
    lest = size;

    if (lest < sizeof(struct icmp6_hdr))
    {
        fprintf(stderr, "lest(%d) < sizeof(struct icmp6_hdr)\n", lest);
        return -1;
    }

    icmp6 = (struct icmp6_hdr *)ptr;
    ptr += sizeof(struct icmp6_hdr);
    lest -= sizeof(struct icmp6_hdr);

    PrintIcmp6(icmp6, stdout);

    return 0;
}

/**
 * @brief TCPパケットの解析
 * @details 以下の処理を行う @n
 * 1. 構造体のサイズ分のデータがあるか確認 @n
 * 2. データポインタを構造体にキャストして代入 @n
 * 3. TCPパケットの表示用関数を呼び出す
 *
 * @param data : データ
 * @param size : データ長
 * @return 0 : 正常終了
 */
int AnalyzeTcp(u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct tcphdr *tcp;

    ptr = data;
    lest = size;

    if (lest < sizeof(struct tcphdr))
    {
        fprintf(stderr, "lest(%d) < sizeof(struct tcphdr)\n", lest);
        return -1;
    }

    tcp = (struct tcphdr *)ptr;
    ptr += sizeof(struct tcphdr);
    lest -= sizeof(struct tcphdr);

    PrintTcp(tcp, stdout);

    return 0;
}

/**
 * @brief UDPパケットの解析
 * @details 以下の処理を行う @n
 * 1. 構造体のサイズ分のデータがあるか確認 @n
 * 2. データポインタを構造体にキャストして代入 @n
 * 3. UDPパケットの表示用関数を呼び出す
 *
 * @param data : データ
 * @param size : データ長
 * @return 0 : 正常終了
 */
int AnalyzeUdp(u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct udphdr *udp;

    ptr = data;
    lest = size;

    if (lest < sizeof(struct udphdr))
    {
        fprintf(stderr, "lest(%d) < sizeof(struct udphdr)\n", lest);
        return -1;
    }

    udp = (struct udphdr *)ptr;
    ptr += sizeof(struct udphdr);
    lest -= sizeof(struct udphdr);

    PrintUdp(udp, stdout);

    return 0;
}

/**
 * @brief IPパケットの解析
 * @details 以下の処理を行う @n
 * 1. 構造体のサイズ分のデータがあるか確認 @n
 * 2. データポインタを構造体にキャストして代入 @n
 * 3. IPパケットの表示用関数を呼び出す @n
 * 4. プロトコル番号に応じてパケットの解析処理を呼び出す
 *
 * @param data : データ
 * @param size : データ長
 * @return 0 : 正常終了
 */
int AnalyzeIp(u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct iphdr *iphdr;
    u_char *option;
    int optionLen, len;
    unsigned short sum;

    ptr = data;
    lest = size;

    if (lest < sizeof(struct iphdr))
    {
        fprintf(stderr, "lest(%d) < sizeof(struct iphdr)\n", lest);
        return -1;
    }

    iphdr = (struct iphdr *)ptr;
    ptr += sizeof(struct iphdr);
    lest -= sizeof(struct iphdr);

    // IPヘッダのオプション部分を読み飛ばす
    optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
    if (optionLen > 0)
    {
        if (optionLen >= 1500)
        {
            fprintf(stderr, "IP optionLen(%d):too big\n", optionLen);
            return -1;
        }
        option = ptr;
        ptr += optionLen;
        lest -= optionLen;
    }
    // IPヘッダのチェックサムを検証
    if (checkIPchecksum(iphdr, option, optionLen) == 0)
    {
        fprintf(stderr, "bad ip checksum\n");
        return -1;
    }
    // IPヘッダの表示
    PrintIpHeader(iphdr, option, optionLen, stdout);

    // プロトコル番号に応じてパケットの解析処理を呼び出す
    if (iphdr->protocol == IPPROTO_ICMP)
    {
        len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
        // ICMPヘッダのチェックサムはICMPヘッダとデータ部分のみで計算(IPヘッダは含まない)
        sum = checksum(ptr, len);
        if (sum != 0 && sum != 0xffff)
        {
            fprintf(stderr, "bad icmp checksum\n");
            return -1;
        }
        AnalyzeIcmp(ptr, lest);
    }
    else if (iphdr->protocol == IPPROTO_TCP)
    {
        len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
        if (checkIPDATAchecksum(iphdr, ptr, len) == 0)
        {
            fprintf(stderr, "bad tcp checksum\n");
            return -1;
        }
        AnalyzeTcp(ptr, lest);
    }
    else if (iphdr->protocol == IPPROTO_UDP)
    {
        struct udphdr *udphdr;
        udphdr = (struct udphdr *)ptr;
        len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
        if (udphdr->check != 0 && checkIPDATAchecksum(iphdr, ptr, len) == 0)
        {
            fprintf(stderr, "bad udp checksum\n");
            return -1;
        }
        AnalyzeUdp(ptr, lest);
    }

    return 0;
}

/**
 * @brief IPv6パケットの解析
 * @details 以下の処理を行う @n
 * 1. 構造体のサイズ分のデータがあるか確認 @n
 * 2. データポインタを構造体にキャストして代入 @n
 * 3. IPv6パケットの表示用関数を呼び出す @n
 * 4. プロトコル番号に応じてパケットの解析処理を呼び出す
 *
 * @param data : データ
 * @param size : データ長
 * @return 0 : 正常終了
 */
int AnalyzeIpv6(u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct ip6_hdr *ip6;
    int len;

    ptr = data;
    lest = size;

    if (lest < sizeof(struct ip6_hdr))
    {
        fprintf(stderr, "lest(%d) < sizeof(struct ip6_hdr)\n", lest);
        return -1;
    }
    ip6 = (struct ip6_hdr *)ptr;
    ptr += sizeof(struct ip6_hdr);
    lest -= sizeof(struct ip6_hdr);
    // IPv6ヘッダの表示
    PrintIp6Header(ip6, stdout);

    // プロトコル番号に応じてパケットの解析処理を呼び出す. チェックサムはいずれもIPv6ヘッダを含んで計算
    if (ip6->ip6_nxt == IPPROTO_ICMPV6)
    {
        len = ntohs(ip6->ip6_plen);
        if (checkIP6DATAchecksum(ip6, ptr, len) == 0)
        {
            fprintf(stderr, "bad icmpv6 checksum\n");
            return -1;
        }
        AnalyzeIcmp6(ptr, lest);
    }
    else if (ip6->ip6_nxt == IPPROTO_TCP)
    {
        len = ntohs(ip6->ip6_plen);
        if (checkIP6DATAchecksum(ip6, ptr, len) == 0)
        {
            fprintf(stderr, "bad tcp checksum\n");
            return -1;
        }
        AnalyzeTcp(ptr, lest);
    }
    else if (ip6->ip6_nxt == IPPROTO_UDP)
    {
        len = ntohs(ip6->ip6_plen);
        if (checkIP6DATAchecksum(ip6, ptr, len) == 0)
        {
            fprintf(stderr, "bad udp checksum\n");
            return -1;
        }
        AnalyzeUdp(ptr, lest);
    }

    return 0;
}

/**
 * @brief パケットの解析
 * @details データリンク層のプロトコル番号に応じてパケットの解析処理を呼び出す
 *
 * @param data : データ
 * @param size : データ長
 * @return 0 : 正常終了
 */
int AnalyzePacket(u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct ether_header *eh;

    ptr = data;
    lest = size;

    if (lest < sizeof(struct ether_header))
    {
        fprintf(stderr, "lest(%d) < sizeof(struct ether_header)\n", lest);
        return -1;
    }
    eh = (struct ether_header *)ptr;
    ptr += sizeof(struct ether_header);
    lest -= sizeof(struct ether_header);

    if (ntohs(eh->ether_type) == ETHERTYPE_ARP)
    {
        fprintf(stderr, "Packet[%dbytes]\n", size);
        PrintEtherHeader(eh, stdout);
        AnalyzeArp(ptr, lest);
    }
    else if (ntohs(eh->ether_type) == ETHERTYPE_IP)
    {
        fprintf(stderr, "Packet[%dbytes]\n", size);
        PrintEtherHeader(eh, stdout);
        AnalyzeIp(ptr, lest);
    }
    else if (ntohs(eh->ether_type) == ETHERTYPE_IPV6)
    {
        fprintf(stderr, "Packet[%dbytes]\n", size);
        PrintEtherHeader(eh, stdout);
        AnalyzeIpv6(ptr, lest);
    }

    return 0;
}