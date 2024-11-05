/**
 * @file checksum.c
 * @brief Chapter 3-1 キャプチャのメイン処理 - サンプルソース3: チェックサム計算関数群
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

struct pseudo_ip
{
    struct in_addr ip_src;
    struct in_addr ip_dst;
    unsigned char dummy;
    unsigned char ip_p;
    unsigned short ip_len;
};

struct pseudo_ip6_hdr
{
    struct in6_addr src;
    struct in6_addr dst;
    unsigned long plen;
    unsigned short dmy1;
    unsigned char dmy2;
    unsigned char nxt;
};

/**
 * @brief チェックサム計算関数
 * @details チェックサムを計算する @n
 * 1. 対象のパケットに対して, 16ビットごとの1の補数和を計算 @n
 * 2. 計算結果の1の補数を取る @n
 *
 * @param [in] data : パケットデータ
 * @param [in] len : パケットデータ長
 * @return チェックサム
 */
u_int16_t checksum(u_char *data, int len)
{
    register u_int32_t sum;
    register u_int16_t *ptr;
    register int c;

    sum = 0;
    ptr = (u_int16_t *)data;
    // 2byte(16bit)ずつ加算
    for (c = len; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    // cが奇数byteだと, 8bit分を0埋めして16bitにして加算
    if (c == 1)
    {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

/**
 * @brief 2つのデータ data1 と data2 のチェックサム計算関数
 *
 * @param [in] data1 : パケットデータ1
 * @param [in] len1 : パケットデータ1長
 * @param [in] data2 : パケットデータ2
 * @param [in] len2 : パケットデータ2長
 * @return チェックサム
 */
u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2)
{
    register u_int32_t sum;
    register u_int16_t *ptr;
    register int c;

    sum = 0;
    ptr = (u_int16_t *)data1;
    // 2byte(16bit)ずつ加算
    for (c = len1; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1)
    { // data1が奇数byte長の場合, data2の先頭1byteを16bitにして加算
        u_int16_t val;
        val = ((*ptr) << 8) + (*data2);
        sum += val;
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr = (u_int16_t *)(data2 + 1);
        len2--;
    }
    else
    {
        ptr = (u_int16_t *)data2;
    }
    // 残りのdata2を16bitごとに加算
    for (c = len2; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1)
    {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

/**
 * @brief IPヘッダのチェックサム計算関数
 *
 * @param [in] iphdr : IPヘッダ
 * @param [in] option : IPオプション
 * @param [in] optionLen : IPオプション長
 * @return 1 : 正常, 0 : 異常
 */
int checkIPchecksum(struct iphdr *iphdr, u_char *option, int optionLen)
{
    unsigned short sum;
    if (optionLen == 0)
    {
        sum = checksum((u_char *)iphdr, sizeof(struct iphdr));
        if (sum == 0 || sum == 0xFFFF)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        sum = checksum2((u_char *)iphdr, sizeof(struct iphdr), option, optionLen);
        if (sum == 0 || sum == 0xFFFF)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
}

/**
 * @brief IPのTCP, UDPのチェックサム計算関数　
 * @details IPヘッダとデータ部分を合わせてチェックサムを計算する
 *
 * @param [in] iphdr : IPヘッダ
 * @param [in] data : データ部分
 * @param [in] len : データ部分長
 * @return 1 : 正常, 0 : 異常
 */
int checkIPDATAchecksum(struct iphdr *iphdr, unsigned char *data, int len)
{
    struct pseudo_ip p_ip;
    unsigned short sum;
    memset(&p_ip, 0, sizeof(struct pseudo_ip));
    p_ip.ip_src.s_addr = iphdr->saddr;
    p_ip.ip_dst.s_addr = iphdr->daddr;
    p_ip.ip_p = iphdr->protocol;
    p_ip.ip_len = htons(len);
    sum = checksum2((u_char *)&p_ip, sizeof(struct pseudo_ip), data, len);
    if (sum == 0 || sum == 0xFFFF)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

/**
 * @brief IPv6のTCP, UDPのチェックサム計算関数
 * @details IPv6ヘッダとデータ部分を合わせてチェックサムを計算する
 *
 * @param [in] ip6 : IPv6ヘッダ
 * @param [in] data : データ部分
 * @param [in] len : データ部分長
 * @return 1 : 正常, 0 : 異常
 */
int checkIP6DATAchecksum(struct ip6_hdr *ip6, unsigned char *data, int len)
{
    struct pseudo_ip6_hdr p_ip6;
    unsigned short sum;
    memset(&p_ip6, 0, sizeof(struct pseudo_ip6_hdr));
    memcpy(&p_ip6.src, &ip6->ip6_src, sizeof(struct in6_addr));
    memcpy(&p_ip6.dst, &ip6->ip6_dst, sizeof(struct in6_addr));
    p_ip6.plen = ip6->ip6_plen;
    p_ip6.nxt = ip6->ip6_nxt;
    sum = checksum2((unsigned char *)&p_ip6, sizeof(struct pseudo_ip6_hdr), data, len);
    if (sum == 0 || sum == 0xFFFF)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}