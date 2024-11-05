/**
 * @file netutil.c
 * @brief ネットワーク関連のユーティリティ関数
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

extern int DebugPrintf(char *fmt, ...);
extern int DebugPerror(char *msg);

/**
 * @brief RAWソケットの準備
 * @details 1. ソケットのファイルディスクリプタを作成 @n
 * 2. ネットワークインターフェースのインデックス番号を取得 @n
 * 3. ソケットにネットワークインターフェースをバインド @n
 *
 * @param [in] device : ネットワークインターフェース名
 * @param [in] promiscFlag : プロミスキャスモードにするかどうかのフラグ
 * @param [in] ipOnly : IPパケットのみを対象とするかどうかのフラグ
 * @return soc : ソケットのファイルディスクリプタ
 */
int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{
    // ifreq 構造体 : ネットワークインターフェースの情報を格納する構造体 (net/if.h で定義)
    // struct ifreq
    // {
    //     char ifr_name[IFNAMSIZ]; /* インターフェース名 */
    //     union
    //     {
    //         struct sockaddr ifr_addr; /* アドレス */
    //         struct sockaddr ifr_dstaddr; /* 宛先アドレス */
    //         struct sockaddr ifr_broadaddr; /* ブロードキャストアドレス */
    //         struct sockaddr ifr_netmask; /* ネットマスク */
    //         struct sockaddr ifr_hwaddr; /* ハードウェアアドレス */
    //         short ifr_flags; /* フラグ */
    //         int ifr_ifindex; /* インターフェースインデックス */
    //         int ifr_metric; /* メトリック */
    //         int ifr_mtu; /* MTU */
    //         struct ifmap ifr_map; /* メモリマップ */
    //         char ifr_slave[IFNAMSIZ]; /* スレーブ */
    //         char ifr_newname[IFNAMSIZ]; /* 新しい名前 */
    //         char *ifr_data; /* データ */
    //     };
    // };
    struct ifreq ifreq;
    // sockaddr_ll 構造体 : データリンク層のアドレスを格納する構造体(netpacket/packet.h で定義)
    // struct sockaddr_ll
    // {
    //     unsigned short sll_family;   /* ファミリー */
    //     unsigned short sll_protocol; /* プロトコル */
    //     int sll_ifindex;             /* インターフェースインデックス */
    //     unsigned short sll_hatype;   /* ハードウェアタイプ */
    //     unsigned char sll_pkttype;   /* パケットタイプ */
    //     unsigned char sll_halen;     /* ハードウェアアドレス長 */
    //     unsigned char sll_addr[8];   /* ハードウェアアドレス */
    // };
    struct sockaddr_ll sa;
    int soc;
    // ソケット soc のファイルディスクリプタを作成
    // データリンク層のパケットを扱うために第一引数(プロトコルファミリー)に PF_PACKET を指定, 第二引数(通信方式)に SOCK_RAW を指定
    if (ipOnly)
    { // IPパケットのみを対象とする場合は, 第三引数(プロトコル)に ETH_P_IP を指定
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
        {
            DebugPerror("socket");
            return -1;
        }
    }
    else
    { // すべてのパケットを対象とする場合は, 第三引数(プロトコル)に ETH_P_ALL を指定
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        {
            DebugPerror("socket");
            return -1;
        }
    }
    // ifreq のメモリ領域をクリア
    memset(&ifreq, 0, sizeof(struct ifreq));
    // ネットワークインターフェース名を設定
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
    // ネットワークインターフェースのインデックス番号を取得
    if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0)
    { // インデックス番号の取得に失敗した場合
        DebugPerror("ioctl:SIOCGIFINDEX");
        close(soc);
        return -1;
    }
    // プロトコルファミリーを PF_PACKET に設定
    sa.sll_family = PF_PACKET;
    // プロトコルを設定
    if (ipOnly)
    { // IPパケットのみを対象とする場合
        sa.sll_protocol = htons(ETH_P_IP);
    }
    else
    { // すべてのパケットを対象とする場合
        sa.sll_protocol = htons(ETH_P_ALL);
    }
    // ネットワークインターフェースのインデックス番号を設定
    sa.sll_ifindex = ifreq.ifr_ifindex;
    // ソケット soc にネットワークインターフェースをバインド
    // ここで soc が指定したネットワークインターフェースに関連付けられる
    if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        DebugPerror("bind");
        close(soc);
        return -1;
    }
    // プロミスキャスモードの設定
    if (promiscFlag)
    {
        // デバイスのフラグを取得
        if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0)
        {
            DebugPerror("ioctl:SIOCGIFFLAGS");
            close(soc);
            return -1;
        }
        // プロミスキャスモードのbitを立てる
        ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
        if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0)
        { // デバイスのフラグを設定
            DebugPerror("ioctl:SIOCSIFFLAGS");
            close(soc);
            return -1;
        }
    }
    return soc;
}

/**
 * @brief ネットワークインターフェースのMACアドレス, ユニキャストアドレス, サブネット, ネットマスクを取得
 *
 * @param [in] device : ネットワークインターフェース名
 * @param [out] hwaddr : MACアドレス
 * @param [out] uaddr : ユニキャストアドレス
 * @param [out] subnet : サブネット
 * @param [out] mask : ネットマスク
 * @return 0 : 正常終了
 */
int GetDeviceInfo(char *device, u_char hwaddr[6], struct in_addr *uaddr, struct in_addr *subnet, struct in_addr *mask)
{
    struct ifreq ifreq;
    struct sockaddr_in addr;
    int soc;
    u_char *p;

    // ソケット soc のファイルディスクリプタを作成
    // データリンク層のパケットを扱うために第一引数(プロトコルファミリー)に PF_PACKET を指定, 第二引数(通信方式)に SOCK_RAW を指定
    if ((soc = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        DebugPerror("socket");
        return -1;
    }
    // ifreq のメモリ領域をクリア
    memset(&ifreq, 0, sizeof(struct ifreq));
    // ネットワークインターフェース名を設定
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
    // ネットワークインターフェースのMACアドレスを取得
    if (ioctl(soc, SIOCGIFHWADDR, &ifreq) == -1)
    { // MACアドレスの取得に失敗した場合
        DebugPerror("ioctl:SIOCGIFHWADDR");
        close(soc);
        return -1;
    }
    else
    {
        p = (u_char *)&ifreq.ifr_hwaddr.sa_data;
        memcpy(hwaddr, p, 6);
    }

    // ネットワークインターフェースのユニキャストアドレスを取得
    if (ioctl(soc, SIOCGIFADDR, &ifreq) == -1)
    { // ユニキャストアドレスの取得に失敗した場合
        DebugPerror("ioctl:SIOCGIFADDR");
        close(soc);
        return -1;
    }
    else if (ifreq.ifr_addr.sa_family != PF_INET)
    {
        DebugPrintf("%s not PF_INET\n", device);
        close(soc);
        return -1;
    }
    else
    {
        memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
        *uaddr = addr.sin_addr;
    }

    // ネットワークインターフェースのサブネットマスクを取得
    if (ioctl(soc, SIOCGIFNETMASK, &ifreq) == -1)
    { // サブネットの取得に失敗した場合
        DebugPerror("ioctl:SIOCGIFNETMASK");
        close(soc);
        return -1;
    }
    else
    {
        memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
        *mask = addr.sin_addr;
    }

    subnet->s_addr = ((uaddr->s_addr) & (mask->s_addr));

    close(soc);
    return 0;
}

/**
 * @brief MACアドレスを文字列に変換
 * @details デバッグ用にMACアドレスを文字列に変換する
 *
 * @param [in] hwaddr : MACアドレス
 * @param [out] buf : MACアドレスを格納するバッファ
 * @param [in] size : MACアドレスを格納するバッファのサイズ
 * @return buf : MACアドレスを格納したバッファ
 */
char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return buf;
}

/**
 * @brief IPアドレスを文字列に変換(struct in_addr用)
 * @details デバッグ用にIPアドレスを文字列に変換する
 *
 * @param [in] addr : IPアドレス
 * @param [out] buf : IPアドレスを格納するバッファ
 * @param [in] size : IPアドレスを格納するバッファのサイズ
 * @return buf : IPアドレスを格納したバッファ
 */
char *my_inet_ntoa_r(struct in_addr *addr, char *buf, socklen_t size)
{
    inet_ntop(PF_INET, addr, buf, size);
    return buf;
}

/**
 * @brief IPアドレスを文字列に変換(struct in_addr_t用)
 * @details デバッグ用にIPアドレスを文字列に変換する
 *
 * @param [in] addr : IPアドレス
 * @param [out] buf : IPアドレスを格納するバッファ
 * @param [in] size : IPアドレスを格納するバッファのサイズ
 * @return buf : IPアドレスを格納したバッファ
 */
char *in_addr_t2str(in_addr_t addr, char *buf, socklen_t size)
{
    struct in_addr a;
    a.s_addr = addr;
    inet_ntop(PF_INET, &a, buf, size);
    return buf;
}

/**
 * @brief イーサネットヘッダの表示
 * @details Ethernetパケットのイーサネットヘッダの情報を表示する
 *
 * @param [in] eh : Ethernetパケットのアドレス
 * @param [in] fp : 出力先ファイルポインタ
 * @return 0 : 正常終了
 */
int PrintEtherHeader(struct ether_header *eh, FILE *fp)
{
    char buf[80];
    fprintf(fp, "ether_header----------------------------------------------------\n");
    fprintf(fp, "ether_dhost=%s\n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
    fprintf(fp, "ether_shost=%s\n", my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
    fprintf(fp, "ether_type=%02X", ntohs(eh->ether_type));
    switch (ntohs(eh->ether_type))
    {
    case ETH_P_IP:
        fprintf(fp, "(IP)\n");
        break;
    case ETH_P_IPV6:
        fprintf(fp, "(IPv6)\n");
        break;
    case ETH_P_ARP:
        fprintf(fp, "(ARP)\n");
        break;
    default:
        fprintf(fp, "(unknown)\n");
        break;
    }
    return 0;
}

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
    struct iphdr iptmp;
    unsigned short sum;

    memcpy(&iptmp, iphdr, sizeof(struct iphdr));

    if (optionLen == 0)
    {
        sum = checksum((u_char *)&iptmp, sizeof(struct iphdr));
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
        sum = checksum2((u_char *)&iptmp, sizeof(struct iphdr), option, optionLen);
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

typedef struct
{
    struct ether_header eh;
    struct ether_arp arp;
} PACKET_ARP;

/**
 * @brief ARPリクエスト送信関数
 *
 * @param[in] soc : ソケット
 * @param[in] target_ip : ターゲットIPアドレス
 * @param[in] target_mac : ターゲットMACアドレス
 * @param[in] my_ip : 自分のIPアドレス
 * @param[in] my_mac : 自分のMACアドレス
 * @return 0 : 正常終了
 */
int SendArpRequestB(int soc, in_addr_t target_ip, u_char target_mac[6], in_addr_t my_ip, u_char my_mac[6])
{
    PACKET_ARP arp;
    int total;
    u_char *p;
    u_char buf[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    union
    {
        unsigned long l;
        u_char c[4];
    } lc;
    int i;

    arp.arp.arp_hrd = htons(ARPHRD_ETHER);
    arp.arp.arp_pro = htons(ETHERTYPE_IP);
    arp.arp.arp_hln = 6;
    arp.arp.arp_pln = 4;
    arp.arp.arp_op = htons(ARPOP_REQUEST);

    for (i = 0; i < 6; i++)
    {
        arp.arp.arp_sha[i] = my_mac[i];
    }
    for (i = 0; i < 6; i++)
    {
        arp.arp.arp_tha[i] = 0;
    }
    lc.l = my_ip;
    for (i = 0; i < 4; i++)
    {
        arp.arp.arp_spa[i] = lc.c[i];
    }
    lc.l = target_ip;
    for (i = 0; i < 4; i++)
    {
        arp.arp.arp_tpa[i] = lc.c[i];
    }

    arp.eh.ether_dhost[0] = target_mac[0];
    arp.eh.ether_dhost[1] = target_mac[1];
    arp.eh.ether_dhost[2] = target_mac[2];
    arp.eh.ether_dhost[3] = target_mac[3];
    arp.eh.ether_dhost[4] = target_mac[4];
    arp.eh.ether_dhost[5] = target_mac[5];

    arp.eh.ether_shost[0] = my_mac[0];
    arp.eh.ether_shost[1] = my_mac[1];
    arp.eh.ether_shost[2] = my_mac[2];
    arp.eh.ether_shost[3] = my_mac[3];
    arp.eh.ether_shost[4] = my_mac[4];
    arp.eh.ether_shost[5] = my_mac[5];

    arp.eh.ether_type = htons(ETHERTYPE_ARP);

    memset(buf, 0, sizeof(buf));
    p = buf;
    memcpy(p, &arp.eh, sizeof(struct ether_header));
    p += sizeof(struct ether_header);
    memcpy(p, &arp.arp, sizeof(struct ether_arp));
    p += sizeof(struct ether_arp);
    total = p - buf;

    write(soc, buf, total);

    return 0;
}