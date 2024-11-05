/**
 * @file netutil.c
 * @brief
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
    { // デバイスのフラグを取得
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