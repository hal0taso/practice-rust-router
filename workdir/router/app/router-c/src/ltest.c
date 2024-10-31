/**
 * @file ltest.c
 * @brief Chapter 2-1 Sample program of Data Link Layer
 * @details
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
            perror("socket");
            return -1;
        }
    }
    else
    { // すべてのパケットを対象とする場合は, 第三引数(プロトコル)に ETH_P_ALL を指定
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        {
            perror("socket");
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
        perror("ioctl:SIOCGIFINDEX");
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
        perror("bind");
        close(soc);
        return -1;
    }
    // プロミスキャスモードの設定
    if (promiscFlag)
    { // デバイスのフラグを取得
        if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0)
        {
            perror("ioctl:SIOCGIFFLAGS");
            close(soc);
            return -1;
        }
        // プロミスキャスモードのbitを立てる
        ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
        if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0)
        { // デバイスのフラグを設定
            perror("ioctl:SIOCSIFFLAGS");
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

/**
 * @brief メイン関数
 * @details
 */
int main(int argc, char *argv[])
{
    int soc, size;
    u_char buf[2048];
    if (argc <= 1)
    {
        fprintf(stderr, "ltest device-name\n");
        return 1;
    }
    if ((soc = InitRawSocket(argv[1], 0, 0)) == -1)
    {
        fprintf(stderr, "InitRawSocket:error:%s\n", argv[1]);
        return 1;
    }
    while (1)
    {
        struct sockaddr_ll from;
        socklen_t fromLen;
        memset(&from, 0, sizeof(from));

        if ((size = recvfrom(soc, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromLen)) <= 0)
        {
            perror("recvfrom");
        }
        else
        {
            printf("sll_family=%u\n", from.sll_family);
            printf("sll_protocol=%04x\n", ntohs(from.sll_protocol));
            printf("sll_ifindex=%d\n", from.sll_ifindex);
            printf("sll_hatype=%02x\n", from.sll_hatype);
            printf("sll_pkttype=%02x\n", from.sll_pkttype);
            printf("sll_halen=%02x\n", from.sll_halen);
            printf("sll_addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
                   from.sll_addr[0], from.sll_addr[1], from.sll_addr[2],
                   from.sll_addr[3], from.sll_addr[4], from.sll_addr[5]);
            if (size >= sizeof(struct ether_header))
            {
                PrintEtherHeader((struct ether_header *)buf, stdout);
            }
            else
            {
                fprintf(stderr, "read size(%d) < %ld\n", size, sizeof(struct ether_header));
            }
        }
    }

    close(soc);

    return 0;
}