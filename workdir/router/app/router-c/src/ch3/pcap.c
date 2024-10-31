/**
 * @file pcap.c
 * @brief Chapter 3-1 キャプチャのメイン処理 - サンプルソース1: メイン処理
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
#include "analyze.h"

/**
 * @brief RAWソケットの準備
 * @details 以下の処理によりRAWソケットを準備する @n
 * 1. ソケットのファイルディスクリプタを作成 @n
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
 * @brief キャプチャ処理
 * @details キャプチャしたパケットを標準出力に表示
 *
 * @param [in] argc :
 * @param [in] argv :
 * @param [in] envp :
 */
int main(int argc, char *argv[], char *envp[])
{
    int soc, size;
    u_char buf[65535];

    if (argc <= 1)
    {
        fprintf(stderr, "pcap device-name\n");
        return 1;
    }

    if ((soc = InitRawSocket(argv[1], 0, 0)) == -1)
    {
        fprintf(stderr, "InitRawSocket:error:%s\n", argv[1]);
        return 1;
    }

    while (1)
    {
        if ((size = read(soc, buf, sizeof(buf))) <= 0)
        {
            perror("read");
        }
        else
        {
            AnalyzePacket(buf, size);
        }
    }

    close(soc);

    return 0;
}