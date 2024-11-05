# Flow of packets seen in the self-made router
小俣光之, "ルーター自作でわかるパケットの流れ～ソースコードで体感するネットワークのしくみ", 技術評論社, 2011 の勉強用リポジトリ

## How to start
本書はNICが2つあるLinux環境上で動作する想定のため, Docker上で環境を用意する.

1. Docker Desktopのインストール
* https://docs.docker.com/get-started/get-docker/


2. コンテナのビルド

```bash
$ cd workdir docker compose build
```

3. コンテナの実行

```bash
docker compose up
```

`workdir/router/app/entrypoint.sh` を書き換えることで、各章で動かしたいプログラムをビルド/実行できる.


### Documents
関数の依存など全体像を把握するため、Doxygenのドキュメント生成に対応したコメントを追加している. 
Doxifileはリポジトリに同梱しているので, `workdir/router/app` 上で実行すればdoxygenを実行すると, `workdir/router/app/docs/html` 配下にドキュメントが生成される.
```bash
$ cd workdir/router/app/
$ doxygen
```

## References
* 小俣光之, "ルーター自作でわかるパケットの流れ～ソースコードで体感するネットワークのしくみ", 技術評論社, 2011
* t13801206, ["Rustでルーターを自作してみよう"](https://zenn.dev/t13801206/books/rust-router-jisaku), Zenn, 2023
