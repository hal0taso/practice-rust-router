# practice-rust-router

## How to start
1. Install Docker Desktop

2. Build containers
```bash
$ cd workdir docker compose build
```

3. Run containers
```bash
docker compose up
```

4. See packets

### Requirements
* Docker Desktop
    * Docker Engine
    * Docker CLI client
    * Docker Compose


### Documents
Document generation by Doxigen is available. Run 
```bash
$ cd workdir/router/app/
$ doxygen
```

## What is this
This is a repository for practicing 
* Network programming

Source codes and other cofig files are from the book and url in References.

## References
* 小俣光之, "ルーター自作でわかるパケットの流れ～ソースコードで体感するネットワークのしくみ", 技術評論社, 2011
* t13801206, ["Rustでルーターを自作してみよう"](https://zenn.dev/t13801206/books/rust-router-jisaku), Zenn, 2023
