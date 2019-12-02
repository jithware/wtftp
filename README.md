# wtftp
The Wireless Trivial File Transfer Protocol (WTFTP) is a protocol for tranferring files wirelessly by broadcasting packets to all hosts listening in [monitor mode](https://en.wikipedia.org/wiki/Monitor_mode).

### Build 
To build wtftp library and wtftpd daemon
#### Eclipse Development
```shell
mkdir ./wtftp.build
cd ./wtftp.build
cmake -G"Eclipse CDT4 - Unix Makefiles" -DCMAKE_ECLIPSE_GENERATE_SOURCE_PROJECT=TRUE -DCMAKE_BUILD_TYPE=Debug ../wtftp
make
```
#### Release
```shell
mkdir ./wtftp.build
cd ./wtftp.build
cmake -G"Unix Makefiles" -DCMAKE_BUILD_TYPE=Release ../wtftp
make
```

### Set capabilities on binary to allow network capture privileges (Linux)
```shell
sudo setcap cap_net_raw,cap_net_admin=eip ./wtftpd/wtftpd
```

### Wireless configuration (Unix-like OS)
```shell
INTERFACE=wlp0s18f2u1
sudo ifconfig $INTERFACE down
sudo iwconfig $INTERFACE mode monitor
sudo ifconfig $INTERFACE mtu 2304
sudo ifconfig $INTERFACE up
sudo iwconfig $INTERFACE channel 1

```

### Sample Usage
#### Search for hosts
```shell
./wtftpd/wtftpd --interface wlp0s19f2u4 --verbose --search 5
```

#### Text host with hardware address 00:12:17:9b:c3:3e
```shell
./wtftpd/wtftpd --interface wlp0s19f2u4 --stdin --prepend myname --text 00:12:17:9b:c3:3e 
```

#### Get all files from host with hardware address 00:12:17:9b:c3:3e
```shell
./wtftpd/wtftpd --interface wlp0s19f2u4 --destination /tmp/dst --get 00:12:17:9b:c3:3e --verify --giveup 15 
```

### Wireshark Usage
