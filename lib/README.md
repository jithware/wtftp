# WTFTP Library Documentation
## Introduction
This is a guide to building applications using the Wireless Trivial File Transfer Protocol (WTFTP) library. If your already viewing this as generated doxygen documentation, skip to the next section below.

If you haven't already done so, run the cmake build as described in the top level [README.md ](../README.md )file. To build the full documentation, run:
```shell
make doc
```
Navigate to the generated html directory and open the index.html file in your browser.

## Sample Hello World Program
Described below is a simple c implementation of the WTFTP library. Here we will initialize libwtftp, respond to any pings with a pong, and print any text received to the screen.

First, initialize libwtftp. The first argument to program will be the wireless interface to capture on:
```c
int main(int argc, char *argv[])
{
	//initialize
	if (wtftp_init(argv[1]) == -1)
	{
		return -1;
	}

	return 0;
}
```
Next, we call the wtftp functions to send a ping and "hello world!" text:
```c
int main(int argc, char *argv[])
{
	...
	
	//send ping to the world
	wtftp_send_ping();

	//say hello to the world, literally
	wtftp_send_text("hello world!");

	...
}
```
Every wtftp implementation must have a callback function to tell how to handle any wtftp packets we receive. First, we parse the packet into a wtftp_t structure:
```c
void captured(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{
	//parse wtftp
	struct wtftp_t wtftp;
	if (wtftp_parse(header, packet, &wtftp) <= 0)
	{
		return;
	}
}

int main(int argc, char *argv[])
{
	...
}
```
Next, we print out what type of wtftp packet we received:
```c
void captured(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{
	...
	
	//print the opcode received
	printf("received: %s\n", wtftp_opcode_string(wtftp.opcode));
}

...
```
In the callback, we determine which type of wtftp packet we received, respond to all pings with a pong or print any text to the screen:
```c
void captured(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{
	...
	
	//check type of wtftp
	switch (wtftp.opcode)
	{
		case WTFTP_OPCODE_PING:
			//tell everyone I am here
			wtftp_send_pong();
			break;

		case WTFTP_OPCODE_TEXT:
			//print out the text
			printf("%s\n", wtftp.file_data);
			break;

		default:
			break;
	}
}

...
```
Lastly, we setup a loop to listen for packets, using our callback function and printing out any errors we receive:
```c
int main(int argc, char *argv[])
{
	...
	
	//listen for callback
	if (wtftp_loop(captured) == -1)
	{
		wtftp_print_error("capture error");
	}

	...
}
```
Using gcc, compile the file. Both pcap and libnet are required libraries so be sure to link to them in the build:
```shell
gcc hello.c -I . -lpcap -lnet ./libwtftp.a -o hello

```
Because we are capture raw network packets we must also allow the program to do so. You can either run the program as root (not recommended), or if your os will allow, set the capabilities:
```shell
sudo setcap cap_net_raw,cap_net_admin=eip ./hello
```
We also need to make sure the wireless interface we are using is set to "monitor" mode (captures all wireless packets) and each host is on the same channel. If your os will allow, set these using:
```shell
INTERFACE=wlp0s19f2u4
ifconfig $INTERFACE down
iwconfig $INTERFACE mode monitor
ifconfig $INTERFACE up
iwconfig $INTERFACE channel 1

```
Optionally we can set the Maximum Transmission Unit (MTU) to the maximum allowed for wireless:
```shell
ifconfig $INTERFACE mtu 2304

```
On two **different** wireless hosts, execute the hello program with the wireless interface to listen on (pressing Control-C terminates the program):
```shell
./hello wlp0s19f2u4

```
On the first host you will see the received ping and printed text:
```shell
received: Ping
received: File Text
hello world!
^C
```
On the second host you will see the received pong:
```shell
received: Pong
^C
```