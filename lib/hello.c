#include <stdio.h>
#include <pcap.h>
#include <wtftp.h>

void captured(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{
	//parse wtftp
	struct wtftp_t wtftp;
	if (wtftp_parse(header, packet, &wtftp) <= 0)
	{
		return;
	}

	//print the opcode received
	printf("received: %s\n", wtftp_opcode_string(wtftp.opcode));

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

int main(int argc, char *argv[])
{
	//initialize
	if (wtftp_init(argv[1]) == -1)
	{
		return -1;
	}

	//send ping to the world
	wtftp_send_ping();

	//say hello to the world, literally
	wtftp_send_text("hello world!");

	//listen for callback
	if (wtftp_loop(captured) == -1)
	{
		wtftp_print_error("capture error");
	}

	return 0;
}
