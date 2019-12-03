/**  @file   wtftp.c
 *   @author jithware
 *   @brief API definitions
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wtftp.h>

u_int wtftp_build_80211(uint8_t *buf, uint8_t *daddr, uint8_t *hwaddr, uint8_t *bssid)
{
	u_int len = 0;

	memcpy(buf + len, "\x08\x00", 2); //Frame control = type data, subtype data
	len += 2;
	memcpy(buf + len, "\x00\x00", 2); //Duration
	len += 2;
	memcpy(buf + len, daddr, IEEE80211_ADDR_LEN); //Destination address
	len += IEEE80211_ADDR_LEN;
	memcpy(buf + len, hwaddr, IEEE80211_ADDR_LEN); //Source address
	len += IEEE80211_ADDR_LEN;
	memcpy(buf + len, bssid, IEEE80211_ADDR_LEN); //BSSID
	len += IEEE80211_ADDR_LEN;
	memcpy(buf + len, "\x00\x00", 2); //Sequence number
	len += 2;

	return len;
}

u_int wtftp_build_llc(uint8_t * buf)
{
	u_int len = 0;

	memcpy(buf + len, "\x01", 1); //DSAP = null LSAP, group address
	len += 1;
	memcpy(buf + len, "\x00", 1); //SSAP = null LSAP, command packet
	len += 1;
	memcpy(buf + len, "\x03", 1); //control field = unnumbered format
	len += 1;
	return len;
}

u_int wtftp_build_llcsnap(uint8_t * buf)
{
	u_int len = 0;

	memcpy(buf + len, "\xAA\xAA\x03\x00\x00\x00", 6); //SNAP Ethernet Type
	len += 6;

	uint16_t ethertype = htons(WTFTP_ETHERTYPE);
	memcpy(buf + len, (uint8_t *)&ethertype, sizeof(ethertype));
	len += 2;

	return len;
}

u_int wtftp_build_radiotap(uint8_t * buf)
{
	u_int len = 0;

	memcpy(buf + len, "\x00\x00\x08\x00\x00\x00\x00\x00", 8); //basic header - firmware/hardware crafts the rest
	len += 8;

	return len;
}

u_int wtftp_build_wtftp(uint8_t * buf, struct wtftp_t *wtftp)
{
	u_int len = 0;

	//opcode
	uint16_t opcode = htons(wtftp->opcode);
	memcpy(buf + len, (uint8_t *) &opcode, sizeof(opcode));
	len += sizeof(opcode);

	if (wtftp->opcode == WTFTP_OPCODE_PING || wtftp->opcode == WTFTP_OPCODE_PONG)
	{
		return len;
	}

	//uid
	memcpy(buf + len, wtftp->uid, WTFTP_UID_LEN);
	len += WTFTP_UID_LEN;

	//block
	uint64_t block = htonll(wtftp->block);
	memcpy(buf + len, (uint8_t *) &block, sizeof(block));
	len += sizeof(block);

	if (wtftp->opcode == WTFTP_OPCODE_REQFILE || wtftp->opcode == WTFTP_OPCODE_REQBLK)
	{
		return len;
	}

	//data
	uint16_t data_len = htons(wtftp->data_len);
	memcpy(buf + len, (uint8_t *) &data_len, sizeof(data_len));
	len += sizeof(data_len);
	memcpy(buf + len, wtftp->file_data, wtftp->data_len);
	len += wtftp->data_len;

	return len;
}

int wtftp_capture(pcap_handler callback)
{
	return pcap_dispatch(_pcap, 1, callback, NULL);
}

int wtftp_capture_filter(pcap_t *handle, const char *filter)
{
	struct bpf_program bpf;

	//apply filter
	if (pcap_compile(handle, &bpf, filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		pcap_perror(handle, "Error compiling filter");
		return -1;
	}
	if (pcap_setfilter(handle, &bpf) == -1)
	{
		pcap_perror(handle, "Error setting filter");
		return -1;
	}

	pcap_freecode(&bpf);

	return 0;
}

int wtftp_close()
{
	if (_pcap_dumper != NULL)
	{
		pcap_dump_close(_pcap_dumper);
		_pcap_dumper = NULL;
	}
	if (_pcap != NULL)
	{
		pcap_breakloop(_pcap);
	}
	
	return 0;
}

void wtftp_dump(const struct pcap_pkthdr *header, const u_char *packet)
{
	if (_pcap_dumper != NULL)
	{
		pcap_dump((u_char *) _pcap_dumper, header, packet);
	}
}

const char * wtftp_get_filter()
{
	return _filter;
}

const uint8_t * wtftp_get_hwaddr()
{
	return _hwaddr;
}

int wtftp_init(const char *iface)
{
	return wtftp_init_all(iface, NULL, NULL, NULL);
}

int wtftp_init_all(const char *iface, uint8_t *bssid, uint8_t *daddr, const char *capfile)
{
	char errbuf[WTFTP_ERRBUF_SIZE];
	char *addr = NULL;

	//initialize pcap
	_pcap = pcap_open_live(iface, BUFSIZ, 0, 1, errbuf);
	if (_pcap == NULL)
	{
		fprintf(stderr, "%s\n", errbuf);
		return -1;
	}

	//make sure we're capturing on wireless radio
	int datalink = pcap_datalink(_pcap);
	if (datalink != DLT_IEEE802_11_RADIO)
	{
		fprintf(stderr, "%s must be %s. %s is not supported.\n", iface, pcap_datalink_val_to_description(DLT_IEEE802_11_RADIO),
				pcap_datalink_val_to_description(datalink));
		pcap_close(_pcap);
		return -1;
	}

	if (pcap_setdirection(_pcap, PCAP_D_IN) == -1) //only want to capture incoming packets
	{
		pcap_perror(_pcap, "Error setting capture direction to in only.");
		pcap_close(_pcap);
		return -1;
	}

	if (capfile != NULL)
	{
		_pcap_dumper = pcap_dump_open(_pcap, capfile);
		if (_pcap_dumper == NULL)
		{
			pcap_perror(_pcap, "Error opening capture file.");
			pcap_close(_pcap);
			return -1;
		}
	}

	//initialize libnet
	_lnet = libnet_init(LIBNET_RAW4, iface, errbuf);
	if (_lnet == NULL)
	{
		fprintf(stderr, "%s\n", errbuf);
		pcap_close(_pcap);
		return -1;
	}

	//initialize random number generation
	if (libnet_seed_prand(_lnet) == -1)
	{
		fprintf(stderr, "%s\n", libnet_geterror(_lnet));
		pcap_close(_pcap);
		libnet_destroy(_lnet);
		return -1;
	}

	//the destination address
	if (daddr == NULL)
	{
		//set to broadcast address
		_daddr = malloc(IEEE80211_ADDR_LEN);
		memcpy(_daddr, "\xFF\xFF\xFF\xFF\xFF\xFF", IEEE80211_ADDR_LEN);
	}
	else
	{
		_daddr = daddr;
	}

	//the bssid address - see https://en.wikipedia.org/wiki/Service_set_(802.11_network)#Extended_service_set_identifier_.28ESSID.29
	if (bssid == NULL)
	{
		_bssid = malloc(IEEE80211_ADDR_LEN);

		//initialize the bssid with 46-bit random number
		int len;
		for (len = 0; len < IEEE80211_ADDR_LEN; len++)
		{
			_bssid[len] = libnet_get_prand(LIBNET_PR8);
		}
	}
	else
	{
		_bssid = bssid;
	}

	//individual/group bit of the address is always set to 0 (individual) for bssid
	BIT_CLEAR(_bssid[0], 0);
	//The universal/local bit of the address is always set to 1 (local) for bssid
	BIT_SET(_bssid[0], 1);

	//get the hardware address (source address)
	struct libnet_ether_addr *ether_addr = libnet_get_hwaddr(_lnet);
	if (ether_addr == NULL)
	{
		fprintf(stderr, "%s\n", libnet_geterror(_lnet));
		pcap_close(_pcap);
		libnet_destroy(_lnet);
		return -1;
	}
	_hwaddr = malloc(IEEE80211_ADDR_LEN);
	memcpy(_hwaddr, ether_addr->ether_addr_octet, IEEE80211_ADDR_LEN);

	//generate capture filter
	char *saddr, *daddr1, *daddr2;
	saddr = wtftp_tohex(_hwaddr, IEEE80211_ADDR_LEN);
	daddr1 = wtftp_tohex(_daddr, IEEE80211_ADDR_LEN);
	daddr2 = wtftp_tohex(_bssid, IEEE80211_ADDR_LEN);

	//see http://www.tcpdump.org/manpages/pcap-filter.7.html
	snprintf(_filter, sizeof(_filter), "(ether proto 0x%.04x) and (not wlan addr2 %s) and (wlan addr1 %s or wlan addr1 %s or wlan addr1 %s)",
			WTFTP_ETHERTYPE, saddr, daddr1, daddr2, saddr);

	free(saddr);
	free(daddr1);
	free(daddr2);

	//apply capture filter
	if (wtftp_capture_filter(_pcap, _filter) == -1)
	{
		pcap_close(_pcap);
		libnet_destroy(_lnet);
		return -1;
	}

	//build the packet header
	u_int len = 0;

	//Radiotap
	len += wtftp_build_radiotap(_buffer + len);

	//802.11
	len += wtftp_build_80211(_buffer + len, _daddr, _hwaddr, _bssid);

	//LLC
	len += wtftp_build_llcsnap(_buffer + len);

	//total header length
	_header = len;

	return 0;
}

int wtftp_loop(pcap_handler callback)
{
	return pcap_loop(_pcap, 0, callback, NULL);
}

const char * wtftp_opcode_string(u_short opcode)
{
	if (opcode > sizeof(WTFTP_STRING_OPCODES))
	{
		return "invalid";
	}

	return WTFTP_STRING_OPCODES[opcode];
}

int wtftp_parse_ieee80211(const struct pcap_pkthdr *header, const u_char *packet, struct ieee80211_packet *ieee80211)
{
	u_int len = 0;

	//parse the radio
	ieee80211->radio_header = (struct ieee80211_radiotap_header *) (packet + len);
	len += ieee80211->radio_header->it_len;

	//parse the ieee80211
	ieee80211->ieee80211_header = (struct ieee80211_frame *) (packet + len);
	len += sizeof(struct ieee80211_frame);

	/* bcp capture filter (type data subtype data and dir nods) will prevent these
	 if ((received->ieee80211_header->i_fc[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA)
	 {
	 return -1;
	 }
	 if ((received->ieee80211_header->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) != IEEE80211_FC0_SUBTYPE_DATA)
	 {
	 return -1;
	 }
	 if ((received->ieee80211_header->i_fc[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_NODS)
	 {
	 return -1;
	 }
	 */

	//parse the llc
	ieee80211->llc_header = (struct llc *) (packet + len);
	if (ieee80211->llc_header->llc_control != LLC_UI /* unnumbered format */)
	{
		return -1;
	}
	len += LLC_SNAPFRAMELEN;

	//parse the wtftp
	ieee80211->wtftp_pdu = (uint8_t *) (packet + len);
	uint16_t wtftp_data_len = header->caplen - (len + IEEE80211_CRC_LEN);
	if (wtftp_data_len > sizeof(struct wtftp_t) /* wtftp_t size */)
	{
		return -1;
	}
	len += wtftp_data_len;

	//parse the framecheck
	ieee80211->ieee80211_framecheck = (uint8_t *) (packet + len);
	len += IEEE80211_CRC_LEN;

	if (len != header->caplen)
	{
		return -1;
	}

	return len;
}

int wtftp_parse(const struct pcap_pkthdr *header, const u_char *packet, struct wtftp_t *wtftp)
{
	struct ieee80211_packet ieee80211;

	return wtftp_parse_all(header, packet, &ieee80211, wtftp);
}


int wtftp_parse_all(const struct pcap_pkthdr *header, const u_char *packet, struct ieee80211_packet *ieee80211, struct wtftp_t *wtftp)
{
	//parse 802.11
	if (wtftp_parse_ieee80211(header, packet, ieee80211) <= 0)
	{
		return -1;
	}

	uint8_t *wtftp_pdu = ieee80211->wtftp_pdu;
	u_int len = 0;

	//parse opcode
	wtftp->opcode = ntohs(*(uint16_t *) (wtftp_pdu + len));
	len += sizeof(wtftp->opcode);

	if (wtftp->opcode == WTFTP_OPCODE_PING || wtftp->opcode == WTFTP_OPCODE_PONG)
	{
		return len;
	}

	//parse uid
	memcpy(wtftp->uid, (uint8_t *) (wtftp_pdu + len), sizeof(wtftp->uid));
	len += sizeof(wtftp->uid);

	//parse block
	wtftp->block = ntohll(*(uint64_t * ) (wtftp_pdu + len));
	len += sizeof(wtftp->block);

	if (wtftp->opcode == WTFTP_OPCODE_REQFILE || wtftp->opcode == WTFTP_OPCODE_REQBLK)
	{
		return len;
	}

	//parse data length
	wtftp->data_len = ntohs(*(uint16_t *) (wtftp_pdu + len));
	len += sizeof(wtftp->data_len);

	//parse file info
	if (wtftp->opcode == WTFTP_OPCODE_FILEINFO)
	{
		memcpy(wtftp->file_info.name, (uint8_t *) (wtftp_pdu + len), sizeof(wtftp->file_info.name));
		len += sizeof(wtftp->file_info.name);
		wtftp->file_info.size = ntohll(*(uint64_t * ) (wtftp_pdu + len));
		len += sizeof(wtftp->file_info.size);
		wtftp->file_info.blocksize = ntohs(*(uint16_t *) (wtftp_pdu + len));
		len += sizeof(wtftp->file_info.blocksize);
		wtftp->file_info.type = ntohs(*(uint16_t *) (wtftp_pdu + len));
		len += sizeof(wtftp->file_info.type);
		wtftp->file_info.mtime = ntohll(*(uint64_t * ) (wtftp_pdu + len));
		len += sizeof(wtftp->file_info.mtime);

		return len;
	}

	//parse other data
	uint8_t *p = (uint8_t *) (wtftp_pdu + len);
	uint16_t data_len;
	for (data_len = 0; p != ieee80211->ieee80211_framecheck && data_len < WTFTP_MAX_DATASIZE; data_len++, p++)
	{
		wtftp->file_data[data_len] = *p;
		len++;
	}

	//check reported data len with actual
	if (wtftp->data_len != data_len)
	{
		return -1;
	}

	return len;
}

void wtftp_print_devices()
{
	pcap_if_t *dev = NULL, *devs = NULL;
	pcap_t *p = NULL;
	int datalink = 0, found = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&devs, errbuf) == -1)
	{
		fprintf(stderr, "%s\n", errbuf);
		return;
	}

	if (devs == NULL)
	{
		fprintf(stderr, "Could not find any available interfaces.\n");
		return;
	}

	for (dev = devs; dev; dev = dev->next)
	{
		p = pcap_open_live(dev->name, BUFSIZ, 0, 1, errbuf);
		if (p != NULL)
		{
			datalink = pcap_datalink(p);
			if (datalink == DLT_IEEE802_11_RADIO)
			{
				printf("%s interface: %s\n", pcap_datalink_val_to_description(DLT_IEEE802_11_RADIO), dev->name);
				found = 1;
			}
			pcap_close(p);
		}
	}

	if (!found)
	{
		fprintf(stderr, "No %s interface found from the following:\n\n", pcap_datalink_val_to_description(DLT_IEEE802_11_RADIO));
		for (dev = devs; dev; dev = dev->next)
		{
			p = pcap_open_live(dev->name, BUFSIZ, 0, 1, errbuf);
			if (p != NULL)
			{
				datalink = pcap_datalink(p);
				fprintf(stderr, "  %s is '%s'\n", dev->name, pcap_datalink_val_to_description(datalink));
				pcap_close(p);
			}
		}
		fprintf(stderr, "\n");
		fprintf(stderr, "At least one wireless interface must be available and set to monitor mode.\n");
	}

	printf("\n");

	pcap_freealldevs(devs);
}

void wtftp_print_error(const char *prefix)
{
	pcap_perror(_pcap, (char *) prefix);
}

void wtftp_print_packet(const u_char *packet, int length)
{
	u_char *p = (u_char *) packet;
	const int LINE_SIZE = 64;
	char hex[LINE_SIZE], ascii[LINE_SIZE], buf[LINE_SIZE];
	int i = 0, j = 0;

	hex[0] = '\0';
	ascii[0] = '\0';

	if (length < 1)
		return;

	while (length--)
	{
		snprintf(buf, LINE_SIZE, "%.2x ", *p);
		strncat(hex, buf, strlen(buf));

		if (isprint(*p))
		{
			snprintf(buf, LINE_SIZE, "%c", *p);
		}
		else
		{
			snprintf(buf, LINE_SIZE, ".");
		}
		strncat(ascii, buf, strlen(buf));

		p++;
		i++;

		if (i % 16 == 0 || length == 0)
		{
			printf(hex);
			if (length != 0)
			{
				printf("| ");
			}
			else
			{
				//pad the last line with spaces
				for (j = 0; j < 48 - strlen(hex); j++)
				{
					printf(" ");
				}
				printf("| ");
			}
			printf(ascii);
			printf("\n");
			hex[0] = '\0';
			ascii[0] = '\0';
		}
	}

	printf("\n");
}

void wtftp_print(struct wtftp_t *wtftp)
{
	printf("OPCODE: %s\n", wtftp_opcode_string(wtftp->opcode));

	if (wtftp->opcode == WTFTP_OPCODE_PING || wtftp->opcode == WTFTP_OPCODE_PONG)
	{
		printf("\n");
		return;
	}

	char *uid = wtftp_tohex(wtftp->uid, WTFTP_UID_LEN);
	printf("UID: %s\n", uid);
	free(uid);

	printf("BLOCK: %lld\n", wtftp->block);

	if (wtftp->opcode == WTFTP_OPCODE_REQFILE || wtftp->opcode == WTFTP_OPCODE_REQBLK)
	{
		printf("\n");
		return;
	}

	printf("DATALEN: %hi\n", wtftp->data_len);
	printf("DATA:\n");

	wtftp_print_packet(wtftp->file_data, wtftp->data_len);
}

void wtftp_rand_uid(uint8_t *uid)
{
	int i;
	for (i = 0; i < WTFTP_UID_LEN; i++)
	{
		uid[i] = libnet_get_prand(LIBNET_PR8);
	}
}

int wtftp_send(struct wtftp_t *wtftp)
{
	u_int len = _header;

	//WTFTP
	len += wtftp_build_wtftp(_buffer + len, wtftp);

	if (pcap_sendpacket(_pcap, _buffer, len) == -1)
	{
		pcap_perror(_pcap, "wtftp_send error");
		return -1;
	}

	return len;
}

int wtftp_send_fileinfo(u_char *uid, uint64_t block, struct wtftp_file_t *wtftp_file)
{
	struct wtftp_t wtftp;
	u_int len = 0;

	wtftp.opcode = WTFTP_OPCODE_FILEINFO;
	memcpy(wtftp.uid, uid, sizeof(wtftp.uid));
	wtftp.block = block;

	uint8_t *buf = wtftp.file_data;

	memcpy(buf + len, wtftp_file->name, sizeof(wtftp_file->name));
	len += sizeof(wtftp_file->name);

	uint64_t size = htonll(wtftp_file->size);
	memcpy(buf + len, (uint64_t *) &size, sizeof(size));
	len += sizeof(size);

	if (wtftp_file->blocksize < WTFTP_MIN_BLOCKSIZE || wtftp_file->blocksize > WTFTP_MAX_BLOCKSIZE)
	{
		fprintf(stderr, "Failed to send file info. Block size %d is invalid.\n", wtftp_file->blocksize);
		return -1;
	}
	uint16_t blocksize = htons(wtftp_file->blocksize);
	memcpy(buf + len, (uint16_t *) &blocksize, sizeof(blocksize));
	len += sizeof(blocksize);

	uint16_t type = htons(wtftp_file->type);
	memcpy(buf + len, (uint16_t *) &type, sizeof(type));
	len += sizeof(type);

	uint64_t mtime = htonll(wtftp_file->mtime);
	memcpy(buf + len, (uint64_t *) &mtime, sizeof(mtime));
	len += sizeof(mtime);

	wtftp.data_len = len;

	return wtftp_send(&wtftp);
}

int wtftp_send_ping()
{
	struct wtftp_t wtftp;
	wtftp.opcode = WTFTP_OPCODE_PING;

	return wtftp_send(&wtftp);
}

int wtftp_send_pong()
{
	struct wtftp_t wtftp;
	wtftp.opcode = WTFTP_OPCODE_PONG;

	return wtftp_send(&wtftp);
}

int wtftp_send_reqblk(u_char *uid, uint64_t block)
{
	struct wtftp_t wtftp;

	wtftp.opcode = WTFTP_OPCODE_REQBLK;
	memcpy(wtftp.uid, uid, WTFTP_UID_LEN);
	wtftp.block = block;

	return wtftp_send(&wtftp);
}

int wtftp_send_reqfile(u_char *uid, uint64_t block)
{
	struct wtftp_t wtftp;

	wtftp.opcode = WTFTP_OPCODE_REQFILE;
	memcpy(wtftp.uid, uid, WTFTP_UID_LEN);
	wtftp.block = block;

	return wtftp_send(&wtftp);
}

int wtftp_send_text(const char *text)
{
	struct wtftp_t wtftp;
	uint64_t i, len = strlen(text);

	wtftp.opcode = WTFTP_OPCODE_TEXT;
	wtftp_rand_uid(wtftp.uid);
	wtftp.block = 0;
	wtftp.data_len = 0;

	for (i = 0; i < len; i++)
	{
		wtftp.file_data[wtftp.data_len] = text[i];
		wtftp.data_len++;
		if (wtftp.data_len == WTFTP_MAX_DATASIZE)
		{
			if (wtftp_send(&wtftp) == -1)
			{
				return -1;
			}
			wtftp.block++;
			wtftp.data_len = 0;
		}
	}

	if (wtftp.data_len > 0)
	{
		if (wtftp_send(&wtftp) == -1)
		{
			return -1;
		}
	}

	return len;

}

char *wtftp_tohex(const u_char *bytes, u_char len)
{
	if (len < 1)
		return NULL;

	char *hex = malloc(len * 3 + 1);
	hex[0] = '\0';
	char buf[4];

	u_char *p = (u_char *) bytes;

	while (len--)
	{
		snprintf(buf, sizeof(buf), "%.2x:", *p);
		strncat(hex, buf, strlen(buf));
		p++;
	}

	//remove trailing ":"
	hex[strlen(hex) - 1] = '\0';

	return hex; //caller responsible for freeing memory
}
