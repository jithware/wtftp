/**  @file wtftp.h
 *   @author jithware
 *   @brief Public API declarations
 */

#ifndef WTFTP_H
#define WTFTP_H

#include <stdint.h>
#include <pcap.h>
#include <libnet.h>

#include <ieee80211.h>
#include <ieee802_11_radio.h>
#include <if_llc.h>

/**
 * Global variables
 * @defgroup variables Variables
 * @{
 */
/** local hardware address */
static uint8_t *_hwaddr = NULL;
/** bssid address */
static uint8_t *_bssid = NULL;
/** destination hardware address */
static uint8_t *_daddr = NULL;
/** pcap pointer */
static pcap_t *_pcap = NULL;
/** pcap file dump pointer */
static pcap_dumper_t *_pcap_dumper = NULL;
/** pcap filter pointer */
static char _filter[256] = "";
/** libnet pointer */
static libnet_t *_lnet = NULL;
/** packet buffer */
static uint8_t _buffer[4096];
/** length of header in packet buffer */
static uint8_t _header = 0;
/** @} variables */

/**
 * Constants
 * @defgroup constants Constants
 * @{
 */

/**
 * WTFTP constant values
 *
 * @defgroup values Constant Values
 * @ingroup constants
 * @{
 */

/** The ethertype used for wtftp */
#define WTFTP_ETHERTYPE	0x88B5 //Local Experimental Ethertype 1 (or 0x88B6) //TODO: make this 'official'
/** The default error buffer size */
#define WTFTP_ERRBUF_SIZE 256
/** The size of the unique identification field */
#define WTFTP_UID_LEN 20
/** The maximum data size */
#define WTFTP_MAX_DATASIZE 2048
/** The maximum transmission unit (see https://en.wikipedia.org/wiki/Maximum_transmission_unit) */
#define WTFTP_MTU 2304
/** The minimum file block size */
#define WTFTP_MIN_BLOCKSIZE 256
/** The default file block size */
#define WTFTP_DEFAULT_BLOCKSIZE 512
/** The maximum file block size */
#define WTFTP_MAX_BLOCKSIZE 2048
/** The size of the filename field */
#define WTFTP_FILENAME_LEN 256
/** The opcodes formatted as strings */
static char const * WTFTP_STRING_OPCODES[] = {"Null", "Ping", "Pong", "File Info", "File Request", "Block Request", "File Data", "End of File", "File Text", "File Stream"};
/** @} constants/values */

/**
 * Performs modification of single bits
 * a = target variable, b = bit number to act upon 0-n
 *
 * @defgroup bits Bit Manipulation
 * @ingroup constants
 * @{
 */
#define BIT_SET(a,b) ((a) |= (1<<(b)))
#define BIT_CLEAR(a,b) ((a) &= ~(1<<(b)))
#define BIT_FLIP(a,b) ((a) ^= (1<<(b)))
#define BIT_CHECK(a,b) ((a) & (1<<(b)))
/** @} constants/bits */

/**
 * Performs transformation of 64 bit network byte order
 *
 * @defgroup order Network Order
 * @ingroup constants
 * @{
 */
#define ntohll(x) ( ( (uint64_t)(ntohl( (uint32_t)((x << 32) >> 32) )) << 32) | ntohl( ((uint32_t)(x >> 32)) ) )
#define htonll(x) ntohll(x)
/** @} constants/order */

/** @} constants */

/**
 * All structs
 * @defgroup structs Structs
 * @{
 */
/**
 * Holds information about a file. This is sent in the data of a @c wtftp_t type
 */
struct wtftp_file_t {
	uint8_t		name[WTFTP_FILENAME_LEN];
	uint64_t	size;
	uint16_t	blocksize;
	uint16_t	type;
	uint64_t	mtime;
};

/**
 * All wtftp packets have the following structure:
 *
@verbatim
 2 bytes         20 bytes             8 bytes       2 bytes               1 - 2048
 --------------------------------------------------------------------------------------------------
| opcode |         uid          |      block      | data len |              data                   |
 --------------------------------------------------------------------------------------------------
@endverbatim
*/
struct wtftp_t {
	uint16_t	opcode;
	uint8_t		uid[WTFTP_UID_LEN];
	uint64_t	block;
	uint16_t	data_len;
	union {
		uint8_t file_data[WTFTP_MAX_DATASIZE];
		struct wtftp_file_t file_info;
	};
};

/**
 * Used for parsing 802.11 packets into its respective parts
 */
struct ieee80211_packet {
	struct ieee80211_radiotap_header *radio_header;
	struct ieee80211_frame *ieee80211_header;
	struct llc *llc_header;
	uint8_t *wtftp_pdu;
	uint8_t *ieee80211_framecheck;
};
/** @} structs */

/**
 * Operation codes describe what the wtftp packet contains or the action to perform
 * @defgroup opcodes Opcodes
 * @{
 */

/**
 * Network status
 *
 * @defgroup network Network Status
 * @ingroup opcodes
 * @{
 */
/**
 * No operation
 */
#define WTFTP_OPCODE_NULL 		0x0000

/**
 * A ping is sent when a host wants to know who is out there
 *
@verbatim
 2 bytes
 --------
|  PING  |
 --------
@endverbatim
*/
#define WTFTP_OPCODE_PING 		0x0001

/**
 * A pong is sent to respond to the host who sent a ping
 *
@verbatim
 2 bytes
 --------
|  PONG  |
 --------
@endverbatim
*/
#define WTFTP_OPCODE_PONG 		0x0002
/** @} opcodes/network */

/**
 * File information
 *
 * @defgroup info File Information
 * @ingroup opcodes
 * @{
 */
/**
 * File information is sent out to hosts to describe each file the host is sharing
 *
@verbatim
 2 bytes         20 bytes             8 bytes       2 bytes            256 bytes              8 bytes      2 bytes     2 bytes        8 bytes
 ---------------------------------------------------------------------------------------------------------------------------------------------------
| opcode |         uid          |      block      | data len |          filename         |   filesize    | blocksize |   type   | modification time | reserved...
 ---------------------------------------------------------------------------------------------------------------------------------------------------
@endverbatim
*/
#define WTFTP_OPCODE_FILEINFO 		0x0003
/** @} opcodes/info */

/**
 * File request
 *
 * @defgroup request File Request
 * @ingroup opcodes
 * @{
 */

/**
 * Request from a host the entire file with the given uid and starting block number
 *
@verbatim
@verbatim
 2 bytes         20 bytes             8 bytes
 -------------------------------------------------
|REQFILE |         uid          |      block      |
 -------------------------------------------------
@endverbatim
*/
#define WTFTP_OPCODE_REQFILE 	0x0004

/**
 * Request from a host the block of a file with the given uid and block number
 *
@verbatim
 2 bytes         20 bytes             8 bytes
 -------------------------------------------------
|REQBLK  |         uid          |      block      |
 -------------------------------------------------
@endverbatim
*/
#define WTFTP_OPCODE_REQBLK 	0x0005
/** @} opcodes/request */

/**
 * File data of the type in the opcode
 *
@verbatim
 2 bytes         20 bytes             8 bytes       2 bytes               1 - 2048
 --------------------------------------------------------------------------------------------------
| OPCODE |         uid          |      block      | data len |              data                   |
 --------------------------------------------------------------------------------------------------
@endverbatim
 *
 * @defgroup data File Data
 * @ingroup opcodes
 * @{
 */
/** File data */
#define WTFTP_OPCODE_FILEDATA	0x0006
/** End of file */
#define WTFTP_OPCODE_EOF		0x0007
/** File text */
#define WTFTP_OPCODE_TEXT 		0x0008
/** File stream */
#define WTFTP_OPCODE_STREAM		0x0009
/** @} opcodes/data */

/** @} opcodes */

/**
 * API functions
 * @defgroup functions Functions
 * @{
 */

/**
 * Build a 802.11 packet header (see https://en.wikipedia.org/wiki/IEEE_802.11)
 * @param buf		The buffer to append the header to
 * @param daddr		The 802.11 destination hardware address
 * @param hwaddr	The 802.11 source hardware address
 * @param bssid		The 802.11 bssid address
 * @return 			Returns the length of the appended header
 */
u_int	wtftp_build_80211(uint8_t *buf, uint8_t *daddr, uint8_t *hwaddr, uint8_t *bssid);

 /**
  * Build a Logical Link Control Type 1 broadcast data packet header (see https://en.wikipedia.org/wiki/IEEE_802.2)
  * @param buf		The buffer to append the header to
  * @return 		Returns the length of the appended header
  */
u_int 	wtftp_build_llc(uint8_t * buf);


/**
 * Build a Logical Link Control SNAP data packet header (see https://en.wikipedia.org/wiki/Subnetwork_Access_Protocol)
 * @param buf	The buffer to append the header to
 * @return 		Returns the length of the appended header
 */
u_int 	wtftp_build_llcsnap(uint8_t * buf);

/**
 * Build a Radiotap packet header (see http://www.radiotap.org)
 * @param buf	The buffer to append the header to
 * @return 		Returns the length of the appended header
 */
u_int 	wtftp_build_radiotap(uint8_t * buf);

/**
 * Build the wtftp packet data
 * @param buf	The buffer to append the data to
 * @param wtftp	The @c wtftp_t data
 * @return 		Returns the length of the appended wtftp data
 */
u_int 	wtftp_build_wtftp(uint8_t * buf, struct wtftp_t *wtftp);

/**
 * Capture one packet using the defined callback then return
 * @param callback	The @c pcap_handler callback function
 * @return 			Returns -1 on error
 */
int 			wtftp_capture(pcap_handler callback);

/**
 * Apply the pcap filter to the capture
 * @param handle	The @c pcap_t handle
 * @param filter	The filter (see http://www.tcpdump.org/manpages/pcap-filter.7.html)
 * @return 			Returns -1 on error
 */
int 			wtftp_capture_filter(pcap_t *handle, const char *filter);

/**
 * Dump the packet header and data to the file initialized in @c wtftp_init
 * @param header	The @c pcap_pkthdr header
 * @param packet	The packet data
 */
void			wtftp_dump(const struct pcap_pkthdr *header, const u_char *packet);

/**
 * Get the current capture filter
 * @return 			Returns the capture filter
 */
const char * 	wtftp_get_filter();

/**
 * Get the current hardware address
 * @return 			Returns the hardware address
 */
const uint8_t *	wtftp_get_hwaddr();

/**
 * Initialize the network interface. This must be called first.
 * @param iface		The interface to initialize
 * @return 			Returns -1 on error
 */
int 			wtftp_init(const char *iface);

/**
 * Initialize the network interface with all parameters. This must be called first.
 * @param iface		The interface to initialize
 * @param bssid		The 802.11 bssid address (NULL generates random)
 * @param daddr		The 802.11 destination hardware address (NULL uses broadcast)
 * @param capfile	The path to a capture file (NULL disables capture file)
 * @return 			Returns -1 on error
 */
int 			wtftp_init_all(const char *iface, uint8_t *bssid, uint8_t *daddr, const char *capfile);

/**
 * Continually capture packets using the defined callback
 * @param callback	The @c pcap_handler callback function
 * @return 			Returns -1 on error
 */
int 			wtftp_loop(pcap_handler callback);

/**
 * Returns a string representation of opcode
 * @param opcode	The opcode
 * @return 			Returns the string
 */
const char * 	wtftp_opcode_string(u_short opcode);

/**
 * Parses the packet data into a @c ieee80211_packet
 * @param header	The @c pcap_pkthdr header
 * @param packet	The packet data
 * @param received	The @c ieee80211_packet to parse to
 * @returns 		The packet length
 */
int 			wtftp_parse_ieee80211(const struct pcap_pkthdr *header, const u_char *packet, struct ieee80211_packet *received);

/**
 * Parses the packet data into a @c wtftp_t
 * @param header	The @c pcap_pkthdr header
 * @param packet	The packet data
 * @param wtftp		The @c wtftp_t to parse to
 * @returns 		The packet length
 */
int 			wtftp_parse(const struct pcap_pkthdr *header, const u_char *packet, struct wtftp_t *wtftp);


/**
 * Parses the packet data into a @c ieee80211_packet and @c wtftp_t
 * @param header	The @c pcap_pkthdr header
 * @param packet	The packet data
 * @param ieee80211	The @c ieee80211_packet to parse to
 * @param wtftp		The @c wtftp_t to parse to
 * @returns 		The packet length
 */
int 			wtftp_parse_all(const struct pcap_pkthdr *header, const u_char *packet, struct ieee80211_packet *ieee80211, struct wtftp_t *wtftp);

/**
 * Prints all available devices to stdout
 */
void 			wtftp_print_devices();

/**
 * Prints any existing pcap errors to stdout
 * @param prefix	The prefix to add to the error
 */
void 			wtftp_print_error(const char *prefix);

/**
 * Prints a packet in hex to stdout
 * @param packet	The packet to print
 * @param length	The length of the packet
 */
void 			wtftp_print_packet(const u_char *packet, int length);

/**
 * Prints a wtftp in hex to stdout
 * @param wtftp		The @c wtftp_t to print
 */
void 			wtftp_print(struct wtftp_t *wtftp);

/**
 * Generate a random uid
 * @param uid		The uid to generate to
 */
void 			wtftp_rand_uid(uint8_t *uid);

/**
 * Send a @c wtftp_t to default @c _daddr.
 * @param wtftp		The @c wtftp_t to send
 * @return 			Returns -1 on error
 */
int 			wtftp_send(struct wtftp_t *wtftp);

/**
 * Send a @c wtftp_file_t to default @c _daddr.
 * @param uid			The uid of the file
 * @param block			The block of the file
 * @param wtftp_file	The @c wtftp_file_t to send
 * @return 				Returns -1 on error
 */
int 			wtftp_send_fileinfo(u_char *uid, uint64_t block, struct wtftp_file_t *wtftp_file);

/**
 * Send a ping to default @c _daddr.
 * @return 				Returns -1 on error
 */
int 			wtftp_send_ping();

/**
 * Send a pong to default @c _daddr.
 * @return 			Returns -1 on error
 */
int 			wtftp_send_pong();

/**
 * Send a request for block of a uid file
 * @param uid			The uid of the file
 * @param block			The block of the file
 * @return 				Returns -1 on error
 */
int 			wtftp_send_reqblk(u_char *uid, uint64_t block);

/**
 * Send a request for a file with given uid
 * @param uid			The uid of the file
 * @param block			The starting block of the file
 * @return 				Returns -1 on error
 */
int 			wtftp_send_reqfile(u_char *uid, uint64_t block);

/**
 * Send text
 * @param text			The text to send
 * @return 				Returns -1 on error
 */
int 			wtftp_send_text(const char *text);

/**
 * Convert bytes to readable hex
 * @param bytes		The bytes to convert
 * @param len		The length of the bytes
 * @return 			Returns string of bytes (caller responsible for freeing memory)
 */
char *			wtftp_tohex(const u_char *bytes, u_char len);
/** @} functions */

#endif
