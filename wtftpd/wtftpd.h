/***************************************************************************
 *   Copyright (C) 2017 by Jithware                                *
 *   jithware@jithware.com                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifndef WTFTPD_H
#define WTFTPD_H

#include <apr.h>
#include <apr_fnmatch.h>
#include <apr_getopt.h>
#include <apr_thread_proc.h>
#include <apr_hash.h>
#include <apr_sha1.h>
#include <apr_strings.h>
#include <apr_queue.h>
#include <apr_lib.h>

#include <pcap.h>
#include <libnet.h>

#include <ieee80211.h>
#include <ieee802_11_radio.h>
#include <if_llc.h>
#include <wtftp.h>

#define WTFTPD_ERRBUF_SIZE 256
#define WTFTPD_DEFAULT_BLOCKSIZE WTFTP_DEFAULT_BLOCKSIZE
#define WTFTPD_IDLE_SLEEP apr_time_from_msec(10)
#define WTFTPD_MAINT_SLEEP apr_time_from_sec(15)
#define WTFTPD_GET_SLEEP apr_time_from_sec(10)
#define WTFTPD_PING_SLEEP apr_time_from_sec(1)
#define WTFTPD_RESP_TIMEOUT apr_time_from_msec(500)
#define WTFTPD_RESP_GIVEUP apr_time_from_sec(60)
#define WTFTPD_FILE_CLOSE apr_time_from_sec(30)
#define WTFTPD_QUEUE_SIZE 102400
#define WTFTPD_MAX_PUT_THREADS 10

//boolean string
#define BOOL(x) ((x) > (0) ? ("true") : ("false"))
#define STRING(x) ((x) ? (x) : ("null"))

//global apr variables
static apr_thread_t *_capture_thread = NULL, *_texting_thread = NULL, *_destination_thread = NULL, *_source_thread = NULL, *_maint_thread = NULL, *_put_thread = NULL, *_get_thread = NULL, *_get_file_thread = NULL, *_put_file_thread = NULL;
static apr_thread_mutex_t *_mutex = NULL, *_mutex_stdout = NULL;
static apr_file_t *_stdout = NULL;
static apr_queue_t *_putq = NULL;
static apr_pool_t *_pool = NULL;

//global command arg variables
static char *_name = NULL, *_pattern = NULL, *_avoid = NULL;
static u_int _usestdin = 0, _echo = 0, _giveup = WTFTPD_RESP_GIVEUP, _blocksize = WTFTPD_DEFAULT_BLOCKSIZE, _silent = 0, _search = 0, _verify = 0, _recursive = 0, _verbose = 0, _debug = 0, _text = 0, _stream = 0;
#ifdef HAVE_WAPI
static u_int _monitor = 0;
static char *_channel = NULL;
#endif

//possible options
enum OPTION_ARGS {
	OPTION_STDIN ='0',
	OPTION_AVOID = 'a',
	OPTION_BLOCKSIZE = 'b',
	#ifdef HAVE_WAPI
	OPTION_CHANNEL = 'c',
	#endif
	OPTION_DESTINATION = 'd',
	OPTION_FILTER = 'f',
	OPTION_GET = 'g',
	OPTION_HELP = 'h',
	OPTION_INTERFACE = 'i',
	OPTION_STREAM = 'm',
	#ifdef HAVE_WAPI
	OPTION_MONITOR = 'n',
	#endif
	OPTION_PREPEND = 'p',
	OPTION_RECURSIVE = 'r',
	OPTION_SOURCE = 's',
	OPTION_TEXT = 't',
	OPTION_UID = 'u',
	OPTION_VERSION = 'v',
	OPTION_CAPFILE = 'w',
	OPTION_SEARCH = 'x',
	OPTION_DEBUG = 'z',
	OPTION_SILENT = 256,
	OPTION_UDP,
	OPTION_BSSID,
	OPTION_DADDR,
	OPTION_GIVEUP,
	OPTION_IGNORE,
	OPTION_PATTERN,
	OPTION_RANDUID,
	OPTION_VERIFY,
	OPTION_VERBOSE,
};

//command line options (order is how they are displayed with --help)
static const apr_getopt_option_t OPTIONS [] = {
	/* long-option, short-option, has-arg flag, description */
	{ "interface", OPTION_INTERFACE, TRUE, "use <interface>" },
	{ "source", OPTION_SOURCE, TRUE, "source <directory>" },
	{ "destination", OPTION_DESTINATION, TRUE, "destination <directory>" },
	{ "uid", OPTION_UID, TRUE, "use <uid> for unique id, otherwise use random (files use sha1)" },
	{ "get", OPTION_GET, TRUE, "get the file with <uid> or all files from <address>" },
	{ "stdin", OPTION_STDIN, FALSE, "read from stdin" },
	{ "prepend", OPTION_PREPEND, TRUE, "prepend <name> on text" },
	{ "text", OPTION_TEXT, TRUE, "text to stdout the file with <uid> or all files from <address> or 'all'" },
	{ "stream", OPTION_STREAM, TRUE, "stream to stdout the file with <uid> or all files from <address> or 'all'" },
	{ "capfile", OPTION_CAPFILE, TRUE, "save capture to <file>" },
	{ "avoid", OPTION_AVOID, TRUE, "avoid the file with <pattern>" },
	{ "pattern", OPTION_PATTERN, TRUE, "get the file with <pattern>" },
	{ "search", OPTION_SEARCH, TRUE, "search for hosts for <seconds> then exit" },
	{ "giveup", OPTION_GIVEUP, TRUE, "giveup on file get after <seconds>" },
	{ "ignore", OPTION_IGNORE, TRUE, "ignore host with <address>" },
	{ "bssid", OPTION_BSSID, TRUE, "use <address> for bssid, otherwise use random" },
	{ "daddr", OPTION_DADDR, TRUE, "use <address> for destination address, otherwise use broadcast" },
	{ "blocksize", OPTION_BLOCKSIZE, TRUE, "<size> of file blocks 512-2048 (must not exceed interface MTU)" },
	{ "silent", OPTION_SILENT, FALSE, "do not send anything, only receive" },
	{ "recursive", OPTION_RECURSIVE, FALSE, "recursively descend into source directory" },
	{ "verify", OPTION_VERIFY, FALSE, "verify downloads when complete" },
	{ "randuid", OPTION_RANDUID, FALSE, "print random uid then exit" },
	{ "filter", OPTION_FILTER, FALSE, "print pcap filter then exit" },
	#ifdef HAVE_WAPI
	{ "monitor", OPTION_MONITOR, FALSE, "set interface into monitor mode" },
	{ "channel", OPTION_CHANNEL, TRUE, "set interface to channel <channel>" },
	#endif
	{ "verbose", OPTION_VERBOSE, FALSE, "be verbose" },
	{ "debug", OPTION_DEBUG, FALSE, "be very verbose" },
	{ "version", OPTION_VERSION, FALSE, "show version then exit" },
	{ "help", OPTION_HELP, FALSE, "show usage then exit" },
	{ NULL, 0, 0, NULL },

	//TODO: add forwarding option
};

struct file_info_t
{
	u_char		uid[WTFTP_UID_LEN]; //uid
	char	 	*path; //full path to local file
	u_char		put; //putting this file?
	u_short		put_threads; //total threads putting this file
	u_char		get; //getting this file?
	u_char		complete; //complete getting this file?
	u_char		text; //text to stdout?
	u_char		stream; //stream to stdout?
	u_long 		total; //total actions on file
	u_long		lost; //lost
	apr_time_t 	start; //start get time on file
	apr_time_t 	last_get;
	apr_time_t 	last_resp;
	apr_time_t 	last_put;
	uint64_t	cur_block; //current block
	apr_file_t	*file_p; //points to local file
	apr_pool_t 	*mp; //memory pool for file
	apr_hash_t  *cache; //wtftp structs to process
	struct wtftp_file_t file_t; //advertised file info
};

struct host_t
{
	u_char 		hwaddr[IEEE80211_ADDR_LEN];
	u_char 		ignore;
	u_long 		total;
	apr_time_t 	last_seen;
	u_char		get; //getting all files from host?
	u_char		text; //text all files from host?
	u_char		stream; //stream all files from host?
	char	 	*source; //files source path
	char	 	*destination; //files destination path
	apr_hash_t 	*files;
	apr_thread_mutex_t *mutex;
	apr_pool_t 	*mp;
};

static struct host_t *_me = NULL; /** pointer to me */
static apr_hash_t *_hosts = NULL; /** pointer to all hosts table */

/**
 * @brief Data structure for wtftpd
 */
struct wtftpd_options_t
{
	char *interface; /** use <interface> */
	char *source; /** source <directory> */
	char *destination; /** destination <directory> */
	char *uid; /** use <uid> for unique id, otherwise use random (files use sha1) */
	char *get; /** get the file with <uid> or all files from <address> */
	u_int stdin; /** read from stdin */
	char *prepend; /** prepend <name> on text */
	char *text; /** text to stdout the file with <uid> or all files from <address> or 'all' */
	char *stream; /** stream to stdout the file with <uid> or all files from <address> or 'all' */
	char *capfile; /** save capture to <file> */
	char *avoid; /** avoid the file with <pattern> */
	char *pattern; /** get the file with <pattern> */
	char *search; /** search for hosts for <seconds> then exit */
	char *giveup; /** giveup on file get after <seconds> */
	char *ignore; /** ignore host with <address> */
	char *bssid; /** use <address> for bssid, otherwise use random */
	char *daddr; /** use <address> for destination address, otherwise use broadcast */
	char *blocksize; /** <size> of file blocks 512-2048 (must not exceed interface MTU) */
	u_int silent; /** do not send anything, only receive */
	u_int recursive; /** recursively descend into source directory */
	u_int verify; /** verify downloads when complete */
	u_int randuid; /** print random uid then exit */
	u_int filter; /** print pcap filter then exit */
	u_int monitor; /** set interface into monitor mode */
	char *channel; /** set interface to channel <channel> */
	u_int verbose; /** be verbose */
	u_int debug; /** be very verbose */
	u_int version; /** show version then exit */
	u_int help; /** show usage then exit */
};

static struct wtftpd_options_t *_options = NULL;

struct 	file_info_t	*add_file			(struct host_t * hinfo, uint8_t *uid);
struct 	file_info_t	*add_file_info 		(struct host_t * hinfo, uint8_t *uid);
struct 	host_t		*add_host			(const uint8_t *addr);
void				callback_capture	(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet);
int					get_destination_dir	(const char *dirname, apr_pool_t *pool);
struct	file_info_t	*get_file_info		(struct host_t * hinfo, const char *path);
void 				get_sha1_uid		(const char *path, uint8_t *uid);
int					get_source_dir 		(const char *dirname, apr_pool_t *pool);
void				ping				(u_int number);
void 				print_file_info		(const struct file_info_t *info);
void				print_host			(struct host_t *hinfo);
void				print_host_text		(void);
void				print_hosts			(const char *title);
void 				print_open_files	(struct host_t *hinfo);
int 				put_file			(struct file_info_t *finfo);
int 				put_file_path		(const char *path);
int 				put_file_info		(struct file_info_t *finfo);
int 				put_file_infos		(struct host_t *hinfo);
int 				put_stream			(struct file_info_t *finfo);
void 				remove_file_info 	(struct host_t * hinfo, uint8_t *uid);
void				status				(apr_status_t rv, u_int quit);
void 				usage				(void);

void	wtftpd_struct	(void);
int		wtftpd_start	(struct wtftpd_options_t *options);

void	* APR_THREAD_FUNC 	start_capture_thread	(apr_thread_t *thread, void *data);
void 	* APR_THREAD_FUNC 	start_destination_thread(apr_thread_t *thread, void *data);
void 	* APR_THREAD_FUNC 	start_get_thread		(apr_thread_t *thread, void *data);
void 	* APR_THREAD_FUNC 	start_get_file_thread	(apr_thread_t *thread, void *data);
void 	* APR_THREAD_FUNC 	start_maint_thread		(apr_thread_t *thread, void *data);
void 	* APR_THREAD_FUNC 	start_put_thread		(apr_thread_t *thread, void *data);
void 	* APR_THREAD_FUNC 	start_put_file_thread	(apr_thread_t *thread, void *data);
void 	* APR_THREAD_FUNC	start_source_thread		(apr_thread_t *thread, void *data);
void 	* APR_THREAD_FUNC	start_texting_thread	(apr_thread_t *thread, void *data);

#endif
