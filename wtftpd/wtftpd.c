/***************************************************************************
 *   Copyright (C) 2017 by Jithware                                *
 *   jithware@jithware.com                                            *
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wtftp.h>
#include <wtftpd.h>

#ifdef HAVE_WAPI
#include <wapi/wapi.h>
#endif

struct file_info_t *add_file(struct host_t *hinfo, uint8_t *uid)
{
	apr_status_t rv;

	struct file_info_t *finfo = add_file_info(hinfo, uid);
	char *u = wtftp_tohex(finfo->uid, WTFTP_UID_LEN);

	rv = apr_filepath_merge(&finfo->path, hinfo->destination, u, APR_FILEPATH_NATIVE, finfo->mp);
	status(rv,TRUE);
	free(u);

	//if file not exist, create it
	rv = apr_file_open(&finfo->file_p, finfo->path, APR_WRITE|APR_CREATE, APR_OS_DEFAULT, finfo->mp);
	status(rv,TRUE);

	//seek to the eof set current block
	apr_off_t offset = 0;
	rv = apr_file_seek(finfo->file_p, APR_END, &offset);
    if (rv == APR_SUCCESS)
    {
    	finfo->cur_block = offset / finfo->file_t.blocksize;
    }

	rv = apr_file_close(finfo->file_p);
	status(rv,TRUE);

	finfo->file_p = NULL;

	return finfo;
}

struct file_info_t * add_file_info(struct host_t *hinfo, uint8_t *uid)
{
	apr_thread_mutex_lock(hinfo->mutex);

	//already available?
	struct file_info_t *finfo = apr_hash_get(hinfo->files, uid, WTFTP_UID_LEN);
	if (finfo != NULL)
	{
		apr_thread_mutex_unlock(hinfo->mutex);
		return finfo;
	}

	apr_status_t rv;
	apr_pool_t *mp;
	rv = apr_pool_create(&mp, NULL);
	status(rv,TRUE);

	finfo = apr_pcalloc(mp, sizeof(struct file_info_t));
	finfo->mp = mp;

	memcpy(finfo->uid, uid, WTFTP_UID_LEN);
	finfo->cache = apr_hash_make(finfo->mp);
	finfo->start = 0;
	finfo->put_threads = 0;
	finfo->last_get = apr_time_now();
	finfo->last_resp = apr_time_now();
	finfo->last_put = apr_time_now();
	finfo->file_t.blocksize = _blocksize;

	apr_hash_set(hinfo->files, &finfo->uid, WTFTP_UID_LEN, finfo);

	if (_debug)
	{
		char *u = wtftp_tohex(uid, WTFTP_UID_LEN);
		char *a = wtftp_tohex(hinfo->hwaddr, IEEE80211_ADDR_LEN);
		printf("Added file %s to host %s\n", u, a);
		free(u);
		free(a);
	}

	apr_thread_mutex_unlock(hinfo->mutex);

	return apr_hash_get(hinfo->files, &finfo->uid, WTFTP_UID_LEN);
}

struct host_t * add_host(const uint8_t *addr)
{
	//already added?
	struct host_t *hinfo = apr_hash_get(_hosts, addr, IEEE80211_ADDR_LEN);
	if (hinfo != NULL)
	{
		return hinfo;
	}

	apr_status_t rv;
	apr_pool_t *mp;
	rv = apr_pool_create(&mp, NULL);
	status(rv,TRUE);

	hinfo = apr_pcalloc(mp, sizeof(struct host_t));
	hinfo->mp = mp;

	rv = apr_thread_mutex_create(&hinfo->mutex, APR_THREAD_MUTEX_DEFAULT, hinfo->mp);
	status(rv,TRUE);

	memcpy(hinfo->hwaddr, addr, IEEE80211_ADDR_LEN);
	hinfo->last_seen = apr_time_now();
	hinfo->files = apr_hash_make(hinfo->mp);

	apr_hash_set(_hosts, &hinfo->hwaddr, IEEE80211_ADDR_LEN, hinfo);

	if (_verbose)
	{
		char *a = wtftp_tohex(hinfo->hwaddr, IEEE80211_ADDR_LEN);
		printf("Added host %s\n", a);
		free(a);
	}

	return apr_hash_get(_hosts, &hinfo->hwaddr, IEEE80211_ADDR_LEN);
}

void callback_capture(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{
	static u_long total;
	apr_status_t rv;
	char cbuf[APR_CTIME_LEN + 1];

	#ifdef WTFTP_DEBUG
	wtftp_dump(header, packet);
	#endif

	//parse the packet
	struct ieee80211_packet ieee80211;
	struct wtftp_t *wtftp = calloc(1, sizeof(struct wtftp_t)); //want zero'd memory and it is used for queue or hash below
	if (wtftp_parse_all(header, packet, &ieee80211, wtftp) <= 0)
	{
		if (_debug)
		{
		    apr_ctime(cbuf, apr_time_now());

			printf("Received unknown packet=%d len=%d on %s:\n", total, header->caplen, cbuf);
			wtftp_print_packet(packet, header->caplen);
		}

		free(wtftp);

		return;
	}

	//capture the host info into the hosts table
	struct host_t *hinfo = NULL;
	hinfo = apr_hash_get(_hosts, &ieee80211.ieee80211_header->i_addr2, IEEE80211_ADDR_LEN);
	if (hinfo == NULL)
	{
		//add to hosts
		hinfo = add_host(ieee80211.ieee80211_header->i_addr2);
		//TODO: add bssid?
	}
	//update host stats
	hinfo->total++;
	//apr_time_ansi_put(&hinfo->last_seen, header->ts.tv_sec);
	hinfo->last_seen = apr_time_now();

	//check if host is ignoreed
	if (hinfo->ignore)
	{
		return;
	}

	total++;

	if (_debug > 2)
	{
	    apr_ctime(cbuf, apr_time_now());

		printf("Received wtftp packet=%d len=%d on %s:\n", total, header->caplen, cbuf);
		wtftp_print(wtftp);
	}

	struct file_info_t *my_finfo = apr_hash_get(_me->files, wtftp->uid, WTFTP_UID_LEN);
	struct file_info_t *their_finfo = NULL;

	switch (wtftp->opcode)
	{
		int i;
		apr_status_t match;

		case WTFTP_OPCODE_PING:

			if (!_silent)
			{
				wtftp_send_pong(); //say hello back
				put_file_infos(_me); //tell them about my files
			}
			free(wtftp);
			break;

		case WTFTP_OPCODE_PONG:

			//host info is already captured above
			free(wtftp);
			break;

		case WTFTP_OPCODE_FILEINFO:

			their_finfo = add_file_info(hinfo, wtftp->uid);
			their_finfo->total++;

			//may have changed so update
			memcpy(&their_finfo->file_t, &wtftp->file_info, sizeof(their_finfo->file_t));

			//check if we are avoiding this file
			if (_avoid != NULL)
			{
				match = apr_fnmatch(_avoid, their_finfo->file_t.name, APR_FNM_CASE_BLIND);
				if (match == APR_SUCCESS)
				{
					if (my_finfo != NULL)
					{
						my_finfo->get = FALSE;
						my_finfo->complete = TRUE;
					}

					free(wtftp);
					break;
				}
			}

			//check if we are looking for file pattern
			if (_pattern != NULL)
			{
				match = apr_fnmatch(_pattern, their_finfo->file_t.name, APR_FNM_CASE_BLIND);
			}

			//if getting all files from host or pattern matches
			if (hinfo->get || match == APR_SUCCESS)
			{
				their_finfo->get = TRUE;

				if (my_finfo == NULL)
				{
					my_finfo = add_file(_me, wtftp->uid);
				}

				if (!my_finfo->complete)
				{
					my_finfo->get = TRUE;
					my_finfo->last_resp = apr_time_now();
				}
			}

			//if getting this file, update my info with their info
			if (my_finfo != NULL && my_finfo->get)
			{
				memcpy(&my_finfo->file_t, &wtftp->file_info, sizeof(my_finfo->file_t));
			}
			free(wtftp);
			break;

		case WTFTP_OPCODE_REQFILE:

			if (my_finfo != NULL && my_finfo->put && my_finfo->put_threads <= WTFTPD_MAX_PUT_THREADS)
			{
				my_finfo->cur_block = wtftp->block;
				rv = apr_thread_create(&_put_file_thread, NULL, start_put_file_thread, my_finfo, my_finfo->mp);
				status(rv,TRUE);
			}
			free(wtftp);
			break;

		case WTFTP_OPCODE_REQBLK:

			if (my_finfo != NULL && my_finfo->put)
			{
				//put this on the queue
				rv = apr_queue_trypush(_putq, wtftp);
				if (rv != APR_SUCCESS)
				{
					free(wtftp);
					break;
				}
				apr_queue_interrupt_all(_putq);
			}
			break;

		case WTFTP_OPCODE_FILEDATA:
		case WTFTP_OPCODE_EOF:

			//if getting this file, and do not have block yet, add it to cache
			if (my_finfo != NULL && my_finfo->get && wtftp->block >= my_finfo->cur_block)
			{
				struct wtftp_t *cache = apr_hash_get(my_finfo->cache, &wtftp->block, sizeof(wtftp->block));
		        if (cache == NULL)
		        {
					apr_hash_set(my_finfo->cache, &wtftp->block, sizeof(wtftp->block), wtftp);
					break;
		        }
			}
			free(wtftp);
			break;

		case WTFTP_OPCODE_TEXT:

			//put the text received to stdout?
			if (_text || hinfo->text || (my_finfo != NULL && my_finfo->text))
			{
				apr_thread_mutex_lock(_mutex_stdout);
				for (i = 0; i < wtftp->data_len; i++)
				{
					apr_file_putc(toascii(wtftp->file_data[i]), _stdout);
				}
				apr_thread_mutex_unlock(_mutex_stdout);
			}
			free(wtftp);
			break;

		case WTFTP_OPCODE_STREAM:

			//put the stream received to stdout?
			if (_stream || hinfo->stream || (my_finfo != NULL && my_finfo->stream))
			{
				apr_thread_mutex_lock(_mutex_stdout);
				for (i = 0; i < wtftp->data_len; i++)
				{
					apr_file_putc(wtftp->file_data[i], _stdout);
				}
				apr_thread_mutex_unlock(_mutex_stdout);
			}
			free(wtftp);
			break;

		default:
			free(wtftp);
			break;
	}
}

int get_destination_dir(const char *dirname, apr_pool_t *pool)
{
    apr_status_t rv;
    apr_finfo_t finfo_t;
    apr_dir_t *dir;

    rv = apr_dir_open(&dir, dirname, pool);
    if (rv != APR_SUCCESS)
    {
    	//ignore if can't open dir
    	return -1;
    }

    while ((apr_dir_read(&finfo_t, APR_FINFO_DIRENT|APR_FINFO_TYPE|APR_FINFO_NAME|APR_FINFO_SIZE|APR_FINFO_MTIME, dir)) == APR_SUCCESS)
    {
    	char *path;
        rv = apr_filepath_merge(&path, dirname, finfo_t.name, 0, pool);
	    if (rv != APR_SUCCESS)
	    {
	    	continue;
	    }

    	if (finfo_t.filetype == APR_REG)
        {
            u_int len;
        	u_char *uid = libnet_hex_aton(finfo_t.name, &len);

			if (len != WTFTP_UID_LEN) //file name is not a uid file
			{
				free(uid);

				//check if already added
				struct file_info_t *finfo = get_file_info(_me, path);
	        	if (finfo == NULL) //create new file info
	        	{
	        		uid = malloc(WTFTP_UID_LEN);
	        		get_sha1_uid(path, uid);
	        		finfo = add_file_info(_me, uid);
	        		finfo->path = (char *)apr_pstrdup(finfo->mp, path);
	        		free(uid);
	        	}
	        	finfo->complete = TRUE;
	        	finfo->get = FALSE;

	        	//if the uid file exists, delete it since already got it
	        	char *remove;
	        	char *u = wtftp_tohex(finfo->uid, WTFTP_UID_LEN);
	            rv = apr_filepath_merge(&remove, dirname, u, 0, pool);
	            apr_finfo_t finfo_t;
	            rv = apr_stat(&finfo_t, remove, APR_FINFO_TYPE, pool);
	            if (rv == APR_SUCCESS)
	            {
	            	rv = apr_file_remove(remove, pool);
	            	status(rv,TRUE);
	            }
	            free(u);

				continue;
			}

			//it's a uid file (incomplete file with uid as name)
			struct file_info_t *finfo = apr_hash_get(_me->files, uid, WTFTP_UID_LEN);
        	if (finfo == NULL) //create new file info
        	{
        		//add it to file infos
        		finfo = add_file_info(_me, uid);

        		//open file
        		rv = apr_file_open(&finfo->file_p, path, APR_READ, APR_OS_DEFAULT, finfo->mp);
        	    if (rv != APR_SUCCESS)
        	    {
        	    	remove_file_info(_me, uid);
        	    	continue;
        	    }

				//seek to the eof set current block
				apr_off_t offset = 0;
				rv = apr_file_seek(finfo->file_p, APR_END, &offset);
        	    if (rv == APR_SUCCESS)
        	    {
        	    	finfo->cur_block = offset / finfo->file_t.blocksize;
        	    }

        	    //close the file
        	    rv = apr_file_close(finfo->file_p);
        	    if (rv == APR_SUCCESS)
        	    {
        	    	finfo->file_p = NULL;
        	    }

        		//update all the values
        		finfo->path = (char *)apr_pstrdup(finfo->mp, path);
        		finfo->get = TRUE;
        	}

			free(uid);
        }
    }

    rv = apr_dir_close(dir);
    status(rv,TRUE);
}

struct file_info_t * get_file_info(struct host_t * hinfo, const char *path)
{
	apr_hash_index_t *i = NULL;
	u_char *key = NULL;
	struct file_info_t *finfo = NULL;

	for (i = apr_hash_first(NULL, hinfo->files); i; i = apr_hash_next(i))
	{
		apr_hash_this(i, (const void**)&key, NULL, (void**)&finfo);

		if (finfo->path != NULL && apr_strnatcmp(finfo->path, path) == 0)
		{
			return finfo;
		}
	}

	return NULL;
}

void get_sha1_uid(const char *path, uint8_t *uid)
{
	apr_status_t rv;
	apr_pool_t *pool;
	apr_file_t *fp;
	apr_sha1_ctx_t context;
	apr_sha1_init(&context);

	if(_verbose)
	{
		printf("Getting uid for %s ...\n", path);
	}

	rv = apr_pool_create(&pool, NULL);
	status(rv,TRUE);

	rv = apr_file_open(&fp, path, APR_READ, APR_OS_DEFAULT, pool);
    status(rv,TRUE);

	uint8_t buf[APR_UINT16_MAX];
	apr_size_t read;
	do
	{
		rv = apr_file_read_full(fp, buf, sizeof(buf), &read);
		apr_sha1_update(&context, buf, read);
	}
	while (rv != APR_EOF);

	apr_sha1_final(uid, &context);

	apr_file_close(fp);
	apr_pool_destroy(pool);

	if(_verbose)
	{
		char *u = wtftp_tohex(uid, WTFTP_UID_LEN);
		printf("%s\n", u);
		free(u);
	}
}

int get_source_dir(const char *dirname, apr_pool_t *pool)
{
    apr_status_t rv;
    apr_finfo_t finfo_t;
    apr_dir_t *dir;

    rv = apr_dir_open(&dir, dirname, pool);
    if (rv != APR_SUCCESS)
    {
    	fprintf(stderr, "Error opening directory %s\n", dirname);
    	return -1;
    }

    while ((apr_dir_read(&finfo_t, APR_FINFO_DIRENT|APR_FINFO_TYPE|APR_FINFO_NAME|APR_FINFO_SIZE|APR_FINFO_MTIME, dir)) == APR_SUCCESS)
    {
    	char *path;
        rv = apr_filepath_merge(&path, dirname, finfo_t.name, 0, pool);
	    if (rv != APR_SUCCESS)
	    {
	    	continue;
	    }

    	if (finfo_t.filetype == APR_DIR)
        {
            if (apr_strnatcmp(finfo_t.name, ".") == 0 || apr_strnatcmp(finfo_t.name, "..") == 0)
            {
                continue;
            }
            if (_recursive)
            {
            	get_source_dir(path, pool);
            }
        }
        else if (finfo_t.filetype == APR_REG)
        {
            //if it is a uid file, do not create file info
        	int len;
        	u_char *u = libnet_hex_aton(finfo_t.name, &len);
			if (len == WTFTP_UID_LEN)
			{
				free(u);
				continue;
			}
			free(u);

        	struct file_info_t *finfo = get_file_info(_me, path);

        	if (finfo == NULL) //create new file info
        	{
        		u_char uid[WTFTP_UID_LEN];
        		get_sha1_uid(path, uid);

        		//add it to file infos
        		finfo = add_file_info(_me, uid);

        		//update all the values
        		finfo->path = (char *)apr_pstrdup(finfo->mp, path);
        		finfo->put = TRUE;
        		finfo->put_threads = 1;
        		finfo->complete = TRUE;
        		snprintf(finfo->file_t.name, sizeof(finfo->file_t.name), "%s", finfo_t.name);
        		finfo->file_t.size = finfo_t.size;
        		finfo->file_t.type = WTFTP_OPCODE_FILEDATA;
        		finfo->file_t.mtime = finfo_t.mtime;

        		//tell everyone about my file
        		if (!_silent)
        		{
        			put_file_info(finfo);
        		}
        	}
        }
    }

    rv = apr_dir_close(dir);
    status(rv,TRUE);
}

void print_file_info(const struct file_info_t *info)
{
	char date_time[APR_CTIME_LEN];

	char *uid = wtftp_tohex(info->uid, WTFTP_UID_LEN);
	printf("UID: %s ", uid); free(uid);
	printf("PATH: %s ", STRING(info->path));
	printf("PUT: %s ", BOOL(info->put));
	printf("PUTTHREADS: %ld ", info->put_threads);
	printf("GET: %s ", BOOL(info->get));
	printf("COMPLETE: %s ", BOOL(info->complete));
	printf("TEXT: %s ", BOOL(info->text));
	printf("STREAM: %s ", BOOL(info->stream));
	printf("TOTAL: %ld ", info->total);
	printf("LOST: %ld ", info->lost);
	apr_ctime(date_time, info->start);
	printf("START: %s ", date_time);
	apr_ctime(date_time, info->last_get);
	printf("LASTGET: %s ", date_time);
	apr_ctime(date_time, info->last_resp);
	printf("LASTRSP: %s ", date_time);
	printf("BLOCK: %li ", info->cur_block);
	printf("CACHE: %u ", apr_hash_count(info->cache));

	//wtftp file
	printf("NAME: %s ", info->file_t.name);
	printf("SIZE: %lld ", info->file_t.size);
	printf("TYPE: %s ", wtftp_opcode_string(info->file_t.type));
	apr_ctime(date_time, info->file_t.mtime);
	printf("MTIME: %s\n\n", date_time);
}

void print_host(struct host_t *hinfo)
{
	char date_time[APR_CTIME_LEN];

	char *addr = wtftp_tohex(hinfo->hwaddr, IEEE80211_ADDR_LEN);
	printf("HWADDR:\t%s\n", addr); free(addr);
	printf("IGNORE:\t%s\n", BOOL(hinfo->ignore));
	printf("TOTAL:\t%li\n", hinfo->total);
	apr_ctime(date_time, hinfo->last_seen);
	printf("LAST:\t%s\n", date_time);
	printf("GET:\t%s\n", BOOL(hinfo->get));
	printf("TEXT:\t%s\n", BOOL(hinfo->text));
	printf("STREAM:\t%s\n", BOOL(hinfo->stream));
	printf("SOURCE:\t%s\n", hinfo->source);
	printf("DEST:\t%s\n", hinfo->destination);

	//iterate thru files
	apr_hash_index_t *fi;
	u_char *fkey;
	struct file_info_t *finfo;
	printf("FILES:\n");
	for (fi = apr_hash_first(NULL, hinfo->files); fi; fi = apr_hash_next(fi))
	{
		apr_hash_this(fi, (const void**)&fkey, NULL, (void**)&finfo);
		printf("\t");
		print_file_info(finfo);
	}

	printf("\n");
}

void print_hosts(const char *title)
{
	apr_hash_index_t *hi;
	char date_time[APR_CTIME_LEN];

	apr_ctime(date_time, apr_time_now());
	printf("\n----- %s at %s -----\n\n", title, date_time);

	apr_thread_mutex_lock(_mutex);
	for (hi = apr_hash_first(NULL, _hosts); hi; hi = apr_hash_next(hi))
	{
		u_char *hkey;
		struct host_t *hinfo;

		apr_hash_this(hi, (const void**)&hkey, NULL, (void**)&hinfo);

		print_host(hinfo);
	}

	apr_thread_mutex_unlock(_mutex);
}

void print_open_files(struct host_t *hinfo)
{
	int count = 0;
	apr_hash_index_t *i;
	u_char *key;
	struct file_info_t *finfo;
	for (i = apr_hash_first(NULL, hinfo->files); i; i = apr_hash_next(i))
	{
		apr_hash_this(i, (const void**)&key, NULL, (void**)&finfo);
		if (finfo->file_p != NULL)
		{
			printf("OPEN PATH: %s\n", finfo->path);
			count++;
		}
	}
	printf("OPEN TOTAL: %d\n", count);
}

void print_host_text()
{
	apr_hash_index_t *hi;
	char date_time[APR_CTIME_LEN];

	apr_ctime(date_time, apr_time_now());
	printf("\nHosts at %s \n\n", date_time);

	for (hi = apr_hash_first(NULL, _hosts); hi; hi = apr_hash_next(hi))
	{
		u_char *hk;
		struct host_t *h;

		apr_hash_this(hi, (const void**)&hk, NULL, (void**)&h);

		char *a = wtftp_tohex(h->hwaddr, IEEE80211_ADDR_LEN);
		printf("%s\n", a);
		free(a);

		apr_hash_index_t *fi;
		u_char *fk;
		struct file_info_t *f;
		for (fi = apr_hash_first(NULL, h->files); fi; fi = apr_hash_next(fi))
		{
			apr_hash_this(fi, (const void**)&fk, NULL, (void**)&f);
			char *u = wtftp_tohex(f->uid, WTFTP_UID_LEN);
			printf("  |-- %s  ", u);
			free(u);
			printf("%s  ", f->file_t.name);
			printf("%lld  ", f->file_t.size);
			printf("%s  ", wtftp_opcode_string(f->file_t.type));
			apr_ctime(date_time,  f->file_t.mtime);
			printf("%s\n", date_time);
		}
		printf("\n");
	}
	printf("\n");
}

int put_file(struct file_info_t *finfo)
{
	struct wtftp_t w;
	w.opcode = WTFTP_OPCODE_FILEDATA;
	memcpy(w.uid, finfo->uid, WTFTP_UID_LEN);

	apr_status_t rv;
	apr_file_t *fp;

	//open the file with a new file pointer
	rv = apr_file_open(&fp, finfo->path, APR_READ, APR_OS_DEFAULT, finfo->mp);
    status(rv,TRUE);

    //seek to the block of the file
	apr_off_t offset = finfo->cur_block * finfo->file_t.blocksize;

	rv = apr_file_seek(fp, APR_SET, &offset);
    if (rv != APR_SUCCESS)
    {
    	w.block = 0;
    }
    else
    {
    	w.block = finfo->cur_block;
    }

	apr_size_t read = finfo->file_t.blocksize;
	do
	{
		rv = apr_file_read_full(fp, w.file_data, finfo->file_t.blocksize, &read);
		if (rv == APR_EOF)
		{
			w.opcode = WTFTP_OPCODE_EOF;
		}

		w.data_len = read;
		if (wtftp_send(&w) == -1)
		{
			apr_file_close(fp);
			return -1;
		}
		w.block++;
	}
	while (rv != APR_EOF);

	apr_file_close(fp);

	return 0;
}

int put_file_path(const char *path)
{
	apr_status_t rv;
	apr_file_t *fp;
	apr_pool_t *pool;

	rv = apr_pool_create(&pool, NULL);
	status(rv,TRUE);

	rv = apr_file_open(&fp, path, APR_READ, APR_OS_DEFAULT, pool);
    status(rv,TRUE);

    struct wtftp_t w;
	w.opcode = WTFTP_OPCODE_FILEDATA;
	get_sha1_uid(path, w.uid);
	w.block = 0;

	apr_size_t read = _blocksize;
	do
	{
		rv = apr_file_read_full(fp, w.file_data, _blocksize, &read);
		if (rv == APR_EOF)
		{
			w.opcode = WTFTP_OPCODE_EOF;
		}

		w.data_len = read;
		if (wtftp_send(&w) == -1)
		{
			return -1;
		}
		w.block++;
	}
	while (rv != APR_EOF);

	apr_file_close(fp);
	apr_pool_destroy(pool);

	return 0;
}

int put_file_info(struct file_info_t *finfo)
{
	if (wtftp_send_fileinfo(finfo->uid, finfo->cur_block, &finfo->file_t) == -1)
	{
		fprintf(stderr, "Error sending file info for %s\n", finfo->file_t.name);
		return -1;
	}

	return 0;
}

int put_file_infos(struct host_t *hinfo)
{
	apr_hash_index_t *i; u_char *key;
	struct file_info_t *finfo;
	for (i = apr_hash_first(NULL, hinfo->files); i; i = apr_hash_next(i))
	{
		apr_hash_this(i, (const void**)&key, NULL, (void**)&finfo);
		if (finfo->put || finfo->file_t.type == WTFTP_OPCODE_TEXT || finfo->file_t.type == WTFTP_OPCODE_STREAM)
		{
			if (put_file_info(finfo) == -1)
			{
				return -1;
			}
		}
	}

	return 0;
}

int put_stream(struct file_info_t *finfo)
{
	struct wtftp_t w;
	apr_status_t rv;

	w.opcode = finfo->file_t.type;
	memcpy(w.uid, finfo->uid, WTFTP_UID_LEN);
	w.block = 0;

	apr_size_t read = finfo->file_t.blocksize;
	do
	{
		rv = apr_file_read_full(finfo->file_p, w.file_data, finfo->file_t.blocksize, &read);
		w.data_len = read;
		if (wtftp_send(&w) == -1)
		{
			return -1;
		}
		w.block++;

		finfo->total++;
		finfo->file_t.size += read;
		finfo->file_t.mtime = apr_time_now();

	}
	while (rv != APR_EOF);

	return 0;
}

void remove_file_info(struct host_t * hinfo, uint8_t *uid)
{
	apr_status_t rv;

	apr_thread_mutex_lock(hinfo->mutex);

	struct file_info_t *finfo = apr_hash_get(hinfo->files, uid, WTFTP_UID_LEN);
	if (finfo != NULL)
	{
		//close file pointer
		if (finfo->file_p != NULL)
		{
			rv = apr_file_close(finfo->file_p);
			status(rv,TRUE);
		}

		//free any memory in cache
		apr_hash_index_t *i; u_char *key;
		struct wtftp_t *w;
		for (i = apr_hash_first(NULL, finfo->cache); i; i = apr_hash_next(i))
		{
			apr_hash_this(i, (const void**)&key, NULL, (void**)&w);
			free(w);
		}
		apr_hash_clear(finfo->cache);

		//remove it from the files table
		apr_hash_set(hinfo->files, &finfo->uid, WTFTP_UID_LEN, NULL);

		if (_verbose)
		{
			char *u = wtftp_tohex(uid, WTFTP_UID_LEN);
			char *h = wtftp_tohex(hinfo->hwaddr, IEEE80211_ADDR_LEN);
			printf("Removed file %s from host %s\n", u, h);
			free(u);
			free(h);
		}

		apr_pool_destroy(finfo->mp);
	}

	apr_thread_mutex_unlock(hinfo->mutex);

}

void ping (u_int number)
{
	int i;

	for(i = 0; i < number; i++)
	{
		wtftp_send_ping();

		apr_sleep(WTFTPD_PING_SLEEP);
	}

}

void * APR_THREAD_FUNC start_capture_thread(apr_thread_t *thread, void *data)
{
	while(thread)
	{
		if (wtftp_capture(callback_capture) == -1)
		{
			wtftp_print_error("Capture error");
		}
	}

	printf("Capturing thread ended.\n");

	apr_thread_exit(thread, APR_SUCCESS);

	return NULL;
}

void * APR_THREAD_FUNC start_destination_thread(apr_thread_t *thread, void *data)
{
	apr_status_t rv;
	apr_finfo_t finfo_t;
	apr_pool_t *pool;
	char *dst = (char *)data;

	rv = apr_pool_create(&pool, NULL);
	status(rv,TRUE);

    rv = apr_stat(&finfo_t, dst, APR_FINFO_TYPE, pool);
    status(rv,TRUE);

    if (finfo_t.filetype != APR_DIR)
    {
    	fprintf(stderr, "%s is not a directory\n", dst);
    	exit(EXIT_FAILURE);
    }

	while(thread)
	{
		//populate all destination files with file infos
		get_destination_dir(dst, pool);

		apr_pool_clear(pool);

		apr_sleep(WTFTPD_MAINT_SLEEP);
	}

	printf("Destination thread ended.\n");

	apr_pool_destroy(pool);

	apr_thread_exit(thread, APR_SUCCESS);

	return NULL;
}

void * APR_THREAD_FUNC start_get_file_thread(apr_thread_t *thread, void *data)
{
	apr_status_t rv;

	struct file_info_t *finfo = (struct file_info_t *)data;

	if (_verbose)
	{
		char *u = wtftp_tohex(finfo->uid, WTFTP_UID_LEN);
		printf("Get file %s thread started.\n", u);
		free(u);
	}

	//if not silent request the whole file
	if (!_silent)
	{
		wtftp_send_reqfile(finfo->uid, finfo->cur_block);
		apr_sleep(WTFTPD_RESP_TIMEOUT);
	}

	//now iterate thru cache, if missed any blocks request them
	finfo->start = apr_time_now();
	while(thread && finfo->get && !finfo->complete)
	{
		struct wtftp_t *w = NULL;

		//check if in cache, otherwise send request for block
		w = apr_hash_get(finfo->cache, &finfo->cur_block, sizeof(finfo->cur_block));
		if (w == NULL)
		{
			//if not silent request block
			if (!_silent)
			{
				finfo->last_get = apr_time_now();
				wtftp_send_reqblk(finfo->uid, finfo->cur_block);
			}
		}

		//wait for it or time out
		apr_time_t start = apr_time_now();
		while (w == NULL && apr_time_now() < start + WTFTPD_RESP_TIMEOUT)
		{
			w = apr_hash_get(finfo->cache, &finfo->cur_block, sizeof(finfo->cur_block));
			apr_sleep(WTFTPD_IDLE_SLEEP);
		}

		//timed out
		if (w == NULL)
		{
			finfo->lost++;

			//should we give up?
			if (_giveup && apr_time_now() >= finfo->last_resp+_giveup)
			{
				if (_verbose)
				{
					char *u = wtftp_tohex(finfo->uid, WTFTP_UID_LEN);
					int seconds = apr_time_sec(_giveup);
					fprintf(stderr, "%d seconds have past since last response, giving up on file %s\n", seconds, u);
					free(u);
				}

				finfo->get = FALSE;
			}

			continue;
		}

		//got successful block to process
		finfo->last_resp = apr_time_now();

		//open file if not already open
		if (finfo->file_p == NULL)
		{
			//open the file
			rv = apr_file_open(&finfo->file_p, finfo->path, APR_WRITE, APR_OS_DEFAULT, finfo->mp);
			if (rv != APR_SUCCESS)
			{
				fprintf(stderr, "Could not open file %s, giving up\n", finfo->path);
				finfo->get = FALSE;
				continue;
			}

			//seek to the current block of the file
			apr_off_t offset = finfo->cur_block * finfo->file_t.blocksize;
			rv = apr_file_seek(finfo->file_p, APR_SET, &offset);
			if (rv != APR_SUCCESS)
			{
				fprintf(stderr, "Could not seek on file %s, giving up\n", finfo->path);
				finfo->get = FALSE;
				continue;
			}
		}

		//write the file data to current block
		apr_size_t write = 0;
		rv = apr_file_write_full(finfo->file_p, w->file_data, w->data_len, &write);
		if (rv != APR_SUCCESS)
		{
			//try to get again on next iteration
			continue;
		}

		//successfully written
		finfo->total++;

		//is this the last block?
		if (w->opcode == WTFTP_OPCODE_EOF)
		{
			//check sha1
			if (_verify)
			{
				u_char uid[WTFTP_UID_LEN];
				get_sha1_uid(finfo->path, uid);
				if (memcmp(uid, finfo->uid, WTFTP_UID_LEN) != 0)
				{
					char *u = wtftp_tohex(uid, WTFTP_UID_LEN);
					fprintf(stderr, "%s does not match the calculated uid %s\n", finfo->path, u);
					free(u);
				}
				else
				{
					printf("%s verified!\n", finfo->path);
				}
			}

			//TODO: handle no name?
			if (strlen(finfo->file_t.name) == 0)
			{

			}

			//rename file
			char *path = (char *)apr_pstrdup(finfo->mp, finfo->path);
			char *filename = (char *)apr_filepath_name_get(path);
			filename[0] = '\0'; //sets filename at end of path to empty string
			char *newname = (char *)apr_pstrcat(finfo->mp, path, finfo->file_t.name, NULL);
			rv = apr_file_rename(finfo->path, newname, finfo->mp);
			status(rv,TRUE);

			if (_verbose)
			{
				printf("%s renamed to %s\n", finfo->path, newname);
				float speed =  (float)finfo->total / (float)apr_time_sec(apr_time_now()-finfo->start);
				float loss = (float)finfo->lost / (float)finfo->total * 100.0;
				printf("avg speed (KB/s): %.1f avg loss: %.1f\% \n", speed, loss);
			}

			finfo->path = newname;

			//set file modification time (ok to be unsuccessful here)
			rv = apr_file_mtime_set(finfo->path, finfo->file_t.mtime, finfo->mp);
			status(rv,0);

			//remove from cache and free memory
			apr_hash_set(finfo->cache, &finfo->cur_block, sizeof(finfo->cur_block), NULL);
			free(w);

			//no longer get file
			finfo->complete = TRUE;
			finfo->get = FALSE;

			//close the local file pointer
			if (finfo->file_p != NULL)
			{
				rv = apr_file_close(finfo->file_p);
				status(rv,TRUE);
				finfo->file_p = NULL;
			}

			continue;
		}

		//remove from cache and free memory
		apr_hash_set(finfo->cache, &finfo->cur_block, sizeof(finfo->cur_block), NULL);
		free(w);

		//get next block
		finfo->cur_block++;

		apr_sleep(WTFTPD_IDLE_SLEEP);
	}

	if (_verbose)
	{
		char *u = wtftp_tohex(finfo->uid, WTFTP_UID_LEN);
		printf("Get file %s thread ended.\n", u);
		free(u);
	}

	apr_thread_exit(thread, APR_SUCCESS);

	return NULL;
}

void * APR_THREAD_FUNC start_get_thread(apr_thread_t *thread, void *data)
{
	apr_status_t rv;

	while(thread)
	{
		//iterate thru all file infos
		apr_hash_index_t *i;
		u_char *key;
		struct file_info_t *finfo;
		for (i = apr_hash_first(NULL, _me->files); i; i = apr_hash_next(i))
		{
			apr_hash_this(i, (const void**)&key, NULL, (void**)&finfo);
			if (finfo->get && !finfo->complete && finfo->start == 0)
			{
				rv = apr_thread_create(&_get_file_thread, NULL, start_get_file_thread, finfo, finfo->mp);
				status(rv,TRUE);
			}
		}

		apr_sleep(WTFTPD_GET_SLEEP);
	}

	printf("Get thread ended.\n");

	apr_thread_exit(thread, APR_SUCCESS);

	return NULL;
}

void * APR_THREAD_FUNC start_maint_thread(apr_thread_t *thread, void *data)
{
	apr_status_t rv;
	apr_pool_t *pool;
	apr_finfo_t finfo_t;
	char errbuf[WTFTPD_ERRBUF_SIZE];
	apr_hash_index_t *i;
	u_char *key;
	struct file_info_t *finfo;

	rv = apr_pool_create(&pool, NULL);
	status(rv,TRUE);

	while(thread)
	{
		u_char ping = FALSE;

		//perform maintenance on all the file infos
		for (i = apr_hash_first(NULL, _me->files); i; i = apr_hash_next(i))
		{
			apr_hash_this(i, (const void**)&key, NULL, (void**)&finfo);

			if (finfo->put)
			{
				//does the put file still exists?
				rv = apr_stat(&finfo_t, finfo->path, APR_FINFO_TYPE|APR_FINFO_MTIME, pool);
				if (rv != APR_SUCCESS)
				{
					if (_verbose)
					{
						fprintf(stderr, "%s: %s\n", apr_strerror(rv, errbuf, WTFTPD_ERRBUF_SIZE), finfo->path);
					}

					//must not exist anymore so remove the file info
					remove_file_info(_me, finfo->uid);

					continue;
				}

				//has the put file been modified?
				if (finfo->file_t.mtime != finfo_t.mtime)
				{
					//remove it from list and pick it up again on next source thread iteration
					remove_file_info(_me, finfo->uid);

					continue;
				}
			}

			//if havent accessed the file in a while, close file pointer
			if (finfo->file_p != NULL && finfo->path != NULL)
			{
				u_char close = FALSE;

				if (finfo->put && apr_time_now() >= finfo->last_put+WTFTPD_FILE_CLOSE)
				{
					close = TRUE;
				}
				else if (!finfo->complete && apr_time_now() >= finfo->last_get+WTFTPD_FILE_CLOSE)
				{
					close = TRUE;
				}
				else if (!finfo->put && finfo->complete)
				{
					close = TRUE;
				}

				if (close)
				{
					if (_verbose)
					{
						int seconds = apr_time_sec(WTFTPD_FILE_CLOSE);
		    			fprintf(stderr, "%d seconds have past since last access, closing file %s\n", seconds, finfo->path);
					}

					apr_thread_mutex_lock(_me->mutex);

					rv = apr_file_close(finfo->file_p);
					status(rv,TRUE);

					finfo->file_p = NULL;

					apr_thread_mutex_unlock(_me->mutex);
				}
			}

			//continue to ping for files?
			if (!finfo->complete)
			{
				ping = TRUE;
			}


			//TODO: other maintenance on file infos?


		}

		//if searching for pattern, have to continually ping
		if (_pattern != NULL)
		{
			ping = TRUE;
		}

		if (!_silent && ping)
		{
			wtftp_send_ping();
		}

		#ifdef WTFTP_DEBUG
		//print_host(_me);
		//printf("\nqueue size: %d\n", apr_queue_size(_putq));
		//print_open_files(_me);
		#endif

		if (_debug > 1)
		{
			print_hosts("Hosts");
		}

		apr_pool_clear(pool);

		apr_sleep(WTFTPD_MAINT_SLEEP);

		//printf("Maintenance thread returned\n");
	}

	printf("Maintenance thread ended.\n");

	apr_pool_destroy(pool);

	apr_thread_exit(thread, APR_SUCCESS);

	return NULL;
}

void * APR_THREAD_FUNC start_put_file_thread(apr_thread_t *thread, void *data)
{
	struct file_info_t *finfo = (struct file_info_t *)data;

	if (_verbose)
	{
		char *u = wtftp_tohex(finfo->uid, WTFTP_UID_LEN);
		printf("Put file %s thread started.\n", u);
		free(u);
	}

	finfo->put_threads++;

	put_file(finfo);

	finfo->put_threads--;

	if (_verbose)
	{
		char *u = wtftp_tohex(finfo->uid, WTFTP_UID_LEN);
		printf("Put file %s thread ended.\n", u);
		free(u);
	}

	apr_thread_exit(thread, APR_SUCCESS);

	return NULL;
}

void * APR_THREAD_FUNC start_put_thread(apr_thread_t *thread, void *data)
{
	apr_status_t rv;
	struct wtftp_t *w = NULL;

	while(thread)
	{
		rv = apr_queue_pop(_putq, (void*)&w);
		if (rv == APR_SUCCESS)
		{
			apr_thread_mutex_lock(_me->mutex);

			struct file_info_t *finfo = apr_hash_get(_me->files, w->uid, WTFTP_UID_LEN);
			if (finfo != NULL && finfo->put)
			{
				//open file if not already open
				if (finfo->file_p == NULL)
				{
	        		rv = apr_file_open(&finfo->file_p, finfo->path, APR_READ, APR_OS_DEFAULT, finfo->mp);
	        	    if (rv != APR_SUCCESS)
	        	    {
	        	    	goto next;
	        	    }
				}

				//seek to the block of the file
				apr_off_t offset = w->block * finfo->file_t.blocksize;
				rv = apr_file_seek(finfo->file_p, APR_SET, &offset);
        	    if (rv != APR_SUCCESS)
        	    {
        	    	goto next;
        	    }

        	    //read the file data block (reusing the wtftp to send)
        		apr_size_t read = 0;
				rv = apr_file_read_full(finfo->file_p, w->file_data, finfo->file_t.blocksize, &read);
        	    if (rv == APR_SUCCESS)
        	    {
        	    	w->opcode = WTFTP_OPCODE_FILEDATA;
        	    }
        	    else if (rv == APR_EOF)
        	    {
        	    	w->opcode = WTFTP_OPCODE_EOF;
        	    }
        	    else
        	    {
        	    	goto next;
        	    }

        	    w->data_len = read;

				if (wtftp_send(w) == -1)
				{
					goto next;
				}

				finfo->total++;
				finfo->last_put = apr_time_now();
			}

			next:
			free(w); //free memory from queue
			apr_thread_mutex_unlock(_me->mutex);
		}

		//printf("Put thread returned\n");
	}

	printf("Put thread ended.\n");

	apr_thread_exit(thread, APR_SUCCESS);

	return NULL;
}

void * APR_THREAD_FUNC start_source_thread(apr_thread_t *thread, void *data)
{
	apr_status_t rv;
	apr_finfo_t finfo_t;
	apr_pool_t *pool;
	char *src = (char *)data;

	rv = apr_pool_create(&pool, NULL);
	status(rv,TRUE);

    rv = apr_stat(&finfo_t, src, APR_FINFO_TYPE, pool);
    status(rv,TRUE);

    if (finfo_t.filetype != APR_DIR)
    {
    	fprintf(stderr, "%s is not a directory\n", src);
    	exit(EXIT_FAILURE);
    }

	while(thread)
	{
		//populate all source files with file infos
		get_source_dir(src, pool);

		apr_pool_clear(pool);

		apr_sleep(WTFTPD_MAINT_SLEEP);

		//printf("Source thread returned\n");
	}

	printf("Source thread ended.\n");

	apr_pool_destroy(pool);

	apr_thread_exit(thread, APR_SUCCESS);

	return NULL;
}

void * APR_THREAD_FUNC start_texting_thread(apr_thread_t *thread, void *data)
{
	//file info
	struct file_info_t *finfo = (struct file_info_t *)data;

	//wtftp data
	struct wtftp_t wtftp_data;
	wtftp_data.opcode = finfo->file_t.type;
	wtftp_data.block = 0;
	memcpy(wtftp_data.uid, finfo->uid, WTFTP_UID_LEN);

	//prepend name
	char textname[sizeof(finfo->file_t.name) + 3];
	textname[0] = '\0';
	if (_name)
	{
		snprintf(textname, sizeof(textname), "%s: ", finfo->file_t.name);
	}

	while(thread)
	{
		apr_status_t rv;
		char buf[finfo->file_t.blocksize];

		if (finfo->file_p == NULL)
		{
			rv = apr_file_open_stdin(&finfo->file_p, finfo->mp);
			status(rv,TRUE);
			apr_sleep(apr_time_from_sec(1));
		}

		//read from stdin until user enters return or buffer size exceeded
		rv = apr_file_gets(buf, finfo->file_t.blocksize-strlen(textname), finfo->file_p);
		if (rv == APR_SUCCESS)
		{
			snprintf(wtftp_data.file_data, sizeof(wtftp_data.file_data), "%s%s", textname, buf);
			wtftp_data.data_len = strlen(wtftp_data.file_data);
			if (wtftp_send(&wtftp_data) != -1)
			{
				//echo back to stdout if name is prepended
				if (_name)
				{
					apr_file_puts(wtftp_data.file_data, _stdout);
				}

				wtftp_data.block++;
				finfo->total++;
				finfo->file_t.size += wtftp_data.data_len;
				finfo->file_t.mtime = apr_time_now();
			}
			else
			{
				fprintf(stderr, "Error sending text: %s\n", wtftp_data.file_data);
			}
		}

		//printf("Texting thread returned\n");
	}

	printf("Texting thread ended.\n");

	apr_thread_exit(thread, APR_SUCCESS);

	return NULL;
}

void status(apr_status_t rv, u_int quit)
{
	char errbuf[WTFTPD_ERRBUF_SIZE];
	if (rv != APR_SUCCESS)
	{
		fprintf(stderr, "%s\n", apr_strerror(rv, errbuf, WTFTPD_ERRBUF_SIZE));
		if (quit)
		{
			exit(EXIT_FAILURE);
		}
	}
}

void usage()
{
	apr_getopt_option_t *option = (apr_getopt_option_t *)OPTIONS;

	printf("Usage: %s [OPTION...]\n\n", "wtftpd");

	while (option != NULL && option->optch != 0)
	{
		if (isascii(option->optch))
		{
			printf("  -%c --%s [%s]\n", option->optch, option->name, option->description);
		}
		else
		{
			printf("  --%s [%s]\n", option->name, option->description);
		}

		option++;
	}

	printf("\n");
}

void wtftpd_struct()
{
	apr_getopt_option_t *option = (apr_getopt_option_t *)OPTIONS;

	printf("\n/**\n");
	printf(" * @brief Options for wtftpd\n");
	printf(" */\n");
	printf("struct wtftpd_options_t\n");
	printf("{\n");

	while (option != NULL && option->optch != 0)
	{
		if (option->has_arg)
		{
			printf("\tchar *%s; /** %s */ \n", option->name, option->description);
		}
		else
		{
			printf("\tu_int %s; /** %s */ \n", option->name, option->description);
		}

		option++;
	}
	printf("};\n");
	printf("\n");
}

int callback_signal(int signum)
{
	printf("Received signal: %i\n", signum);

	switch (signum)
	{
		case SIGTERM:

			return 1;

		case SIGINT:

			return 1;

		#ifndef WIN32
		case SIGTSTP:

			return 0;

		case SIGHUP:

			return 0;

		#endif
	}

	return 0;
}

int main(int argc, const char * const argv[])
{
	apr_status_t rv;
	apr_getopt_t *opt;
	apr_pool_t *mp;
	int optch, len;
	const char *optarg;
	uint8_t *addr =	NULL, *bssid =	NULL, *daddr =	NULL;
	const uint8_t *hwaddr =	NULL;
	char *iface = NULL, *source = NULL, *destination = NULL, *capfile = NULL;
	u_char *uid = NULL;

	//apr init
	rv = apr_app_initialize(&argc, &argv, NULL);
	status(rv,TRUE);
	//main memory pool
	rv = apr_pool_create(&mp, NULL);
	status(rv,TRUE);
	//mutex for threads
	rv = apr_thread_mutex_create(&_mutex, APR_THREAD_MUTEX_DEFAULT, mp);
	status(rv,TRUE);
	rv = apr_thread_mutex_create(&_mutex_stdout, APR_THREAD_MUTEX_DEFAULT, mp);
	status(rv,TRUE);
	//hosts table
	_hosts = apr_hash_make(mp);
	//queues
	rv = apr_queue_create(&_putq, WTFTPD_QUEUE_SIZE, mp);
	status(rv,TRUE);

	//get options
	apr_getopt_init(&opt, mp, argc, argv);
	while ((rv = apr_getopt_long(opt, OPTIONS, &optch, &optarg)) == APR_SUCCESS) {
		switch (optch) {

			case OPTION_INTERFACE:
				iface = (char*)optarg;
				break;

			case OPTION_UID:
				uid = libnet_hex_aton((char*)optarg, &len);
				if (len == WTFTP_UID_LEN)
				{
					break;
				}
				fprintf(stderr, "Invalid uid: %s\n\n", (char*)optarg);
				usage();
				exit(EXIT_FAILURE);

			case OPTION_BSSID:
				bssid = libnet_hex_aton((char*)optarg, &len);
				if (len == IEEE80211_ADDR_LEN)
				{
					break;
				}
				fprintf(stderr, "Invalid bssid: %s\n\n", (char*)optarg);
				usage();
				exit(EXIT_FAILURE);

			case OPTION_DADDR:
				daddr = libnet_hex_aton((char*)optarg, &len);
				if (len == IEEE80211_ADDR_LEN)
				{
					break;
				}
				fprintf(stderr, "Invalid daddr: %s\n\n", (char*)optarg);
				usage();
				exit(EXIT_FAILURE);

			case OPTION_SEARCH:
				_search = atoi((char*)optarg);
				break;

			case OPTION_PATTERN:
				_pattern = (char*)optarg;
				break;

			case OPTION_AVOID:
				_avoid = (char*)optarg;
				break;

			case OPTION_GIVEUP:
				_giveup = apr_time_from_sec(atoi((char*)optarg));
				if (_giveup <= 0)
				{
					fprintf(stderr, "Invalid giveup: %s\n\n", (char*)optarg);
					usage();
					exit(EXIT_FAILURE);
				}
				break;

			case OPTION_BLOCKSIZE:
				_blocksize = atoi((char*)optarg);
				if (_blocksize < WTFTP_MIN_BLOCKSIZE || _blocksize > WTFTP_MAX_BLOCKSIZE)
				{
					fprintf(stderr, "Invalid block size: %s\n\n", (char*)optarg);
					usage();
					exit(EXIT_FAILURE);
				}
				break;

			case OPTION_STDIN:
				_usestdin = TRUE;
				break;

			case OPTION_PREPEND:
				_name = (char*)optarg;
				break;

			case OPTION_CAPFILE:
				capfile = (char*)optarg;
				break;

			case OPTION_SILENT:
				_silent = TRUE;
				break;

			case OPTION_SOURCE:
				source = (char*)optarg;
				break;

			case OPTION_DESTINATION:
				destination = (char*)optarg;
				break;

			case OPTION_RECURSIVE:
				_recursive = TRUE;
				break;

			case OPTION_VERIFY:
				_verify = TRUE;
				break;

			case OPTION_VERBOSE:
				_verbose = TRUE;
				break;

			case OPTION_DEBUG:
				_debug++;
				break;

			#ifdef HAVE_WAPI
			case OPTION_MONITOR:
				_monitor = TRUE;
				break;

			case OPTION_CHANNEL:
				_channel = (char*)optarg;
				break;
			#endif

			case OPTION_VERSION:
				printf("%s %s\n\n", "wtftpd", WTFTP_VERSION);
				exit(EXIT_SUCCESS);

			case OPTION_HELP:
				usage();
				exit(EXIT_SUCCESS);
		}
	}

	if (rv != APR_EOF)
	{
		fprintf(stderr, "use -h or --help for more help\n");
		exit(EXIT_FAILURE);
	}

	if (iface == NULL)
	{
		printf("No interface selected. Choose one of the following interfaces:\n\n");
		wtftp_print_devices();
		exit(EXIT_FAILURE);
	}

	#ifdef HAVE_WAPI
	if (_monitor || _channel)
	{
		int ret, sock = wapi_make_socket();
		wapi_set_ifdown(sock, iface);
		if (_monitor)
		{
			ret = wapi_set_mode(sock, iface, WAPI_MODE_MONITOR);
			if (ret < 0)
			{
				fprintf(stderr, "Could not set interface %s into monitor mode.\n", iface);
			}
		}
		if (_channel)
		{
			double freq = 0.0;
			int chan = atoi(_channel);
			wapi_set_ifup(sock, iface);
			wapi_chan2freq(sock, iface, chan, &freq);
			ret = wapi_set_freq(sock, iface, freq, WAPI_FREQ_FIXED);
			if (ret < 0)
			{
				fprintf(stderr, "Could not put interface %s to channel %i.\n", iface, chan);
			}
		}
		wapi_set_ifup(sock, iface);
	}
	#endif

	//initialize the network interface
	if (wtftp_init_all(iface, bssid, daddr, capfile) == -1)
	{
		exit(EXIT_FAILURE);
	}

	//add me to host list
	hwaddr = wtftp_get_hwaddr();
	_me = add_host(hwaddr);

	if (source != NULL)
	{
		_me->source = (char *)apr_pstrdup(_me->mp, source);
	}

	if (destination != NULL)
	{
		_me->destination = (char *)apr_pstrdup(_me->mp, destination);
	}

	//get options that required the initialization above
	struct host_t *hinfo = NULL;
	const char *filter = NULL;
	apr_getopt_init(&opt, mp, argc, argv);
	while ((rv = apr_getopt_long(opt, OPTIONS, &optch, &optarg)) == APR_SUCCESS) {
		switch (optch) {

			case OPTION_GET:
				if (destination == NULL)
				{
					fprintf(stderr, "Can not get without a destination\n\n");
					usage();
					exit(EXIT_FAILURE);
				}
				addr = libnet_hex_aton((char*)optarg, &len);
				if (len == IEEE80211_ADDR_LEN)
				{
					hinfo = add_host(addr);
					hinfo->get = TRUE;
					free(addr);
					break;
				}
				if (len == WTFTP_UID_LEN)
				{
					struct file_info_t *finfo = add_file(_me, addr);
					finfo->get = TRUE;
					free(addr);
					break;
				}
				fprintf(stderr, "Invalid get address or uid: %s\n\n", (char*)optarg);
				usage();
				exit(EXIT_FAILURE);

			case OPTION_IGNORE:
				addr = libnet_hex_aton((char*)optarg, &len);
				if (len == IEEE80211_ADDR_LEN)
				{
					hinfo = add_host(addr);
					hinfo->ignore = 1;
					hinfo->last_seen = 0;
					free(addr);
					break;
				}
				fprintf(stderr, "Invalid ignore address: %s\n\n", (char*)optarg);
				usage();
				exit(EXIT_FAILURE);

			case OPTION_TEXT:
				addr = libnet_hex_aton((char*)optarg, &len);
				if (len == IEEE80211_ADDR_LEN)
				{
					hinfo = add_host(addr);
					hinfo->text = TRUE;
					hinfo->last_seen = 0;
					free(addr);
					break;
				}
				else if (len == WTFTP_UID_LEN)
				{
					struct file_info_t *finfo = add_file_info(_me, addr);
					finfo->text = TRUE;
					free(addr);
					break;
				}
				else if (apr_strnatcmp((char*)optarg, "all") == 0)
				{
					_text = TRUE;
					break;
				}
				fprintf(stderr, "Invalid text address or uid: %s\n\n", (char*)optarg);
				usage();
				exit(EXIT_FAILURE);

			case OPTION_STREAM:
				addr = libnet_hex_aton((char*)optarg, &len);
				if (len == IEEE80211_ADDR_LEN)
				{
					hinfo = add_host(addr);
					hinfo->stream = TRUE;
					hinfo->last_seen = 0;
					free(addr);
					break;
				}
				else if (len == WTFTP_UID_LEN)
				{
					struct file_info_t *finfo = add_file_info(_me, addr);
					finfo->stream = TRUE;
					free(addr);
					break;
				}
				else if (apr_strnatcmp((char*)optarg, "all") == 0)
				{
					_stream = TRUE;
					break;
				}
				fprintf(stderr, "Invalid stream address or uid: %s\n\n", (char*)optarg);
				usage();
				exit(EXIT_FAILURE);

			case OPTION_RANDUID:
				uid = malloc(WTFTP_UID_LEN);
				wtftp_rand_uid(uid);
				printf("%s\n", wtftp_tohex(uid, WTFTP_UID_LEN));
				exit(EXIT_SUCCESS);

			case OPTION_FILTER:
				filter = wtftp_get_filter();
				printf("%s\n", filter);
				exit(EXIT_SUCCESS);
		}
	}

	if (rv != APR_EOF)
	{
		usage();
		exit(EXIT_FAILURE);
	}

	//open stdout
	rv = apr_file_open_stdout(&_stdout, mp);
	status(rv,TRUE);

	//search for hosts, display, then exit
	if (_search > 0)
	{
		rv = apr_thread_create(&_capture_thread, NULL, start_capture_thread, NULL, mp);
		status(rv,TRUE);

		if (source != NULL)
		{
			printf("Searching for files in %s...\n", source);
			get_source_dir(source, mp);
		}

		printf("Searching for files in hosts...\n");

		ping(_search);

		printf("\n");

		print_host_text();

		exit(EXIT_SUCCESS);
	}

	//use stdin?
	if (_usestdin)
	{
		if (uid == NULL)
		{
			uid = malloc(WTFTP_UID_LEN);
			wtftp_rand_uid(uid); //can not determine sha1 on stdin so generate random one
		}

		//file info to announce
		struct file_info_t *finfo = add_file_info(_me, uid);

		rv = apr_file_open_stdin(&finfo->file_p, mp);
		status(rv,TRUE);

		//file name
		if (_name != NULL)
		{
			snprintf(finfo->file_t.name, sizeof(finfo->file_t.name), _name);
		}

		//file modification time
		finfo->file_t.mtime = apr_time_now();

		//get apr file info type
		apr_finfo_t finfo_t;
		rv = apr_file_info_get(&finfo_t, APR_FINFO_TYPE, finfo->file_p);
		status(rv,TRUE);
		switch (finfo_t.filetype)
		{
			//read from keyboard
			case APR_CHR:
				finfo->file_t.type = WTFTP_OPCODE_TEXT;

				//create texting thread
				rv = apr_thread_create(&_texting_thread, NULL, start_texting_thread, finfo, mp);
				status(rv,TRUE);

				//continue as normal
				break;

			//piped file to stdin
			case APR_PIPE:
				finfo->file_t.type = WTFTP_OPCODE_STREAM;

				//create capture thread (responds to pings/requests while streaming)
				rv = apr_thread_create(&_capture_thread, NULL, start_capture_thread, NULL, mp);
				status(rv,TRUE);

				//put file pipe, then exit when eof is reached
				if (put_stream(finfo) == -1)
				{
					exit(EXIT_FAILURE);
				}

				exit(EXIT_SUCCESS);

			default:
				fprintf(stderr, "Unknown stdin file type.\n");
				exit(EXIT_FAILURE);

		}
	}

	//create capture thread
	rv = apr_thread_create(&_capture_thread, NULL, start_capture_thread, NULL, mp);
	status(rv,TRUE);

	//create maintenance thread
	rv = apr_thread_create(&_maint_thread, NULL, start_maint_thread, NULL, mp);
	status(rv,TRUE);

	//create destination thread
	if (destination != NULL)
	{
		rv = apr_thread_create(&_destination_thread, NULL, start_destination_thread, destination, mp);
		status(rv,TRUE);

		rv = apr_thread_create(&_get_thread, NULL, start_get_thread, NULL, mp);
		status(rv,TRUE);
	}

	//create source thread
	if (source != NULL)
	{
		rv = apr_thread_create(&_source_thread, NULL, start_source_thread, source, mp);
		status(rv,TRUE);

		rv = apr_thread_create(&_put_thread, NULL, start_put_thread, NULL, mp);
		status(rv,TRUE);
	}

	//say hello to everyone!
	if (!_silent)
	{
		ping(3);
	}

	//create thread for listening to signals (exits when callback returns 1)
	#ifndef WIN32
	apr_setup_signal_thread();
	apr_signal_thread(callback_signal);
	#else
	//signal thread not supported so just yield to other threads
	apr_thread_yield();
	#endif

	apr_pool_destroy(mp);

	apr_terminate();

	return EXIT_SUCCESS;
}
