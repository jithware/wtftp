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

#include "config.h"

#include <epan/etypes.h>
#include <epan/packet.h>

#include "packet-wtftp.h"

static int proto_wtftp = -1;
static gint ett_wtftp = -1;

static int hf_wtftp_opcode = -1;
static int hf_wtftp_uid = -1;
static int hf_wtftp_blocknum = -1;
static int hf_wtftp_datalen = -1;
static int hf_wtftp_filedata = -1;
static int hf_wtftp_filetext = -1;
static int hf_wtftp_fileinfo = -1;
static int hf_wtftp_fileinfo_name = -1;
static int hf_wtftp_fileinfo_size = -1;
static int hf_wtftp_fileinfo_blocksize = -1;
static int hf_wtftp_fileinfo_type = -1;
static int hf_wtftp_fileinfo_mtime = -1;

static const value_string opcodes[] = {
    {WTFTP_OPCODE_PING, "Ping"},
    {WTFTP_OPCODE_PONG, "Pong"},
    {WTFTP_OPCODE_FILEINFO, "File Info"},
	{WTFTP_OPCODE_REQFILE, "Request File"},
	{WTFTP_OPCODE_REQBLK, "Request Block"},
	{WTFTP_OPCODE_FILEDATA, "File Data"},
	{WTFTP_OPCODE_EOF, "EOF"},
	{WTFTP_OPCODE_TEXT, "Text"},
	{WTFTP_OPCODE_STREAM, "Stream"},
	{WTFTP_OPCODE_NULL, NULL}
};

static const value_string filetypes[] = {
	{WTFTP_OPCODE_FILEDATA, "File"},
	{WTFTP_OPCODE_TEXT, "Text"},
	{WTFTP_OPCODE_STREAM, "Stream"},
	{WTFTP_OPCODE_NULL, NULL}
};

void
proto_register_wtftp(void)
{
    static hf_register_info hf[] = {
        { &hf_wtftp_opcode,
            { "Opcode", "wtftp.opcode",
            FT_UINT16, BASE_HEX,
			VALS(opcodes), 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_uid,
            { "UID", "wtftp.uid",
            FT_BYTES, BASE_NONE,
			NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_blocknum,
            { "Block Number", "wtftp.blocknum",
            FT_UINT64, BASE_DEC,
			NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_datalen,
            { "Data Length", "wtftp.datalen",
            FT_UINT16, BASE_DEC,
			NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_filedata,
            { "File Data", "wtftp.filedata",
            FT_BYTES, BASE_NONE,
			NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_filetext,
            { "File Text", "wtftp.filetext",
            FT_STRING, BASE_NONE,
			NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_fileinfo,
            { "File Info", "wtftp.fileinfo",
            FT_NONE, BASE_NONE,
			NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_fileinfo_name,
            { "Name", "wtftp.fileinfo.name",
            FT_STRING, BASE_NONE,
			NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_fileinfo_size,
            { "Size", "wtftp.fileinfo.size",
            FT_UINT64, BASE_DEC,
			NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_fileinfo_blocksize,
            { "Block Size", "wtftp.fileinfo.blocksize",
            FT_UINT16, BASE_DEC,
			NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_fileinfo_type,
            { "Type", "wtftp.fileinfo.type",
            FT_UINT16, BASE_HEX,
			VALS(filetypes), 0x0,
            NULL, HFILL }
        },
        { &hf_wtftp_fileinfo_mtime,
            { "Modification Time", "wtftp.fileinfo.mtime",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0x0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_wtftp
    };

    proto_wtftp = proto_register_protocol (
		"Wireless Trivial File Transfer Protocol",
		"WTFTP",
		"wtftp"
    );

    proto_register_field_array(proto_wtftp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static int
dissect_wtftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

	gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WTFTP");
    col_clear(pinfo->cinfo,COL_INFO);

    guint16 opcode = tvb_get_ntohs(tvb, offset);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(opcode, opcodes, "0x%02x"));

    proto_item *ti = proto_tree_add_item(tree, proto_wtftp, tvb, 0, -1, ENC_NA);
    proto_tree *wtftp_tree = proto_item_add_subtree(ti, ett_wtftp);

    proto_tree_add_item(wtftp_tree, hf_wtftp_opcode, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (opcode == WTFTP_OPCODE_PING || opcode == WTFTP_OPCODE_PONG)
    {
    	return tvb_captured_length(tvb);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": uid=%s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, WTFTP_UID_LEN));
    proto_tree_add_item(wtftp_tree, hf_wtftp_uid, tvb, offset, WTFTP_UID_LEN, ENC_BIG_ENDIAN);
    offset += WTFTP_UID_LEN;

    col_append_fstr(pinfo->cinfo, COL_INFO, "; blocknum=%lu", tvb_get_ntoh64(tvb, offset));
    proto_tree_add_item(wtftp_tree, hf_wtftp_blocknum, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    if (opcode == WTFTP_OPCODE_REQFILE || opcode == WTFTP_OPCODE_REQBLK)
    {
    	return tvb_captured_length(tvb);
    }

    guint16 datalen = tvb_get_ntohs(tvb, offset);
    if (datalen > WTFTP_MAX_BLOCKSIZE)
    {
    	return 0;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "; datalen=%u", tvb_get_ntohs(tvb, offset));
    proto_tree_add_item(wtftp_tree, hf_wtftp_datalen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (opcode == WTFTP_OPCODE_FILEINFO)
    {
    	proto_item *item = proto_tree_add_item(wtftp_tree, hf_wtftp_fileinfo, tvb, 0, -1, ENC_NA);
    	proto_tree *fileinfo_tree = proto_item_add_subtree(item, ett_wtftp);

    	proto_tree_add_item(fileinfo_tree, hf_wtftp_fileinfo_name, tvb, offset, WTFTP_FILENAME_LEN, ENC_BIG_ENDIAN);
    	offset += WTFTP_FILENAME_LEN;

    	col_append_fstr(pinfo->cinfo, COL_INFO, "; size=%lu", tvb_get_ntoh64(tvb, offset));
        proto_tree_add_item(fileinfo_tree, hf_wtftp_fileinfo_size, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        col_append_fstr(pinfo->cinfo, COL_INFO, "; blocksize=%u", tvb_get_ntohs(tvb, offset));
        proto_tree_add_item(fileinfo_tree, hf_wtftp_fileinfo_blocksize, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, "; type=%s", val_to_str(tvb_get_ntohs(tvb, offset), filetypes, "0x%02x"));
        proto_tree_add_item(fileinfo_tree, hf_wtftp_fileinfo_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        //no built in 64-bit time so convert
        guint64 mtime = tvb_get_ntoh64(tvb, offset);
        nstime_t timestamp;
        timestamp.secs = mtime / 1000000;
        timestamp.nsecs = mtime % 1000000;
        proto_tree_add_time(fileinfo_tree, hf_wtftp_fileinfo_mtime, tvb, offset, 8, &timestamp);
        offset += 8;

    	return tvb_captured_length(tvb);
    }

    if (opcode == WTFTP_OPCODE_TEXT)
    {
    	proto_tree_add_item(wtftp_tree, hf_wtftp_filetext, tvb, offset, datalen, ENC_BIG_ENDIAN);
    	offset += datalen;

    	return tvb_captured_length(tvb);
    }

    //default is file data
    proto_tree_add_item(wtftp_tree, hf_wtftp_filedata, tvb, offset, datalen, ENC_BIG_ENDIAN);
    offset += datalen;

    return tvb_captured_length(tvb);
}

void
proto_reg_handoff_wtftp(void)
{
	static dissector_handle_t wtftp_handle;

    wtftp_handle = create_dissector_handle(dissect_wtftp, proto_wtftp);

    dissector_add_uint("ethertype", ETHERTYPE_EXPERIMENTAL_ETH1, wtftp_handle); //TODO: make this 'official'
}
