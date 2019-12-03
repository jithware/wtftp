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

#define WTFTP_OPCODE_NULL 		0x0000
#define WTFTP_OPCODE_PING 		0x0001
#define WTFTP_OPCODE_PONG 		0x0002
#define WTFTP_OPCODE_FILEINFO 	0x0003
#define WTFTP_OPCODE_REQFILE 	0x0004
#define WTFTP_OPCODE_REQBLK 	0x0005
#define WTFTP_OPCODE_FILEDATA	0x0006
#define WTFTP_OPCODE_EOF		0x0007
#define WTFTP_OPCODE_TEXT 		0x0008
#define WTFTP_OPCODE_STREAM		0x0009

#define WTFTP_UID_LEN 20
#define WTFTP_MAX_BLOCKSIZE 2048
#define WTFTP_FILENAME_LEN 256
