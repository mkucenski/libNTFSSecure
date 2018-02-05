// Copyright 2017 Matthew A. Kucenski
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef _NTFSSECURESDS_H_
#define _NTFSSECURESDS_H_

#include "misc/windowsTypes.h"
#include "misc/coded-message.h"

typedef struct _SECURITY_DESCRIPTOR {
	//Header
	BYTE				vRevision;			// 0:		01
	BYTE				zPadding;			// 1:		00
	WORD				fxControl;			// 2:		04 80
	DWORD				posUserSID;			// 4:		48 00 00 00
	DWORD				posGroupSID;		// 8:		54 00 00 00
	DWORD				posSACL;				// 12: 	00 00 00 00
	DWORD				posDACL;				// 16:	14 00 00 00
} __attribute__((packed)) SECURITY_DESCRIPTOR;
#define USN_RECORD_VER2_BASE_LENGTH 60

typdef struct _SECURITY_DESCRIPTOR_ACE {
	BYTE				vType;
	BYTE				fxFlags;
	WORD				cSize;
	DWORD				fxAccessMask;
	DWORDLONG		idSID;
} __attribute__((packed)) SECURITY_DESCRIPTOR_ACE;

typdef struct _SECURITY_DESCRIPTOR_ACL {
	BYTE				vRevision;
	BYTE				zPadding;
	WORD				cSize;
	WORD				cACECount;
	WORD				zPadding;
} __attribute__((packed)) SECURITY_DESCRIPTOR_ACL;

typedef struct _SECURITY_DESCRIPTOR_STREAM_ITEM {
	DWORD				idHash;					// 0:		cb c6 fe 32
	DWORD				idSecurity;				// 4:		00 01 00 00
	DWORDLONG		posOffset;				// 8:		00 00 00 00 00 00 00 00
	DWORD				cSize;					// 12:	78 00 00 00
						idSelfSecDescr;		// 16:	            01 00 04 80 48 00 00 00 54 00 00 00 
													//	32:	00 00 00 00 14 00 00 00 02 00 34 00 02 00 00 00
													//	48:	00 00 14 00 89 00 12 00 01 01 00 00 00 00 00 05
													//	64:	12 00 00 00 00 00 18 00 89 00 12 00 01 02 00 00
													//	80:	00 00 00 05 20 00 00 00 20 02 00 00 01 01 00 00
													//	96:	00 00 00 05 12 00 00 00 01 02 00 00 00 00 00 05
													//	112:	20 00 00 00 20 02 00 00
	//BYTE			zPadding;				//
} __attribute__((packed)) SECURITY_DESCRIPTOR_STREAM_ITEM;
#define USN_RECORD_VER2_BASE_LENGTH 60

static coded_message_t SECURITY_DESCRIPTOR_CONTROL_FLAGS[] = {
	// Message, 							Code, 	Details,	Short
	{"SE_OWNER_DEFAULTED",				0x0001,	"",		""},
	{"SE_GROUP_DEFAULTED",				0x0002,	"",		""},
	{"SE_DACL_PRESENT",					0x0004,	"",		""},
	{"SE_DACL_DEFAULTED",				0x0008,	"",		""},
	{"SE_SACL_PRESENT",					0x0010,	"",		""},
	{"SE_SACL_DEFAULTED",				0x0020,	"",		""},
	{"SE_UNKNOWN1",						0x0040,	"",		""},
	{"SE_UNKNOWN2",						0x0080,	"",		""},
	{"SE_DACL_AUTO_INHERITED_REQD",	0x0100,	"",		""},
	{"SE_SACL_AUTO_INHERITED_REQD",	0x0200,	"",		""},
	{"SE_DACL_AUTO_INHERITED",			0x0400,	"",		""},
	{"SE_SACL_AUTO_INHERITED",			0x0800,	"",		""},
	{"SE_DACL_PROTECTED",				0x1000,	"",		""},
	{"SE_SACL_PROTECTED",				0x2000,	"",		""},
	{"SE_RM_CONTROL_VALID",				0x4000,	"",		""},
	{"SE_SELF_RELATIVE",					0x8000,	"",		""},
};

#endif //_NTFSSECURESDS_H

