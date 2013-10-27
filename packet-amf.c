/* packet-amf.c
 *
 * Copyright (C) 2012 - 2013, Marc Hoersken, <info@marc-hoersken.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>

#define PROTO_TAG_AMF				"AMF"
#define FRAME_HEADER_LEN			4

/* Wireshark ID of the AMF protocol */
static int proto_amf = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_amf()
*/

/** Defining the protocol */
static gint hf_amf_version = -1;
static gint hf_amf_headers = -1;
static gint hf_amf_messages = -1;

static gint hf_amf_header = -1;
static gint hf_amf_header_length = -1;

static gint hf_amf_message = -1;
static gint hf_amf_message_length = -1;

static gint hf_amf_string = -1;

static gint hf_amf0_u8 = -1;
static gint hf_amf0_u16 = -1;
static gint hf_amf0_s16 = -1;
static gint hf_amf0_u32 = -1;
static gint hf_amf0_double = -1;
static gint hf_amf0_utf8 = -1;
static gint hf_amf0_utf8long = -1;
static gint hf_amf3_u29 = -1;
static gint hf_amf3_integer = -1;
static gint hf_amf3_utf8 = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_amf = -1;
static gint ett_amf_header = -1;
static gint ett_amf_message = -1;
static gint ett_amf_string = -1;


typedef enum {
	AMF0_U8,
	AMF0_U16,
	AMF0_S16,
	AMF0_U32,
	AMF0_DOUBLE,
	AMF0_UTF8,
	AMF0_UTF8LONG,
	
	AMF0_Object,
	AMF0_ECMAArray,
	AMF0_StrictArray,
	AMF0_Date,
	AMF0_TypedObject,
	AMF0_Reference,
	
	AMF3_U29,
	AMF3_INTEGER,
	AMF3_UTF8
} type;

typedef struct amf_type {
	type		type;
	guint		offset;
	guint		length;
	gchar		*className;
	union {
		guint8		u8;
		guint16		u16;
		gint16		s16;
		guint32		u32;

		gboolean	boolean;
		gint		integer;
		gdouble		number;
		gdouble		date;
		gchar		*string;
		gchar		*xml;
		gchar		*utf8;
		GArray		*array;
		GList		*list;
		GHashTable	*map;
	} data;
} amf_type;

typedef struct amf_trait {
	GList		*names;
	gchar		*className;
	gint		count;
	gboolean	dynamic;
	gboolean	externalizable;
} amf_trait;

typedef struct amf_ref {
	GPtrArray	*amf0objects;
	GPtrArray	*amf3objects;
	GPtrArray	*amf3traits;
	GPtrArray	*amf3strings;
} amf_ref;


static amf_ref* amf_ref_new()
{
	amf_ref *ref = (amf_ref*)ep_alloc(sizeof(amf_ref));

	ref->amf0objects = g_ptr_array_new();
	ref->amf3objects = g_ptr_array_new();
	ref->amf3traits = g_ptr_array_new();
	ref->amf3strings = g_ptr_array_new();

	return ref;
}

static void amf_ref_free(amf_ref *ref)
{
	g_ptr_array_free(ref->amf0objects, TRUE);
	g_ptr_array_free(ref->amf3objects, TRUE);
	g_ptr_array_free(ref->amf3traits, TRUE);
	g_ptr_array_free(ref->amf3strings, TRUE);
}

static guint8 decode_amf0_u8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 *offset, amf_ref *ref)
{
	guint8 u8;

	u8 = tvb_get_guint8(tvb, *offset);
	proto_tree_add_item(tree, hf_amf0_u8, tvb, *offset, sizeof(u8), FALSE);
	*offset += sizeof(u8);

	return u8;
}

static guint32 decode_amf0_u32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 *offset, amf_ref *ref)
{
	guint32 u32;

	u32 = tvb_get_guint8(tvb, *offset);
	proto_tree_add_item(tree, hf_amf0_u32, tvb, *offset, sizeof(u32), FALSE);
	*offset += sizeof(u32);

	return u32;
}

static guint8* decode_amf0_utf8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 *offset, amf_ref *ref)
{
	proto_item *string_item = NULL;
	proto_tree *string_tree = NULL;
	guint16 len;
	guint8 *str;

	len = tvb_get_ntohs(tvb, *offset);
	string_item = proto_tree_add_item(tree, hf_amf_string, tvb, *offset+sizeof(len), len, FALSE);
	string_tree = proto_item_add_subtree(string_item, ett_amf_string);
	proto_tree_add_item(string_tree, hf_amf0_u16, tvb, *offset, sizeof(len), FALSE);
	*offset += sizeof(len);

	str = tvb_get_ephemeral_string(tvb, *offset, len);
	proto_tree_add_item(string_tree, hf_amf0_utf8, tvb, *offset, len, FALSE);
	*offset += len;

	return str;
}

static void decode_amf0_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 *offset, amf_ref *ref)
{
	guint32 type;

	type = decode_amf0_u8(tvb, pinfo, tree, offset, ref);
}

static void decode_amf_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 *offset)
{
	guint8 *headerName;
	guint8 mustUnderstand;
	guint32 headerLength;

	amf_ref *ref = amf_ref_new();

	// header-name
	headerName = decode_amf0_utf8(tvb, pinfo, tree, offset, ref);

	// must-understand
	mustUnderstand = decode_amf0_u8(tvb, pinfo, tree, offset, ref);

	// header-length
	headerLength = tvb_get_ntohl(tvb, *offset);
	if (headerLength != 0xFFFFFFFF) {
		proto_tree_add_item(tree, hf_amf_header_length, tvb, *offset, sizeof(headerLength), FALSE);
	} else {
		proto_tree_add_string(tree, hf_amf_string, tvb, *offset, sizeof(headerLength), "Unknown Length");
	}
	*offset += sizeof(headerLength);

	decode_amf0_type(tvb, pinfo, tree, offset, ref);

	amf_ref_free(ref);
}

static void decode_amf_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 *offset)
{
	guint8 *targetURI, *responseURI;
	guint32 messageLength;

	amf_ref *ref = amf_ref_new();

	// target-uri
	targetURI = decode_amf0_utf8(tvb, pinfo, tree, offset, ref);

	// response-uri
	responseURI = decode_amf0_utf8(tvb, pinfo, tree, offset, ref);

	// message-length
	messageLength = tvb_get_ntohl(tvb, *offset);
	if (messageLength != 0xFFFFFFFF) {
		proto_tree_add_item(tree, hf_amf_message_length, tvb, *offset, sizeof(messageLength), FALSE);
	} else {
		proto_tree_add_string(tree, hf_amf_string, tvb, *offset, sizeof(messageLength), "Unknown Length");
	}
	*offset += sizeof(messageLength);

	decode_amf0_type(tvb, pinfo, tree, offset, ref);

	amf_ref_free(ref);
}

static void decode_amf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *header_item = NULL, *message_item = NULL;
	proto_tree *header_tree = NULL, *message_tree = NULL;
	guint16 version, headers, messages;
	guint32 i, offset = 0;

	version = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_amf_version, tvb, offset, sizeof(version), FALSE);
	offset += sizeof(version);

	headers = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_amf_headers, tvb, offset, sizeof(version), FALSE);
	offset += sizeof(headers);

	for (i = 0; i < headers; i++) {
		header_item = proto_tree_add_item(tree, hf_amf_header, tvb, offset, -1, FALSE);
		header_tree = proto_item_add_subtree(header_item, ett_amf_header);

		decode_amf_header(tvb, pinfo, header_tree, &offset);
	}

	messages = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_amf_messages, tvb, offset, sizeof(version), FALSE);
	offset += sizeof(messages);

	for (i = 0; i < messages; i++) {
		message_item = proto_tree_add_item(tree, hf_amf_message, tvb, offset, -1, FALSE);
		message_tree = proto_item_add_subtree(message_item, ett_amf_message);

		decode_amf_message(tvb, pinfo, message_tree, &offset);
	}
}

static void dissect_amf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *amf_item = NULL;
	proto_tree *amf_tree = NULL;
	guint32 length = tvb_length(tvb);
	guint32 offset = 0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_AMF);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d", 
			pinfo->srcport, 
			pinfo->destport
		);
	}

	if (tree) { /* we are being asked for details */
		amf_item = proto_tree_add_item(tree, proto_amf, tvb, 0, -1, FALSE);
		amf_tree = proto_item_add_subtree(amf_item, ett_amf);

		decode_amf(tvb, pinfo, amf_tree);
	}
}

void proto_register_amf(void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	static hf_register_info hf[] = {
		{ &hf_amf_version,
			{ "Version", "amf.version", FT_UINT16, BASE_DEC, NULL, 0x0, "AMF Version", HFILL }
		},
		{ &hf_amf_headers,
			{ "Headers", "amf.headers", FT_UINT16, BASE_DEC, NULL, 0x0, "AMF Headers", HFILL }
		},
		{ &hf_amf_messages,
			{ "Messages", "amf.messages", FT_UINT16, BASE_DEC, NULL, 0x0, "AMF Messages", HFILL }
		},
		{ &hf_amf_header,
			{ "Header", "amf.header", FT_NONE, BASE_NONE, NULL, 0x0, "AMF Header", HFILL }
		},
		{ &hf_amf_header_length,
			{ "Header Length", "amf.header.length", FT_UINT32, BASE_DEC, NULL, 0x0, "AMF Header Length", HFILL }
		},
		{ &hf_amf_message,
			{ "Message", "amf.message", FT_NONE, BASE_NONE, NULL, 0x0, "AMF Message", HFILL }
		},
		{ &hf_amf_message_length,
			{ "Message Length", "amf.message.length", FT_UINT32, BASE_DEC, NULL, 0x0, "AMF Message Length", HFILL }
		},
		{ &hf_amf_string,
			{ "String", "amf.string", FT_STRING, BASE_NONE, NULL, 0x0, "AMF String", HFILL }
		},
		{ &hf_amf0_u8,
			{ "U8", "amf.type.u8", FT_UINT8, BASE_DEC, NULL, 0x0, "AMFv0 U8", HFILL }
		},
		{ &hf_amf0_u16,
			{ "U16", "amf.type.u16", FT_UINT16, BASE_DEC, NULL, 0x0, "AMFv0 U16", HFILL }
		},
		{ &hf_amf0_s16,
			{ "S16", "amf.type.s16", FT_INT16, BASE_DEC, NULL, 0x0, "AMFv0 S16", HFILL }
		},
		{ &hf_amf0_u32,
			{ "U32", "amf.type.u32", FT_UINT32, BASE_DEC, NULL, 0x0, "AMFv0 U32", HFILL }
		},
		{ &hf_amf0_double,
			{ "DOUBLE", "amf.type.double", FT_DOUBLE, BASE_NONE, NULL, 0x0, "AMFv0 DOUBLE", HFILL }
		},
		{ &hf_amf0_utf8,
			{ "UTF8", "amf.type.utf8", FT_STRING, BASE_NONE, NULL, 0x0, "AMFv0 UTF8", HFILL }
		},
		{ &hf_amf0_utf8long,
			{ "UTF8-long", "amf.type.utf8long", FT_STRING, BASE_NONE, NULL, 0x0, "AMFv0 UTF8-long", HFILL }
		},
		{ &hf_amf3_u29,
			{ "U32", "amf.type.u29", FT_UINT32, BASE_DEC, NULL, 0x0, "AMFv0 U32", HFILL }
		},
		{ &hf_amf3_integer,
			{ "INT", "amf.type.int", FT_UINT32, BASE_DEC, NULL, 0x0, "AMFv0 U32", HFILL }
		},
		{ &hf_amf3_utf8,
			{ "UTF8", "amf.type.utf8", FT_STRING, BASE_NONE, NULL, 0x0, "AMFv0 UTF8", HFILL }
		}
	};
	static gint *ett[] = {
		&ett_amf,
		&ett_amf_header,
		&ett_amf_message,
		&ett_amf_string
	};

	proto_amf = proto_register_protocol("Action Message Format", PROTO_TAG_AMF, "amf");
	proto_register_field_array(proto_amf, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length (ett));

	register_dissector("amf", dissect_amf, proto_amf);
}

void proto_reg_handoff_amf(void)
{
	static int amf_initialized = FALSE;
	static dissector_handle_t amf_handle;

	if (!amf_initialized)
	{
		amf_handle = create_dissector_handle(dissect_amf, proto_amf);
		amf_initialized = TRUE;
	}
	else
	{
		dissector_delete_string("media_type", "application/x-amf", amf_handle);
	}

	dissector_add_string("media_type", "application/x-amf", amf_handle);
}