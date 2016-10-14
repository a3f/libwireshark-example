/* packet-mpls.h
 * Declarations of exported routines from MPLS dissector
 * Author: Carlos Pignataro <cpignata@cisco.com>
 * Copyright 2005, cisco Systems, Inc.
 *
 * (c) Copyright 2006, _FF_ Francesco Fondelli <francesco.fondelli@gmail.com>
 *                     added MPLS OAM support, ITU-T Y.1711
 * (c) Copyright 2011, Shobhank Sharma <ssharma5@ncsu.edu>
 *                     added MPLS Generic Associated Channel as per RFC 5586
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_MPLS_H
#define PACKET_MPLS_H

/* Special labels in MPLS */
enum {
    MPLS_LABEL_IP4_EXPLICIT_NULL = 0,
    MPLS_LABEL_ROUTER_ALERT,
    MPLS_LABEL_IP6_EXPLICIT_NULL,
    MPLS_LABEL_IMPLICIT_NULL,
    MPLS_LABEL_GACH              = 13, /* aka GAL */
    MPLS_LABEL_OAM_ALERT         = 14,
    MPLS_LABEL_MAX_RESERVED      = 15,
    MPLS_LABEL_INVALID           = -1
};

/*
 * FF: private data passed from the MPLS dissector to subdissectors
 * (data parameter).
 */
struct mplsinfo {
    guint32 label; /* last mpls label in label stack */
    guint8  exp;   /* former EXP bits of last mpls shim in stack */
    guint8  bos;   /* BOS bit of last mpls shim in stack */
    guint8  ttl;   /* TTL bits of last mpls shim in stack */
};

extern const value_string special_labels[];
extern void decode_mpls_label(tvbuff_t *tvb, int offset,
                              guint32 *label, guint8 *exp,
                              guint8 *bos, guint8 *ttl);

extern gboolean dissect_try_cw_first_nibble(tvbuff_t *tvb, packet_info *pinfo,
                                            proto_tree *tree );
int dissect_mpls_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

#endif
