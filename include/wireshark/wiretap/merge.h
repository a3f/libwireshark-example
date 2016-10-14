/* merge.h
 * Definitions for routines for merging files.
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

#ifndef __MERGE_H__
#define __MERGE_H__

#include "wiretap/wtap.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
  PACKET_PRESENT,
  PACKET_NOT_PRESENT,
  AT_EOF,
  GOT_ERROR
} in_file_state_e;

/**
 * Structures to manage our input files.
 */
typedef struct merge_in_file_s {
  const char     *filename;
  wtap           *wth;
  gint64          data_offset;
  in_file_state_e state;
  guint32         packet_num;	  /* current packet number */
  gint64          size;		      /* file size */
  guint32         interface_id;   /* identifier of the interface.
								   * Used for fake interfaces when writing WTAP_ENCAP_PER_PACKET */
} merge_in_file_t;

/** Open a number of input files to merge.
 *
 * @param in_file_count number of entries in in_file_names and in_files
 * @param in_file_names filenames of the input files
 * @param in_files input file array to be filled (>= sizeof(merge_in_file_t) * in_file_count)
 * @param err wiretap error, if failed
 * @param err_info wiretap error string, if failed
 * @param err_fileno file on which open failed, if failed
 * @return TRUE if all files could be opened, FALSE otherwise
 */
WS_DLL_PUBLIC gboolean
merge_open_in_files(int in_file_count, char *const *in_file_names,
                    merge_in_file_t **in_files, int *err, gchar **err_info,
                    int *err_fileno);

/** Close the input files again.
 *
 * @param in_file_count number of entries in in_files
 * @param in_files input file array to be closed
 */
WS_DLL_PUBLIC void
merge_close_in_files(int in_file_count, merge_in_file_t in_files[]);

/** Try to get the frame type from the input files.
 *
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @return the frame type
 */
WS_DLL_PUBLIC int
merge_select_frame_type(int in_file_count, merge_in_file_t in_files[]);

/** Try to get the snapshot length from the input files.
 *
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @return the snapshot length
 */
WS_DLL_PUBLIC int
merge_max_snapshot_length(int in_file_count, merge_in_file_t in_files[]);

/** Read the next packet, in chronological order, from the set of files to
 * be merged.
 *
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @param err wiretap error, if failed
 * @param err_info wiretap error string, if failed
 * @return pointer to merge_in_file_t for file from which that packet
 * came, or NULL on error or EOF
 */
WS_DLL_PUBLIC merge_in_file_t *
merge_read_packet(int in_file_count, merge_in_file_t in_files[], int *err,
                  gchar **err_info);


/** Read the next packet, in file sequence order, from the set of files
 * to be merged.
 *
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @param err wiretap error, if failed
 * @param err_info wiretap error string, if failed
 * @return pointer to merge_in_file_t for file from which that packet
 * came, or NULL on error or EOF
 */
WS_DLL_PUBLIC merge_in_file_t *
merge_append_read_packet(int in_file_count, merge_in_file_t in_files[],
                         int *err, gchar **err_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MERGE_H__ */

