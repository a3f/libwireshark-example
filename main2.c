#define HAVE_STDARG_H 1
#define WS_MSVC_NORETURN
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#ifdef _WIN32
#define access(s,i) _access(s,i)
#endif
#include <string.h>
#include <epan/epan.h>
#include <epan/print.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/epan-int.h>
#include <wsutil/privileges.h>
#include <epan/epan_dissect.h>
#include <epan/proto.h>
#include <epan/ftypes/ftypes.h>
#include <epan/asm_utils.h>

#define BUFSIZE 2048 * 100

extern tvbuff_t *frame_tvbuff_new(const frame_data *fd, const guint8 *buf);
static void timestamp_set(capture_file cfile);
static const nstime_t *tshark_get_frame_ts(void *data, guint32 frame_num);
static void clean();

//global variable
capture_file cfile;

e_prefs *get_prefs()
{
	e_prefs     *prefs_p;
	char        *gpf_path, *pf_path;
	int          gpf_read_errno, gpf_open_errno;
	int          pf_open_errno, pf_read_errno;

	prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
			&pf_open_errno, &pf_read_errno, &pf_path);
	return prefs_p;
}

int init(char *filename)
{
	int          err = 0;
	char       *err_info = NULL;
	e_prefs     *prefs_p;

	init_process_policies();
    epan_register_plugin_types(); /* Types known to libwireshark */
    wtap_register_plugin_types(); /* Types known to libwiretap */

    if (!epan_init(register_all_protocols, register_all_protocol_handoffs, NULL,
                NULL)) {
        fprintf(stderr, "Error at epan_init\n");
        return 2;
    }

    proto_initialize_all_prefixes();

	cap_file_init(&cfile);
	cfile.filename = filename;

	cfile.wth = wtap_open_offline(cfile.filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
	if (cfile.wth == NULL)
		goto fail;

	cfile.count = 0;
	cfile.epan = epan_new();
	cfile.epan->data = &cfile;
	cfile.epan->get_frame_ts = tshark_get_frame_ts;

	timestamp_set(cfile);
	cfile.frames = new_frame_data_sequence();

	prefs_p = get_prefs();

	build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

	return 0;

fail:
	clean();
	return err;
}

gboolean read_packet(epan_dissect_t **edt_r)
{
	epan_dissect_t    *edt;
	int                err;
	char             *err_info = NULL;
	static guint32     cum_bytes = 0;
	static gint64      data_offset = 0;

	struct wtap_pkthdr *whdr = wtap_phdr(cfile.wth);
	unsigned char             *buf = wtap_buf_ptr(cfile.wth);

	while (wtap_read(cfile.wth, &err, &err_info, &data_offset)) {

		cfile.count++;

		frame_data fdlocal;
		frame_data_init(&fdlocal, cfile.count, whdr, data_offset, cum_bytes);


		edt = epan_dissect_new(cfile.epan, TRUE, TRUE);

		frame_data_set_before_dissect(&fdlocal, &cfile.elapsed_time, &cfile.ref, cfile.prev_dis);
		cfile.ref = &fdlocal;

		/*epan_dissect_run(edt, cfile.cd_t, &(cfile.phdr), frame_tvbuff_new(&fdlocal, buf), &fdlocal, &cfile.cinfo);*/
        epan_dissect_run_with_taps(edt, cfile.cd_t, whdr, frame_tvbuff_new(&fdlocal, buf), &fdlocal, &cfile.cinfo);

		frame_data_set_after_dissect(&fdlocal, &cum_bytes);
		cfile.prev_cap = cfile.prev_dis = frame_data_sequence_add(cfile.frames, &fdlocal);

		//free space
		frame_data_destroy(&fdlocal);

		*edt_r = edt;
		return TRUE;
	}
	return FALSE;
}

void clean()
{
	if (cfile.frames != NULL) {
		free_frame_data_sequence(cfile.frames);
		cfile.frames = NULL;
	}

	if (cfile.wth != NULL) {
		wtap_close(cfile.wth);
		cfile.wth = NULL;
	}

	if (cfile.epan != NULL)
		epan_free(cfile.epan);

	epan_cleanup();
}

static void
timestamp_set(capture_file cfile)
{
    timestamp_set_precision(TS_PREC_AUTO);
}

static const nstime_t *
tshark_get_frame_ts(void *data, guint32 frame_num)
{
  capture_file *cf = (capture_file *) data;

  if (cf->ref && cf->ref->num == frame_num)
    return &(cf->ref->abs_ts);

  if (cf->prev_dis && cf->prev_dis->num == frame_num)
    return &(cf->prev_dis->abs_ts);

  if (cf->prev_cap && cf->prev_cap->num == frame_num)
    return &(cf->prev_cap->abs_ts);

  if (cf->frames) {
     frame_data *fd = frame_data_sequence_find(cf->frames, frame_num);

     return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

void
cap_file_init(capture_file *cf)
{
	/* Initialize the capture file struct */
	memset(cf, 0, sizeof(capture_file));
	cf->snap            = WTAP_MAX_PACKET_SIZE;
}

void print_usage(char *argv[])
{
	printf("Usage: %s -f <input_file>\n", argv[0]);
}

static void
print_field(proto_node *node, int *level, char **buf)
{
	if (node->finfo == NULL)
		return;

	//reset level when node is proto
        if (node->finfo->hfinfo->type == FT_PROTOCOL)
		*level = 0;

	for (int i = 0; i < *level; i++) {
		snprintf(*buf + strlen(*buf), BUFSIZE, "%s", ". ");
	}

	const char *name = node->finfo->hfinfo->abbrev;

	fvalue_t fv = node->finfo->value;
	char *value = fvalue_to_string_repr(NULL, &fv, FTREPR_DISPLAY, node->finfo->hfinfo->display);

	if (value == NULL) {
		snprintf(*buf + strlen(*buf), BUFSIZE, "[%s]\n", name);
	} else {
		snprintf(*buf + strlen(*buf), BUFSIZE, "[%s] %s\n", name, value);
	}
}

void visit(proto_node *node, gpointer data)
{
    field_info *fi  = PNODE_FINFO(node);
	char *buf = calloc(1, BUFSIZE);
	int level = 0;

	print_field(node, &level, &buf);

	level++;
    g_assert((fi->tree_type >= -1) && (fi->tree_type < num_tree_types));
    if (node->first_child != NULL) {
        level++;
        proto_tree_children_foreach(node, visit, data);
        level--;
    }

	printf("%s", buf);

	free(buf);
}

void print_each_packet_self_format()
{
	epan_dissect_t *edt;

	while (read_packet(&edt)) {

		/*print_node(edt);*/
        proto_tree_children_foreach(edt->tree, visit, NULL);

		epan_dissect_free(edt);
		edt = NULL;
	}
}

int main(int argc, char* argv[])
{

	int          err;
	char        *filename = NULL;
	int          opt;

	while((opt = getopt(argc, argv, "f:")) != -1) {
		switch(opt) {
		case 'f':
			filename = strdup(optarg);
			break;
		default:
			print_usage(argv);
			return 1;
		}
	}

	if (filename == NULL) {
		print_usage(argv);
		return 1;
	}

    if (access(filename, F_OK) == -1) {
        fprintf(stderr, "File '%s' doesn't exist.\n", filename);
        return 1;
    }

	err = init(filename);
	if (err) {
		return 1;
	}

	print_each_packet_self_format();

	clean();
	return 0;
}

