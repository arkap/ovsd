/*
 * ovsd - Open vSwitch integration into OpenWrt's netifd
 * Copyright (C) 2016 Arne Kappen <arne.kappen@hhi.fraunhofer.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <net/if.h>

#include <libubox/utils.h>
#include <libubus.h>
#include <uci_blob.h>

#include "ovs.h"
#include "ubus.h"


struct ubus_context *ubus_ctx = NULL;
static struct blob_buf bbuf;
static const char *ubus_path;
static struct ubus_object ovsd_obj;

static int
_ovs_error_to_ubus_error(int s)
{
	switch (s) {
		case OVSD_ENOEXIST:         return UBUS_STATUS_NOT_FOUND;
		case OVSD_EINVALID_ARG:     /* fall-through */
		case OVSD_EINVALID_VLAN:    return UBUS_STATUS_INVALID_ARGUMENT;
		case OVSD_ENOPARENT:        return UBUS_STATUS_NOT_FOUND;
		default:                    return UBUS_STATUS_UNKNOWN_ERROR;
	}
}

static int
ovsd_add_ubus_object(void)
{
	int ret = ubus_add_object(ubus_ctx, &ovsd_obj);

	if (ret) {
		ovsd_log_msg(L_CRIT, "Failed to register '%s' ubus object: "
		       "%s\n", ovsd_obj.name, ubus_strerror(ret));
		return ret;
	}
	return 0;
}

static void
ovsd_ubus_add_fd(void)
{
	ubus_add_uloop(ubus_ctx);
}

static void
ovsd_timed_ubus_reconnect(struct uloop_timeout *to)
{
	static struct uloop_timeout retry = {
		.cb = ovsd_timed_ubus_reconnect,
	};
	int t = 2;

	ovsd_log_msg(L_WARNING, "ubus connection lost\n");

	if (ubus_reconnect(ubus_ctx, ubus_path) != 0) {
		ovsd_log_msg(L_WARNING, "ubus reconnect failed, "
			  "retry in %ds\n", t);
		uloop_timeout_set(&retry, t * 1000);
		return;
	}

	ovsd_log_msg(L_NOTICE, "reconnected to ubus\n");
	ovsd_ubus_add_fd();
}

static void
ovsd_ubus_connection_lost_cb(struct ubus_context *ubus_ctx)
{
	ovsd_timed_ubus_reconnect(NULL);
}

int
ovsd_ubus_init(const char *path)
{
	uloop_init();
	ubus_path = path;

	ubus_ctx = ubus_connect(path);
	if (!ubus_ctx)
		return -EIO;

	ovsd_log_msg(L_NOTICE, "connected to ubus\n");
	ubus_ctx->connection_lost = ovsd_ubus_connection_lost_cb;
	ovsd_ubus_add_fd();

	ovsd_add_ubus_object();

	return 0;
}

static char**
_parse_strarray(struct blob_attr *tb, size_t *n_entries)
{
	int n;
	struct blob_attr *cur;
	int offset = 0;
	char **arr, *s;

	n = blobmsg_check_array(tb, BLOBMSG_TYPE_STRING);
	if (n < 0) {
		/* single-entry string arrays get interpreted as strings.
		 * blobmsg_check_array returns -1 in this case.
		 */
		if (blobmsg_type(tb) == BLOBMSG_TYPE_STRING) {
			n = 1;
		} else {
			goto error;
		}
	}

	arr = calloc(n, sizeof(char*));
	if (!arr)
		goto error;

	blobmsg_for_each_attr(cur, tb, n) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		s = blobmsg_get_string(cur);
		if (!s)
			goto error_free;

		arr[offset++] = s;
	}

	*n_entries = offset;
	return arr;

error_free:
	free(arr);
error:
	*n_entries = 0;
	return NULL;
}

enum {
	CREATPOL_BRIDGE,
	CREATPOL_PARENT,
	CREATPOL_VLAN,
	CREATPOL_OFCONTROLLERS,
	CREATPOL_FAILMODE,
	CREATPOL_SSLPRIVKEY,
	CREATPOL_SSLCERT,
	CREATPOL_SSLCACERT,
	CREATPOL_BOOTSTRAP_SSLCACERT,
	CREATPOL_SSLPROTO,
	CREATPOL_SSLCIPHERS,
	CREATPOL_OFPROTO,
	__CREATPOL_MAX
};
static const struct blobmsg_policy create_policy[__CREATPOL_MAX] = {
	[CREATPOL_BRIDGE] = { "name", BLOBMSG_TYPE_STRING },
	[CREATPOL_PARENT] = { "parent", BLOBMSG_TYPE_STRING },
	[CREATPOL_VLAN] = { "vlan", BLOBMSG_TYPE_INT32 },
	[CREATPOL_OFCONTROLLERS] = { "ofcontrollers", BLOBMSG_TYPE_ARRAY },
	[CREATPOL_FAILMODE] = { "controller_fail_mode", BLOBMSG_TYPE_STRING },
	[CREATPOL_OFPROTO] = { "ofproto", BLOBMSG_TYPE_ARRAY },
	[CREATPOL_SSLPRIVKEY] = { "ssl_private_key", BLOBMSG_TYPE_STRING },
	[CREATPOL_SSLCERT] = { "ssl_cert", BLOBMSG_TYPE_STRING },
	[CREATPOL_SSLCACERT] = { "ssl_ca_cert", BLOBMSG_TYPE_STRING },
	[CREATPOL_BOOTSTRAP_SSLCACERT] =
			{ "ssl_bootstrap_ca_cert",BLOBMSG_TYPE_STRING },
	[CREATPOL_SSLPROTO] = { "ssl_proto", BLOBMSG_TYPE_ARRAY },
	[CREATPOL_SSLCIPHERS] = { "ssl_ciphers", BLOBMSG_TYPE_ARRAY },
};

enum {
	GETDPIDPOL_NAME,
	__GETDPIDPOL_MAX
};
static const struct blobmsg_policy get_dpid_policy[__GETDPIDPOL_MAX] = {
	[GETDPIDPOL_NAME] = { "name", BLOBMSG_TYPE_STRING },
};

#ifdef DEBUG
static void debug_dump_attr_data(struct blob_attr *msg);

static void debug_dump_table(struct blob_attr *attr, int len, bool array)
{
	struct blob_attr *cur;
	struct blobmsg_hdr *hdr;

	__blob_for_each_attr(cur, attr, len) {
		hdr = blob_data(cur);
		if (!array)
			ovsd_log_msg(L_DEBUG, "%s :", hdr->name);
		debug_dump_attr_data(attr);
	}
}

static void debug_dump_attr_data(struct blob_attr *msg)
{
	struct blob_attr *cur;
	int rem;
	int type;

	blobmsg_for_each_attr(cur, msg, rem) {
		type = blobmsg_type(cur);
		switch (type) {
			case BLOBMSG_TYPE_ARRAY:
			case BLOBMSG_TYPE_TABLE:
				debug_dump_table(blob_data(cur), blob_len(cur), type == BLOBMSG_TYPE_ARRAY);
				break;
			case BLOBMSG_TYPE_STRING:
				ovsd_log_msg(L_DEBUG, "%s: %s\n", blobmsg_name(cur), blobmsg_get_string(cur));
				break;
			case BLOBMSG_TYPE_INT64:
				ovsd_log_msg(L_DEBUG, "%s: %lu\n", blobmsg_name(cur), blobmsg_get_u64(cur));
				break;
			case BLOBMSG_TYPE_INT32:
				ovsd_log_msg(L_DEBUG, "%s: %d\n", blobmsg_name(cur), blobmsg_get_u32(cur));
				break;
			case BLOBMSG_TYPE_INT16:
				ovsd_log_msg(L_DEBUG, "%s: %d\n", blobmsg_name(cur), blobmsg_get_u16(cur));
				break;
			case BLOBMSG_TYPE_INT8:
				ovsd_log_msg(L_DEBUG, "%s: %d\n", blobmsg_name(cur), blobmsg_get_u8(cur));
				break;
			default:
				break;

		}
	}
}
#endif

static int
handle_get_datapath_id(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct blob_attr *tb;
	char dpid_buf[17], *br = NULL, **br_list = NULL, **dpid_list = NULL;
	size_t n;
	void *cookie;
	int ret;
	bool single = false;

	ret = blobmsg_parse(get_dpid_policy, 1, &tb, blobmsg_data(msg),
				blobmsg_len(msg));
	if (ret) {
		ret = ovs_get_bridges(&br_list, &dpid_list, &n);
	} else if (tb) {
		br = blobmsg_get_string(tb);
		single = true;
		ret = ovs_get_datapath_id(br, dpid_buf);
		n = 1;
	} else {
		goto parse_error;
	}

	if (ret)
		goto cleanup;

	blob_buf_init(&bbuf, 0);
	cookie = blobmsg_open_table(&bbuf, "bridges");
	if (single)
		blobmsg_add_string(&bbuf, br, dpid_buf);
	else
		for (size_t i = 0; i < n; i++)
			blobmsg_add_string(&bbuf, br_list[i], dpid_list[i]);
	blobmsg_close_table(&bbuf, cookie);

	ret = ubus_send_reply(ubus_ctx, req, bbuf.head);

cleanup:
	if (dpid_list) free(dpid_list);
	if (br_list) free(br_list);

	return ret;

parse_error:
	return UBUS_STATUS_INVALID_ARGUMENT;
}

static int
parse_ofcontroller_opts(struct blob_attr **tb, struct ovswitch_br_config *cfg)
{
	const char *s;

	if (!tb[CREATPOL_OFCONTROLLERS])
		return 0;

	cfg->ofcontrollers = _parse_strarray(tb[CREATPOL_OFCONTROLLERS],
		&cfg->n_ofcontrollers);

	if (!cfg->ofcontrollers)
		return -1;

	if (tb[CREATPOL_FAILMODE]) {
		s = blobmsg_get_string(tb[CREATPOL_FAILMODE]);
		if (!strcmp(s, "standalone"))
			cfg->fail_mode = OVS_FAIL_MODE_STANDALONE;
		else if (!strcmp(s, "secure"))
			cfg->fail_mode = OVS_FAIL_MODE_SECURE;
		else
			return -1;
	} else {
		cfg->fail_mode = OVS_FAIL_MODE_SECURE;
	}

	return 0;
}

static int
parse_ofproto_opts(struct blob_attr **tb, struct ovswitch_br_config *cfg)
{
	static const size_t ofp_len = strlen("OpenFlow1x,");
	static const size_t proto_len = strlen("protocols=");

	char **arr, *ptr;
	int ret;
	size_t n;

	arr = _parse_strarray(tb[CREATPOL_OFPROTO], &n);
	if (!arr)
		return -1;

	cfg->ofproto = malloc(proto_len + n * ofp_len);
	if (!cfg->ofproto)
		return ENOMEM;

	snprintf(cfg->ofproto, proto_len + 1, "protocols=");
	ptr = cfg->ofproto + proto_len;
	for (int i = 0; i < n; i++) {
		ret = snprintf(ptr, ofp_len + 1, "OpenFlow%s,", arr[i]);
		if (ret != ofp_len)
			goto error;

		ptr += ofp_len;
	}

	*ptr = '\0';
	free(arr);

	return 0;

error:
	free(arr);
	free(cfg->ofproto);
	return -1;
}

static int
parse_ssl_opts(struct blob_attr **tb, struct ovswitch_br_config *cfg)
{
	char *s, **arr;
	size_t n;

	s = blobmsg_get_string(tb[CREATPOL_SSLPRIVKEY]);
	if (!s)
		return UBUS_STATUS_INVALID_ARGUMENT;
	cfg->ssl.privkey_file = s;

	s = blobmsg_get_string(tb[CREATPOL_SSLCERT]);
	if (!s)
		return UBUS_STATUS_INVALID_ARGUMENT;
	cfg->ssl.cert_file = s;

	if (tb[CREATPOL_SSLCACERT]) {
		s = blobmsg_get_string(tb[CREATPOL_SSLCACERT]);
		cfg->ssl.bootstrap = false;
	} else if (tb[CREATPOL_BOOTSTRAP_SSLCACERT]) {
		s = blobmsg_get_string(tb[CREATPOL_BOOTSTRAP_SSLCACERT]);
		cfg->ssl.bootstrap = true;
	} else {
		return -1;
	}

	cfg->ssl.cacert_file = s;

	if (tb[CREATPOL_SSLPROTO]) {
		arr = _parse_strarray(tb[CREATPOL_SSLPROTO], &n);
		if (!arr)
			return -1;
		cfg->ssl.proto = arr;
		cfg->ssl.n_proto = n;
	}

	if (tb[CREATPOL_SSLCIPHERS]) {
		arr = _parse_strarray(tb[CREATPOL_SSLCIPHERS], &n);
		if (!arr)
			return -1;
		cfg->ssl.ciphers = arr;
		cfg->ssl.n_ciphers = n;
	}

	return 0;
}

static int
parse_create_msg(struct blob_attr **tb, struct ovswitch_br_config *cfg)
{
	if (!tb[CREATPOL_BRIDGE])
		return UBUS_STATUS_INVALID_ARGUMENT;
	cfg->name = blobmsg_get_string(tb[CREATPOL_BRIDGE]);

	if (tb[CREATPOL_PARENT] && tb[CREATPOL_VLAN]) {
		cfg->parent = blobmsg_get_string(tb[CREATPOL_PARENT]);
		cfg->vlan_tag = blobmsg_get_u32(tb[CREATPOL_VLAN]);
	}

	if (tb[CREATPOL_SSLPRIVKEY] && tb[CREATPOL_SSLCERT])
		parse_ssl_opts(tb, cfg);

	parse_ofcontroller_opts(tb, cfg);

	if (tb[CREATPOL_OFPROTO])
		parse_ofproto_opts(tb, cfg);

	return 0;
}

static int
handle_create(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	struct blob_attr *tb[__CREATPOL_MAX];
	struct ovswitch_br_config ovs_cfg;
	int ret;

	ret = blobmsg_parse(create_policy, __CREATPOL_MAX, tb, blob_data(msg),
		blob_len(msg));
	if (ret)
		return ret;

	memset(&ovs_cfg, 0, sizeof(ovs_cfg));

	ret = parse_create_msg(tb, &ovs_cfg);
	if (ret)
		return ret;

	ret = ovs_create(&ovs_cfg);

	if (ovs_cfg.ofcontrollers) {
		free(ovs_cfg.ofcontrollers);
		free(ovs_cfg.ofproto);
	}

	if (ret)
		return _ovs_error_to_ubus_error(ret);

	ovsd_log_msg(L_NOTICE, "Created ovs %s\n", ovs_cfg.name);

	return 0;
}

static int
handle_reload(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
	      const char *method, struct blob_attr *msg)
{
	ovsd_log_msg(L_DEBUG, "call :: %s\n", __func__);

	enum {
		RELOAD_POLICY_OLD,
		RELOAD_POLICY_NEW,
		__RELOAD_MAX
	};

	static const struct blobmsg_policy pol[__RELOAD_MAX] = {
		[RELOAD_POLICY_OLD] = { "old", BLOBMSG_TYPE_TABLE },
		[RELOAD_POLICY_NEW] = { "new", BLOBMSG_TYPE_TABLE },
	};

	static const struct uci_blob_param_list cfg_params = {
		.params = create_policy,
		.n_params = __CREATPOL_MAX,
	};

	/* Config fields that make an on-the-fly reload impossible and require device re-creation */
	static const unsigned long HARD_RELOAD_MASK =
		(1 << CREATPOL_BRIDGE) | /* difference in bridge name */
		(1 << CREATPOL_PARENT) | /* difference in parent bridge */
		(1 << CREATPOL_VLAN);    /* difference in VLAN tag */

	unsigned long diff;
	int ret;
	struct blob_attr *tb[__RELOAD_MAX], *tb_old[__CREATPOL_MAX], *tb_new[__CREATPOL_MAX];
	struct ovswitch_br_config ovs_cfg_old, ovs_cfg_new;

	ret = blobmsg_parse(pol, __RELOAD_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));
	if (ret || !tb[RELOAD_POLICY_OLD] || !tb[RELOAD_POLICY_NEW])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ret = blobmsg_parse(create_policy, __CREATPOL_MAX, tb_old,
		blobmsg_data(tb[RELOAD_POLICY_OLD]), blobmsg_len(tb[RELOAD_POLICY_OLD]));
	ret |= blobmsg_parse(create_policy, __CREATPOL_MAX, tb_new,
		blobmsg_data(tb[RELOAD_POLICY_NEW]), blobmsg_len(tb[RELOAD_POLICY_NEW]));
	if (ret)
		return UBUS_STATUS_INVALID_ARGUMENT;

	diff = 0;
	uci_blob_diff(tb_old, tb_new, &cfg_params, &diff);
	if (!diff)
		return UBUS_STATUS_OK;

	if (diff & HARD_RELOAD_MASK)
		return UBUS_STATUS_NOT_SUPPORTED;

	memset(&ovs_cfg_old, 0, sizeof(ovs_cfg_old));
	memset(&ovs_cfg_old, 0, sizeof(ovs_cfg_new));

	ret = parse_create_msg(tb_old, &ovs_cfg_old);
	ret |= parse_create_msg(tb_new, &ovs_cfg_new);
	if (ret) {
		ret = UBUS_STATUS_INVALID_ARGUMENT;
		goto cleanup;
	}

	ret = ovs_reload(&ovs_cfg_new);
	if (ret)
		return _ovs_error_to_ubus_error(ret);

	ovsd_log_msg(L_NOTICE, "Reloaded ovs %s\n", ovs_cfg_old.name);

cleanup:
	if (ovs_cfg_old.ofcontrollers) free(ovs_cfg_old.ofcontrollers);
	if (ovs_cfg_new.ofcontrollers) free(ovs_cfg_new.ofcontrollers);
	if (ovs_cfg_old.ofproto) free(ovs_cfg_old.ofproto);
	if (ovs_cfg_new.ofproto) free(ovs_cfg_new.ofproto);

	return ret;
}

enum {
	DUMP_INFO_POLICY_NAME,
	__DUMP_INFO_POLICY_MAX,
};

static struct blobmsg_policy dump_info_policy[__DUMP_INFO_POLICY_MAX] = {
	[DUMP_INFO_POLICY_NAME] = { "name", BLOBMSG_TYPE_STRING },
};

static int
_handle_dump_info(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__DUMP_INFO_POLICY_MAX];

	blobmsg_parse(dump_info_policy, __DUMP_INFO_POLICY_MAX, tb,
		blobmsg_data(msg), blobmsg_len(msg));

	blob_buf_init(&bbuf, 0);
	ovs_dump_info(&bbuf, blobmsg_get_string(tb[DUMP_INFO_POLICY_NAME]));

	ubus_send_reply(ubus_ctx, req, bbuf.head);
	return 0;
}

static const struct blobmsg_policy no_policy[] = {};

static int
__no_handler(struct ubus_context *ctx, struct ubus_object *obj,
	     struct ubus_request_data *req, const char *method,
	     struct blob_attr *msg)
{
	return 0;
}

enum {
	DELPOL_NAME,
	__DELPOL_MAX
};
static const struct blobmsg_policy delete_policy[__DELPOL_MAX] = {
	[DELPOL_NAME] = { "name", BLOBMSG_TYPE_STRING },
};

static int
handle_free(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	struct blob_attr *tb[__DELPOL_MAX];
	char *name;
	int ret;

	blobmsg_parse(delete_policy, __DELPOL_MAX, tb, blobmsg_data(msg),
		blobmsg_len(msg));

	if (!tb[DELPOL_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	name = blobmsg_get_string(tb[DELPOL_NAME]);
	ret = ovs_delete(name);

	if (ret)
		return _ovs_error_to_ubus_error(ret);

	ovsd_log_msg(L_NOTICE, "deleted ovs '%s'\n", name);

	return 0;
}

enum {
	CHECK_STATE_POLICY_NAME,
	__CHECK_STATE_POLICY_MAX
};

static struct blobmsg_policy check_state_policy[__CHECK_STATE_POLICY_MAX] = {
	[CHECK_STATE_POLICY_NAME] = { "name", BLOBMSG_TYPE_STRING },
};

static int
handle_check_state(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__CHECK_STATE_POLICY_MAX];

	blobmsg_parse(check_state_policy, __CHECK_STATE_POLICY_MAX, tb,
			blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[CHECK_STATE_POLICY_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (ovs_check_state(blobmsg_get_string(tb[CHECK_STATE_POLICY_NAME])))
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

enum {
	ADDPOL_BRIDGE,
	ADDPOL_MEMBER,
	__ADDPOL_MAX
};

static const struct blobmsg_policy hotplug_add_policy[__ADDPOL_MAX] = {
	[ADDPOL_BRIDGE] = { "bridge",  BLOBMSG_TYPE_STRING },
	[ADDPOL_MEMBER] = { "member",  BLOBMSG_TYPE_STRING },
};

static int
handle_hotplug_add(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__ADDPOL_MAX];
	char *bridge, *port;
	int ret;

	blobmsg_parse(hotplug_add_policy, __ADDPOL_MAX, tb,
		blob_data(msg), blob_len(msg));

	if (!tb[ADDPOL_BRIDGE] || !tb[ADDPOL_MEMBER])
		return UBUS_STATUS_INVALID_ARGUMENT;

	bridge = blobmsg_get_string(tb[ADDPOL_BRIDGE]);
	port = blobmsg_get_string(tb[ADDPOL_MEMBER]);
	ret = ovs_add_port(bridge, port);

	if (ret)
		return _ovs_error_to_ubus_error(ret);

	ovsd_log_msg(L_NOTICE, "ovs '%s': new port '%s'\n", bridge, port);

	return 0;
}

enum {
	RMPOL_BRIDGE,
	RMPOL_MEMBER,
	__RMPOL_MAX,
};
static const struct blobmsg_policy hotplug_del_policy[__RMPOL_MAX] = {
	[RMPOL_BRIDGE] = { "bridge", BLOBMSG_TYPE_STRING },
	[RMPOL_MEMBER] = { "member", BLOBMSG_TYPE_STRING },
};

static int
handle_hotplug_remove(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[__RMPOL_MAX];
	char *bridge, *port;
	int ret;

	blobmsg_parse(hotplug_del_policy, __RMPOL_MAX, tb,
		blob_data(msg), blob_len(msg));

	if (!tb[RMPOL_BRIDGE] || !tb[RMPOL_MEMBER])
		return UBUS_STATUS_INVALID_ARGUMENT;

	bridge = blobmsg_get_string(tb[RMPOL_BRIDGE]);
	port = blobmsg_get_string(tb[RMPOL_MEMBER]);

	ret = ovs_remove_port(bridge, port);
	if (ret)
		return _ovs_error_to_ubus_error(ret);

	ovsd_log_msg(L_NOTICE, "ovs '%s': removed port '%'\n", bridge, port);

	return 0;
}

enum {
	METHOD_GET_DATAPATH_ID,
	METHOD_CREATE,
	METHOD_CONFIG_INIT,
	METHOD_RELOAD,
	METHOD_DUMP_INFO,
	METHOD_DUMP_STATS,
	METHOD_CHECK_STATE,
	METHOD_FREE,
	METHOD_HOTPLUG_ADD,
	METHOD_HOTPLUG_REMOVE,
	METHOD_HOTPLUG_PREPARE,
	__METHODS_MAX
};
static struct ubus_method ubus_methods[__METHODS_MAX] = {
	[METHOD_GET_DATAPATH_ID] = UBUS_METHOD("get_datapath_id",
		handle_get_datapath_id, get_dpid_policy),
	[METHOD_CREATE] = UBUS_METHOD("create", handle_create, create_policy),
	[METHOD_CONFIG_INIT] = UBUS_METHOD("configure", __no_handler,
		no_policy),
	[METHOD_RELOAD] = UBUS_METHOD("reload", handle_reload, create_policy),
	[METHOD_DUMP_INFO] = UBUS_METHOD("dump_info", _handle_dump_info,
		dump_info_policy),
	[METHOD_DUMP_STATS] = UBUS_METHOD_NOARG("dump_stats", __no_handler),
	[METHOD_CHECK_STATE] = UBUS_METHOD("check_state", handle_check_state,
		check_state_policy),
	[METHOD_FREE] = UBUS_METHOD("free", handle_free, delete_policy),
	[METHOD_HOTPLUG_ADD] = UBUS_METHOD("add", handle_hotplug_add,
		hotplug_add_policy),
	[METHOD_HOTPLUG_REMOVE] = UBUS_METHOD("remove", handle_hotplug_remove,
		hotplug_del_policy),
	[METHOD_HOTPLUG_PREPARE] = UBUS_METHOD("prepare", __no_handler,
		no_policy),
};

static struct ubus_object_type ovsd_obj_type =
	UBUS_OBJECT_TYPE("ovsd", ubus_methods);

static struct ubus_object ovsd_obj = {
	.name = "ovs",
	.type = &ovsd_obj_type,
	.methods = ubus_methods,
	.n_methods = __METHODS_MAX,
};
