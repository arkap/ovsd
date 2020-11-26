/*
 * ovsd - Open vSwitch device handler for OpenWrt's netifd
 * Copyright (C) 2016 Arne Kappen <arne.kappen@hhi.fraunhofer.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <net/if.h>
#include <errno.h>
#include <libubox/utils.h>

#include "ovs-shell.h"

#define DPID_STRLEN 16
#define CMD_LEN_MAX 65536
#define VLAN_TAG_MASK 0xfff


enum {
	RECORD_DATAPATH_ID,
	__RECORD_MAX
};

static char * const ovs_record[__RECORD_MAX] = {
	[RECORD_DATAPATH_ID] = "datapath_id",
};

enum {
	TABLE_BRIDGE,
	__TABLE_MAX
};

static char * const ovs_table[__TABLE_MAX] = {
	[TABLE_BRIDGE] = "bridge",
};

static char * const ovs_vsctl_cmd[__CMD_MAX] = {
	[CMD_CREATE_BR]					= "add-br",
	[CMD_DEL_BR]					= "del-br",
	[CMD_ADD_PORT]					= "add-port",
	[CMD_DEL_PORT]					= "del-port",
	[CMD_BR_EXISTS]					= "br-exists",
	[CMD_BR_TO_VLAN]				= "br-to-vlan",
	[CMD_BR_TO_PARENT]				= "br-to-parent",

	[CMD_SET_OFCTL]					= "set-controller",
	[CMD_DEL_OFCTL]					= "del-controller",
	[CMD_GET_OFCTL]					= "get-controller",
	[CMD_SET_FAIL_MODE]				= "set-fail-mode",
	[CMD_DEL_FAIL_MODE]				= "del-fail-mode",
	[CMD_GET_FAIL_MODE]				= "get-fail-mode",
	[CMD_SET_SSL]					= "set-ssl",
	[CMD_DEL_SSL]					= "del-ssl",
	[CMD_GET_SSL]					= "get-ssl",

	[CMD_GET_TBL]					= "get",
	[CMD_SET_TBL]					= "set",

	[CMD_LIST_BR]					= "list-br",
	[CMD_LIST_PORTS]				= "list-ports",

	[OPT_MAY_EXIST]					= "--may-exist",
	[OPT_IF_EXISTS]					= "--if-exists",
	[OPT_SSL_BOOTSTRAP]				= "--bootstrap",

	[KVOPT_SSL_PROTOCOLS]				= "--ssl-protocols",
	[KVOPT_SSL_CIPHERS]				= "--ssl-ciphers",

	[ATOMIC_CMD_SEPARATOR]				= "--",
};


char*
ovs_cmd(enum ovs_vsctl_cmd cmd)
{
	if (cmd > __CMD_MAX)
		return NULL;

	return ovs_vsctl_cmd[cmd];
}

#ifdef DEBUG
static void
debug_print_argv(char * const *argv)
{
	char *str;
	size_t len = 0, pos = 0;

	for (size_t i = 0; argv[i] != NULL; i++)
		len += strlen(argv[i]) + 1;

	len += 2;

	str = malloc(len * sizeof(char));
	if (!str)
		return;

	for (size_t i = 0; argv[i] != NULL; i++)
		pos += sprintf(str + pos, "%s ", argv[i]);

	ovsd_log_msg(L_DEBUG, "calling %s\n", str);
	free(str);
}
#endif

int
ovs_vsctl(char * const *argv)
{
	int rc, status;
	pid_t pid = fork();
	if (!pid)
		exit(execv(OVS_VSCTL, argv));
	if (pid < 0) {
		rc = -1;
	} else {
		do {
			rc = waitpid(pid, &status, 0);
		} while (rc == -1 && errno == EINTR);

		if (rc == pid && WIFEXITED(status))
			rc = WEXITSTATUS(status);
		else
			rc = -1;
	}
	return rc;
}

/* Remove leading and trailing whitespace from string */
static char*
_trim(char *str)
{
	char *end;

	while (isspace(*str))
		str++;

	if (*str == '\0')
		return NULL;

	end = str + strlen(str) - 1;
	while (end > str && isspace(*end))
		end--;

	*(end + 1) = '\0';

	return str;
}

/* Strip escape sequences from string. */
static char *
_strip(char *str)
{
	char *seek_ptr = str, *write_ptr = str;

	while (*seek_ptr != '\0') {
		if (*seek_ptr == '\\')
			seek_ptr++;

		*write_ptr = *seek_ptr;
		write_ptr++;
		seek_ptr++;
	}

	*write_ptr = '\0';
	return str;
}

static void
_lowercase(char *str)
{
	for (; *str != '\0'; str++)
		*str = (char) tolower(*str);
}

static void
_replace(char *str, char c, char other)
{
	for (; *str != '\0'; str++)
		if (*str == c)
			*str = other;
}

static char *
sanitize(char *str)
{
	char edit_buf[SHELL_OUTPUT_LINE_MAXSIZE];
	char *ret;
	strcpy(edit_buf, str);

	ret = _trim(edit_buf);
	ret = _strip(ret);
	strcpy(str, ret);

	_lowercase(str);
	_replace(str, ' ', '_');
	return str;
}

void
ovs_shell_capture_string(const char *cmd, const char *bridge, const char *name,
			 struct blob_buf *buf)
{
	char output[256];
	FILE *f;

	size_t cmd_len = strlen(OVS_VSCTL) + strlen(cmd) + strlen(bridge) + 3;

	if (cmd_len > CMD_LEN_MAX)
		return;

	char cmd_str[cmd_len];
	sprintf(cmd_str, "%s %s %s", OVS_VSCTL, cmd, bridge);

	if ((f = popen(cmd_str, "r")) == NULL)
		return;

	if (fgets(output, 256, f) == NULL)
		goto done;

	blobmsg_add_string(buf, name, sanitize(output));

done:
	pclose(f);
}

void
ovs_shell_capture_list(const char *cmd, const char *bridge,
		       const char *list_name, struct blob_buf *buf, bool table)
{
	char *tmp, out[512];
	FILE *f;
	void *list;
	size_t cmd_len;

	cmd_len = strlen(OVS_VSCTL) + 1 + strlen(cmd) + 1;
	if (bridge)
		cmd_len += strlen(bridge) + 1;

	if (cmd_len > CMD_LEN_MAX)
		return;

	char cmd_str[cmd_len];
	sprintf(cmd_str, "%s %s %s", OVS_VSCTL, cmd, bridge ? bridge : "");

	if ((f = popen(cmd_str, "r")) == NULL)
		return;

	if (table)
		list = blobmsg_open_table(buf, list_name);
	else
		list = blobmsg_open_array(buf, list_name);

	while (fgets(out, 512, f) != NULL) {
		if (table && (tmp = strchr(out, ':'))) {
			*tmp++ = '\0';
			blobmsg_add_string(buf, sanitize(out), sanitize(tmp));
		} else {
			blobmsg_add_string(buf, NULL, sanitize(out));
		}
	}

	if (table)
		blobmsg_close_table(buf, list);
	else
		blobmsg_close_array(buf, list);
	pclose(f);
}

bool
ovs_shell_br_exists(char *name)
{
	char * const argv[4] = {
		[0] = OVS_VSCTL,
		[1] = ovs_vsctl_cmd[CMD_BR_EXISTS],
		[2] = name,
		[3] = NULL,
	};

	return ovs_vsctl(argv) == 0;
}

static int
_ovs_shell_get_output(const char *cmd, const char *bridge, char *buf, int n)
{
	FILE *f;
	size_t cmd_len;
	int ret = 0;

	cmd_len = strlen(OVS_VSCTL) + 1 + strlen(cmd) + 1;
	if (bridge)
		cmd_len += strlen(bridge) + 1;

	if (cmd_len > CMD_LEN_MAX)
		return -1;

	char cmd_str[cmd_len];
	sprintf(cmd_str, "%s %s %s", OVS_VSCTL, cmd, bridge ? bridge : "");

	if ((f = popen(cmd_str, "r")) == NULL)
		return -1;

	if (fgets(buf, n, f) == NULL)
		ret = -1;

	pclose(f);
	return ret;
}

int
ovs_shell_get_datapath_id(char *bridge, char *dpid)
{
	static char cmdbuf[64];

	FILE *f;
	size_t pos = 0;
	char c;

	sprintf(cmdbuf, "%s %s %s %s %s", OVS_VSCTL,
		ovs_vsctl_cmd[CMD_GET_TBL], ovs_table[TABLE_BRIDGE], bridge,
		ovs_record[RECORD_DATAPATH_ID]);

	if ((f = popen(cmdbuf, "r")) == NULL)
		return -1;

	while ((c = fgetc(f)) != EOF) {
		if (!isalnum(c))
			continue;

		dpid[pos++] = c;

		if (pos == 16) {
			dpid[pos] = '\0';
			pclose(f);
			return 0;
		}
	}

	return -1;
}

int
ovs_shell_get_bridges(char ***br_list, char ***dpid_list, size_t *n)
{
	int ret;
	FILE *f;
	char sbuf[IF_NAMESIZE + 1], **br_buf, **dpid_buf = NULL, c;
	size_t pos, ccur, cmd_len, cnt;

	cmd_len = strlen(OVS_VSCTL) + 1 +
			strlen(ovs_vsctl_cmd[CMD_LIST_BR]) + 1;

	char cmd_str[cmd_len];
	sprintf(cmd_str, "%s %s", OVS_VSCTL, ovs_vsctl_cmd[CMD_LIST_BR]);

	if ((f = popen(cmd_str, "r")) == NULL)
		return -1;

	for (cnt = 0; fgets(sbuf, IF_NAMESIZE, f) != NULL; cnt++);
	pclose(f);

	br_buf = malloc(cnt * sizeof(char*));
	dpid_buf = malloc(cnt * sizeof(char*));
	if (!br_buf || !dpid_buf)
		return ENOMEM;

	for (size_t i = 0; i < cnt; i++) {
		br_buf[i] = calloc(IF_NAMESIZE + 1, sizeof(char));
		dpid_buf[i] = calloc(DPID_STRLEN + 1, sizeof(char));
		if (!br_buf[i] || !dpid_buf[i])
			return ENOMEM;
	}

	if ((f = popen(cmd_str, "r")) == NULL)
		return -1;

	pos = 0;
	ccur = 0;
	c = fgetc(f);
	while (!feof(f)) {
		if (isgraph(c)) {
			br_buf[pos][ccur++] = c;
		} else if (c == '\n') {
			br_buf[pos++][ccur] = '\0';
			ccur = 0;
		} else if (feof(f)) {
			break;
		}
		c = fgetc(f);
	}
	pclose(f);

	br_buf[pos][ccur] = '\0';

	for (pos = 0; pos < cnt; pos++) {
		ret = ovs_shell_get_datapath_id(br_buf[pos], dpid_buf[pos]);
		if (ret)
			goto error;
	}

	*n = cnt;
	*br_list = br_buf;
	*dpid_list = dpid_buf;
	return 0;

error:
	pclose(f);
	free(br_buf);
	*br_list = NULL;
	*dpid_list = NULL;
	*n = 0;
	return ret;
}


int
ovs_shell_br_to_vlan(char *bridge)
{
	char buf[5];

	if (!ovs_shell_br_exists(bridge))
		return -1;

	if (_ovs_shell_get_output(ovs_cmd(CMD_BR_TO_VLAN), bridge, buf, 5))
		return -1;

	return atoi(buf);
}

size_t
ovs_shell_br_to_parent(char *br, char *buf, size_t n)
{
	char out[64];
	int ret;

	if (!ovs_shell_br_exists(br))
		return 0;

	ret = _ovs_shell_get_output(ovs_cmd(CMD_BR_TO_PARENT), br, out, 64);
	if (ret)
		return 0;

	sanitize(out);
	strncpy(buf, out, n);
	return strnlen(out, 64);
}

int
ovs_shell_create_bridge(struct ovs_config *cfg)
{
	bool fake_br = false;
	size_t nargs = 2;	/* program name and terminating NULL */
	size_t cur;

	/* 7 arguments:
	 * add-br
	 * --may-exist
	 * br-name
	 * separator
	 * set-fail-mode
	 * bridge
	 * fail-mode */
	nargs += 7;

	/* in case of fake bridge, check args */
	if (cfg->parent && (cfg->vlan_tag >= 0)) {

		/* check 802.1q compliance */
		if (cfg->vlan_tag > 0 &&
		((cfg->vlan_tag & VLAN_TAG_MASK) == 0xfff))
			return OVSD_EINVALID_VLAN;

		/* check if parent bridge exists */
		if (!ovs_shell_br_exists(cfg->parent))
			return OVSD_ENOPARENT;

		nargs += 2;
		fake_br = true;
	}

	/* 1: atomic cmd separator, 2: set-controller cmd,
	 * 3: bridge, 4...: controllers */
	if (!fake_br && cfg->ofcontrollers)
		nargs += 3 + cfg->n_ofcontrollers;

	/* SSL options: 5 or 6 options
	 * separator
	 * (--bootstrap)
	 * set-ssl
	 * private key
	 * cert
	 * CA cert */
	if (cfg->ssl.privkey_file) {
		if (cfg->ssl.bootstrap)
			nargs += 6;
		else
			nargs += 5;
	}

	/* 1: atomic cmd separator
	 * 2: set
	 * 3: bridge
	 * 4: bridge name
	 * 5: protocols= */
	if (cfg->ofproto)
		nargs += 5;

	/* build argv for ovs-vsctl */
	char *argv[nargs];

	cur = 0;

	/* program name */
	argv[cur++] = OVS_VSCTL;

	/* create bridge command with --may-exist */
	argv[cur++] = ovs_cmd(OPT_MAY_EXIST);
	argv[cur++] = ovs_cmd(CMD_CREATE_BR);

	/* bridge name */
	argv[cur++] = cfg->name;

	/* fake bridge parameters */
	if (fake_br) {
		argv[cur++] = cfg->parent;
		argv[cur] = alloca(6 * sizeof(char));
		sprintf(argv[cur++], "%hu",
			(uint16_t) cfg->vlan_tag);
	} else if (cfg->ofcontrollers) {
		argv[cur++] = ovs_cmd(ATOMIC_CMD_SEPARATOR);
		argv[cur++] = ovs_cmd(CMD_SET_OFCTL);
		argv[cur++] = cfg->name;
		for (int i = 0; i < cfg->n_ofcontrollers; i++)
			argv[cur++] = cfg->ofcontrollers[i];
	}

	/* fail mode in case of OF controller unavailability */
	if (cfg->fail_mode == OVS_FAIL_MODE_STANDALONE) {
		argv[cur++] = ovs_cmd(ATOMIC_CMD_SEPARATOR);
		argv[cur++] = ovs_cmd(CMD_SET_FAIL_MODE);
		argv[cur++] = cfg->name;
		argv[cur++] = "standalone";
	} else {
		argv[cur++] = ovs_cmd(ATOMIC_CMD_SEPARATOR);
		argv[cur++] = ovs_cmd(CMD_SET_FAIL_MODE);
		argv[cur++] = cfg->name;
		argv[cur++] = "secure";
	}

	/* SSL options */
	if (cfg->ssl.privkey_file) {
		argv[cur++] = ovs_cmd(ATOMIC_CMD_SEPARATOR);
		if (cfg->ssl.bootstrap)
			argv[cur++] = ovs_cmd(OPT_SSL_BOOTSTRAP);
		argv[cur++] = ovs_cmd(CMD_SET_SSL);
		argv[cur++] = cfg->ssl.privkey_file;
		argv[cur++] = cfg->ssl.cert_file;
		argv[cur++] = cfg->ssl.cacert_file;
	}

	/* OpenFlow protocol version */
	if (cfg->ofproto) {
		argv[cur++] = ovs_cmd(ATOMIC_CMD_SEPARATOR);
		argv[cur++] = ovs_cmd(CMD_SET_TBL);
		argv[cur++] = "bridge";
		argv[cur++] = cfg->name;
		argv[cur++] = cfg->ofproto;
	}

	argv[cur] = NULL;

	return ovs_vsctl(argv);
}

int
ovs_shell_reload_bridge(const struct ovs_config *cfg)
{
	if (!ovs_shell_br_exists(cfg->name))
		return OVSD_ENOEXIST;

	size_t n_args = 2; /* program name and terminating NULL */

	/* '-- set-fail-mode BRIDGE MODE' */
	n_args += 4;

	/* '-- set-controller BRIDGE CTL_1 ... CTL_n' */
	if (cfg->n_ofcontrollers)
		n_args += 3 + cfg->n_ofcontrollers;

	/* '-- set-ssl PRIVKEY CERT CACERT' */
	if (cfg->ssl.privkey_file && cfg->ssl.cert_file && cfg->ssl.cacert_file)
		n_args += 5;

	/* '-- set bridge BRIDGE OFPROTO'*/
	if (cfg->ofproto)
		n_args += 5;

	char *argv[n_args];
	size_t arg = 0;

	argv[arg++] = OVS_VSCTL;
	argv[arg++] = ovs_cmd(ATOMIC_CMD_SEPARATOR);
	argv[arg++] = ovs_cmd(CMD_SET_FAIL_MODE);
	argv[arg++] = cfg->name;
	argv[arg++] = cfg->fail_mode == OVS_FAIL_MODE_STANDALONE ? "standalone" : "secure";

	if (cfg->n_ofcontrollers) {
		argv[arg++] = ovs_cmd(ATOMIC_CMD_SEPARATOR);
		argv[arg++] = ovs_cmd(CMD_SET_OFCTL);
		argv[arg++] = cfg->name;
		for (size_t i = 0; i < cfg->n_ofcontrollers; i++)
			argv[arg++] = cfg->ofcontrollers[i];
	}

	if (cfg->ssl.privkey_file) {
		argv[arg++] = ovs_cmd(ATOMIC_CMD_SEPARATOR);
		argv[arg++] = ovs_cmd(CMD_SET_SSL);
		argv[arg++] = cfg->ssl.privkey_file;
		argv[arg++] = cfg->ssl.cert_file;
		argv[arg++] = cfg->ssl.cacert_file;
	}

	if (cfg->ofproto) {
		argv[arg++] = ovs_cmd(ATOMIC_CMD_SEPARATOR);
		argv[arg++] = ovs_cmd(CMD_SET_TBL);
		argv[arg++] = ovs_table[TABLE_BRIDGE];
		argv[arg++] = cfg->name;
		argv[arg++] = cfg->ofproto;
	}

	argv[arg] = NULL;

	return ovs_vsctl(argv);
}

int
ovs_shell_delete_bridge(char *bridge)
{
	if (!ovs_shell_br_exists(bridge))
		return OVSD_ENOEXIST;

	char * const argv[5] = {
		[0] = OVS_VSCTL,
		[1] = ovs_vsctl_cmd[OPT_IF_EXISTS],
		[2] = ovs_vsctl_cmd[CMD_DEL_BR],
		[3] = bridge,
		[4] = NULL,
	};

	return ovs_vsctl(argv);
}

int
ovs_shell_add_port(char *bridge, char *port)
{
	if (!ovs_shell_br_exists(bridge))
		return OVSD_ENOEXIST;

	char * const argv[6] = {
		[0] = OVS_VSCTL,
		[1] = ovs_cmd(OPT_MAY_EXIST),
		[2] = ovs_cmd(CMD_ADD_PORT),
		[3] = bridge,
		[4] = port,
		[5] = NULL,
	};

	return ovs_vsctl(argv);
}

int
ovs_shell_remove_port(char *bridge, char *port)
{
	if (!ovs_shell_br_exists(bridge))
		return OVSD_ENOPARENT;

	char * const argv[6] = {
		[0] = OVS_VSCTL,
		[1] = ovs_cmd(OPT_IF_EXISTS),
		[2] = ovs_cmd(CMD_DEL_PORT),
		[3] = bridge,
		[4] = port,
		[5] = NULL
	};

	return ovs_vsctl(argv);
}
