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
#include <stdio.h>

#include "ovs.h"
#include "ovs-shell.h"

int
ovs_create(struct ovs_config *cfg)
{
	int ret = ovs_shell_create_bridge(cfg);

	if (ret)
		fprintf(stderr, "Could not create bridge '%s': %s\n",
			cfg->name ? cfg->name : "", ovs_strerror(ret));

	return ret;
}

int
ovs_delete(char *bridge)
{
	return ovs_shell_delete_bridge(bridge);
}

int
ovs_reload(const struct ovs_config *cfg)
{
	return ovs_shell_reload_bridge(cfg);
}

int
ovs_add_port(char *bridge, char *port)
{
	int ret = ovs_shell_add_port(bridge, port);
	if (ret)
		ovsd_log_msg(L_WARNING, "'%s' failed to add port '%s': %s\n",
				bridge, port, ovs_strerror(ret));

	return ret;
}

int
ovs_remove_port(char *bridge, char *port)
{
	int ret = ovs_shell_remove_port(bridge, port);
	if (ret)
		ovsd_log_msg(L_WARNING, "'%s' failed to remove port '%s': "
			  "%s\n", bridge, port, ovs_strerror(ret));

	return ret;
}

int
ovs_check_state(char *bridge)
{
	if (!ovs_shell_br_exists(bridge))
		return OVSD_ENOEXIST;

	return 0;
}

int
ovs_dump_info(struct blob_buf *buf, char *bridge)
{
	char out[64];
	int vlan_tag;

	ovs_shell_capture_list(ovs_cmd(CMD_GET_SSL), NULL, "ssl", buf, true);

	if (!bridge)
		return 0;

	if (!ovs_shell_br_exists(bridge))
		return OVSD_ENOEXIST;

	if (ovs_shell_br_to_parent(bridge, out, 64) && strcmp(out, bridge))
		blobmsg_add_string(buf, "parent", out);


	vlan_tag = ovs_shell_br_to_vlan(bridge);
	if (vlan_tag > 0)
		blobmsg_add_u32(buf, "vlan", (uint32_t) vlan_tag);

	ovs_shell_capture_list(ovs_cmd(CMD_GET_OFCTL), bridge,
		"ofcontrollers", buf, false);
	ovs_shell_capture_string(ovs_cmd(CMD_GET_FAIL_MODE), bridge,
		"fail_mode", buf);
	ovs_shell_capture_list(ovs_cmd(CMD_LIST_PORTS), bridge, "ports",
		buf, false);

	return 0;
}

const char*
ovs_strerror(int error)
{
	switch (error) {
		case OVSD_ENOEXIST: return "does not exist";
		case OVSD_EINVALID_ARG: return "invalid argument";
		case OVSD_ENOPARENT: return "parent does not exist";
		case OVSD_EINVALID_VLAN: return "invalid VLAN tag";
		case OVSD_EUNKNOWN: /* fall-through */
		default: return "unknown error";
	}
}

int
ovs_get_datapath_id(char *bridge, char *dpid)
{
	int ret = ovs_shell_get_datapath_id(bridge, dpid);
	if (ret)
		ovsd_log_msg(L_DEBUG, "Failed to get datapath ID for %s: "
			"%s\n", bridge, ovs_strerror(ret));
	return ret;
}

int
ovs_get_bridges(char ***br_buf, char ***dpid_buf, size_t *n)
{
	int ret = ovs_shell_get_bridges(br_buf, dpid_buf, n);
	if (ret)
		ovsd_log_msg(L_DEBUG, "Failed to retrieve ovs bridges: "
			"%s\n", ovs_strerror(ret));
	return ret;
}
