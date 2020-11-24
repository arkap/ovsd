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
#ifndef __OVSD_H
#define __OVSD_H

#include <libubus.h>

enum ovsd_status {
	OVSD_OK,
	OVSD_EUNKNOWN,
	OVSD_ENOEXIST,
	OVSD_ENOPARENT,
	OVSD_EINVALID_ARG,
	OVSD_EINVALID_VLAN,
};

enum {
	L_CRIT,
	L_WARNING,
	L_NOTICE,
	L_INFO,
	L_DEBUG
};

enum ovs_fail_mode {
	OVS_FAIL_MODE_STANDALONE,
	OVS_FAIL_MODE_SECURE,
};

struct ssl_config {
	char *privkey_file;
	char *cert_file;
	char *cacert_file;
	bool bootstrap;
	char **proto;
	size_t n_proto;
	char **ciphers;
	size_t n_ciphers;
};

struct ovs_config {
	char *name;

	/* fake bridge args */
	char *parent;
	int vlan_tag;

	/* OpenFlow controller args */
	char **ofcontrollers;
	size_t n_ofcontrollers;
	enum ovs_fail_mode fail_mode;

	/* SSL config */
	struct ssl_config ssl;

	/* OpenFlow versions to use (e.g. OpenFlow10,OpenFlow13) */
	char *ofproto;
};

void ovsd_log_msg(int log_lvl, const char *format, ...);

#endif
