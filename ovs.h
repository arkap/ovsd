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
#ifndef __OVSD_OVS_H
#define __OVSD_OVS_H

#include "ovsd.h"

int ovs_delete(char *bridge);
int ovs_create(struct ovswitch_br_config *cfg);
int ovs_reload(const struct ovswitch_br_config *cfg);

int ovs_add_port(char *bridge, char *port);
int ovs_remove_port(char *bridge, char *port);

int ovs_check_state(char *bridge);
int ovs_dump_info(struct blob_buf *buf, char *bridge);

int ovs_get_datapath_id(char *bridge, char *dpid);
int ovs_get_bridges(char ***br_buf, char ***dpid_buf, size_t *n);

const char* ovs_strerror(int error);

#endif
