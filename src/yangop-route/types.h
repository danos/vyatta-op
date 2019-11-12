/* Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef TYPES_H_
#define TYPES_H_

#include <stdio.h>
#include <netinet/in.h>
#include <jansson.h>
#include "list.h"

struct path {
	struct list path;
	struct in6_addr nexthop;
	int af;
	unsigned int ifidx;
	unsigned int flags;
};

#define PATHF_NEXTHOP (1U<<0)
#define PATHF_IFIDX   (1U<<1)

struct route {
	struct list paths;
	struct in6_addr dest;
	unsigned int pfxlen;
	struct in6_addr src;
	unsigned int srclen;
	int af;
};


struct route *route_create(void);
void route_destroy(void *);
json_t *route_json(const struct route *r, const char *ns);

struct path *path_create(void);
void path_destroy(void *);

#endif
