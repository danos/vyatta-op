#!/usr/bin/perl
#
# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
#
# Copyright (c) 2015 Brocade Communications Systems, Inc.
# All rights reserved
#
# SPDX-License-Identifier: GPL-2.0-only
use strict;
use warnings;
use JSON;

my $input = join( '', <STDIN> );
my $rpc = decode_json $input;

my $cmd = "/opt/vyatta/bin/yangop-get-route";

my $family = "ipv4";
$family = $rpc->{family}
  if $rpc->{family};
$cmd .= " -6" if $family eq "ipv6";

my $dest = $rpc->{destination};
$cmd .= " -r $dest" if $dest;

exec $cmd;
