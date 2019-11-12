#!/usr/bin/perl

# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
#
# Copyright (c) 2015 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings 'all';

use File::Basename;
use File::Slurp qw( read_file);
use Cwd 'abs_path';
use Test::More 'no_plan';

# instead of uses
eval read_file(abs_path(dirname(__FILE__)) .
               '/../scripts/vyatta-show-version');


my $version = '4.0R1';

ok(match_project_id_version('VR5600:4.0:R1', '4.0R1'),
   'project id matches');

ok(!match_project_id_version('VR5600:4.0:R0', '4.0R1'),
   'project id does not match');

my %res = parse_key_values();
ok(!%res, 'parse_key_value: empty');
%res = parse_key_values('key=value');
ok($res{key}, 'parse_key_value: single');
my @testlines = qw(key1=value key2="another");
%res = parse_key_values(@testlines);
is(keys %res, 2, 'parse_key_value: multiple');
is($res{key2}, 'another', 'parse_key_value: multiple value');

print_os_release( );

my %testdata = (
    NAME => 'Brocade Vyatta Network OS',
    BUILD_ID => '20151105T1138',
    VYATTA_PROJECT_ID => 'VSE:master',
);

print_os_release( %testdata );

%testdata = (
    NAME => 'Brocade Vyatta Network OS',
    BUILD_ID => '20151105T1138',
    VYATTA_PROJECT_ID => 'VR5600:4.0:R1',
    VERSION_ID => '4.0R1',
    VERSION => '4.0 R1',
    PRETTY_NAME => 'Brocade vRouter 5600',
);

print_os_release( %testdata );


BEGIN {
  *CORE::GLOBAL::readpipe = \&mock_readpipe
};

my @mock_retval;

sub mock_readpipe {
  wantarray ? @mock_retval : join("\n", @mock_retval);
}

is(get_build_type(), '', 'get_build_type: empty');

@mock_retval = ( "ii  vyatta-ent1-runtime60" );
is(get_build_type(), 'A', 'get_build_type: A');

@mock_retval = ( "ii  vyatta-ent1-runtime60-hard" );
is(get_build_type(), 'B', 'get_build_type: B');

@mock_retval = ( "ii  vyatta-ent1-runtime60 0.25+0+gb69799c+50.1              amd64        Various utilities",
                 "ii  vyatta-ent1-runtime60-hard  0.0.14+1+g80328e5+39.1            all          Used for provisioning using vmware tools." );
is(get_build_type(), 'B', 'get_build_type: B');
