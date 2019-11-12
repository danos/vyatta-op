#!/usr/bin/perl
#
# Copyright (c) 2017,2019, AT&T Intellectual Property. All rights reserved.
#
# Copyright (c) 2014-2016 Brocade Communications Systems, Inc.
# All rights reserved
#
# SPDX-License-Identifier: GPL-2.0-only

use strict;
use warnings;
use IPC::Cmd qw[run];
use JSON;

my $input = join( '', <STDIN> );
my $rpc = decode_json $input;

my $cmd = "/opt/vyatta/bin/ping $rpc->{host}";
while ( my ( $key, $value ) = each %{$rpc} ) {
    $cmd .= " $key $value" unless $key =~ /^(-|host)/;
}
$cmd .= " quiet";    # Always run in quiet mode

my %out;
my ( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf ) =
  run( command => $cmd, verbose => 0 );
my @result = split( /\n/, join( "", @$stdout_buf ) );
foreach my $line (@result) {
    if ( $line =~ /^(\d+)\s+packets\s+transmitted,\s+(\d+)\s+received/ ) {
        $out{"tx-packet-count"} = int($1);
        $out{"rx-packet-count"} = int($2);
    } elsif ( $line =~
        /^rtt min\/avg\/max\/mdev = ([0-9.]+)\/([0-9.]+)\/([0-9.]+)\/[0-9.]+ ms/
      )
    {
        # Units are milliseconds.  We don't display sub-ms times as that
		# either requires changing the YANG units, or the type, and neither
		# is really allowed.  'ping' is a basic diagnostic - if times are
		# that small, everything is working pretty well ...
        $out{"min-delay"}     = int($1);
        $out{"average-delay"} = int($2);
        $out{"max-delay"}     = int($3);
    }
}

if ( !@result ) {
    $out{"tx-packet-count"} = $rpc->{count};
    $out{"rx-packet-count"} = 0;
}

print encode_json( \%out );
