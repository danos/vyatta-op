#! /usr/bin/perl
# Wrapper around the base Linux traceroute command to provide
#  nicer API (ie no flag arguments)
#
# **** License ****
# Copyright (c) 2017,2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2014 Vyatta, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
# **** End License ****
#
# Syntax
#   traceroute [ipv4] [ipv6] [version] HOST
#           [ as-path ]
#           [ bypass-routing ]
#           [ debug-socket ]
#           [ first-ttl VALUE ]
#           [ gateway VALUE ]
#           [ icmp-echo ]
#           [ icmp-extensions ]
#           [ interface VALUE ]
#           [ interval VALUE ]
#           [ max-ttl VALUE ]
#           [ no-fragment ]
#           [ num-queries VALUE ]
#           [ port VALUE ]
#           [ seq-queries VALUE ]
#           [ source-addr VALUE ]
#           [ tcp-syn VALUE ]
#           [ tos VALUE ]
#           [ version ]
#           [ wait-time VALUE ]

use strict;
use warnings;
use NetAddr::IP;
use Data::Validate::IP qw(is_linklocal_ipv6);

# Table for translating options to arguments
my %options = (
    'icmp-echo'        => 'I',
    'tcp-syn'          => 'T',
    'debug-socket'     => 'd',
    'no-fragment'      => 'F',
    'first-ttl'        => 'f:',
    'gateway'          => 'g:',
    'interface'        => 'i:',
    'max-ttl'          => 'm:',
    'seq-queries'      => 'N:',
    'no-map'           => 'n',
    'port'             => 'p:',
    'tos'              => 't:',
    'wait-time'        => 'w:',
    'num-queries'      => 'q:',
    'bypass-routing'   => 'r',
    'source-addr'      => 's:',
    'interval'         => 'z:',
    'icmp-extensions'  => 'e',
    'as-path'          => 'A',
    'version'          => 'V',
);

my $rti;
my @new_argv;
while (scalar @ARGV) {
    $_ = shift @ARGV;
    if ($_ eq "routing-instance") {
        $rti = shift @ARGV;
        next;
    }
    push @new_argv, $_;
}

@ARGV = @new_argv;

exec "/usr/sbin/chvrf", $rti, "/opt/vyatta/bin/traceroute.pl", @ARGV
  if (defined $rti);

my $cmd     = '/usr/bin/traceroute';
my @cmdargs = ();
my $host;
my $ip6_ll = 0;

# First argument is host or ip version
while (scalar @ARGV) {
    my $first_arg = shift @ARGV;
    if ( $first_arg eq 'ipv6' ) {
        push @cmdargs, '-6';
    } elsif ( $first_arg ne 'ipv4' ) {
        $host = $first_arg;
        last;
    }
}

die "traceroute: Missing host\n"
  unless defined($host);
my $ip = new NetAddr::IP $host;
die "traceroute: Unknown host: $host\n"
  unless defined($ip);

if ( !scalar(@cmdargs) ) {
    if ( $ip->version ) {
        if ( $ip->version == 6 ) {
            push @cmdargs, '-6';
            if ( is_linklocal_ipv6($host) ) {
                $ip6_ll = 1;
            }
        } elsif ( $ip->version != 4 ) {
            die "Unknown address: $host\n";
        }
    }
}

my $int_spcfd;
my $args      = [ 'traceroute', $host, @ARGV ];
shift @$args;
shift @$args;
while ( my $arg = shift @$args ) {
    my $traceroutearg = $options{$arg};
    die "traceroute: unknown option $arg\n"
      unless $traceroutearg;

    my $flag = "-" . substr( $traceroutearg, 0, 1 );
    push @cmdargs, $flag;

    if ( rindex( $traceroutearg, ':' ) != -1 ) {
        my $optarg = shift @$args;
        die "traceroute: missing argument for $arg option\n"
          unless defined($optarg);
        if ( "i:" eq $traceroutearg ) { $int_spcfd = 1; }
        push @cmdargs, $optarg;
    }
}

if ( $ip6_ll && !$int_spcfd ) {
    print "\nSpecify outgoing interface: ";
    my $out_iface = <STDIN>;
    chomp($out_iface);
    die "traceroute: Outgoing interface not specified.\n"
      if ( $out_iface eq "" );

    push @cmdargs, "-i", $out_iface;
}

exec $cmd, @cmdargs, $host;
