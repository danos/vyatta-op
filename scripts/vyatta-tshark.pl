#!/usr/bin/perl
#
# Module: vyatta-tshark.pl
#
# **** License ****
#
# Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
#
# Copyright (c) 2014-2015 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2011-2013 Vyatta, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Author: John Southworth
# Date: Sept. 2011
# Description: run tshark on a given interface with options
#
# **** End License ****
#

use strict;
use warnings;
use Getopt::Long;
use Data::Dumper qw(Dumper);
use JSON qw(decode_json);

use lib "/opt/vyatta/share/perl5/";
use Vyatta::Dataplane;

my $TSHARK = "/usr/bin/tshark";
my $DEBUG  = 0;

sub check_if_interface_is_tsharkable {
    my $interface = shift;

    open( my $tshark, '-|', "$TSHARK -D 2>&1" )
      or die "tshark failed: $!\n";

    while (<$tshark>) {
        chomp;
        return 1 if /^\d+\. $interface$/;
    }
    close $tshark;
    die "Unable to capture traffic on $interface\n";
}

my (
    $detail, $filter, $intf,   $unlimited, $save,
    $files,  $size,   $swonly, $snaplen,   $bandwidth
);
my $count = 1000;

#
# The size parameter can have one of the following
# unit suffixes:
#
# - [kK] KiB (1024 bytes)
# - [mM] MiB (1048576 bytes)
# - [gG] GiB (1073741824 bytes)
# - [tT] TiB (109951162778 bytes)
#
# Note: tshark's default size unit is KiB
sub parse_size {
    my ( $name, $parm ) = @_;
    my %mult = (
        'T' => 1073741824,
        't' => 1073741824,
        'G' => 1048576,
        'g' => 1048576,
        'M' => 1024,
        'm' => 1024,
        'K' => 1,
        'k' => 1
    );

    die "Invalid parameter: $name" if ( $name ne "size" );
    my ( $value, $unit ) = $parm =~ m/^([0-9]+)([kKmMgGtT])?$/;
    die "Invalid size. (e.g. 1 or 1K = 1KiB, 1M = 1MiB, 1G = 1Gib, 1T = 1TiB)\n"
        unless ($value);
    $unit = "K" unless $unit;
    $size = $value * $mult{$unit};
}

#
# When invoked to monitor a dataplane interface, the script is passed
# a "stream" of tokens corresponding to the YANG nodes. That is,
# "detail capture-size 100" rather than "--detail --capture-size 100".
#
# Process the tokens and turn them into options suitable for use by
# the main GetOptions parser.
#
sub generate_options {
    my ($argv) = @_;

    my %flagopt = (
        'detail'        => 1,
        'unlimited'     => 1,
        'software-only' => 1,
    );

    my @newargv       = ();
    my $next_is_param = 0;
    foreach my $arg (@$argv) {
        if ($next_is_param) {
            $next_is_param = 0;
        } else {
            $arg =~ s/^--//;
            $next_is_param = 1 if !$flagopt{$arg};
            $arg = '--' . $arg;
        }

        push @newargv, $arg;
    }

    return \@newargv;
}

sub capture_show {
    my ($intf) = @_;

    my ( $dpids, $dpconns ) = Vyatta::Dataplane::setup_fabric_conns();
    my $cmd = "capture show $intf";

    eval {
        my @dprsp = vplane_exec_cmd( $cmd, $dpids, $dpconns, 1 );
        foreach my $rsp (@dprsp) {
            my $json = @{$rsp}[0];
            return decode_json($json) if defined($json);
        }
        1;
    };

    return undef;
}

#
# main
#

my @ARGV = generate_options( \@ARGV );

my $result = GetOptions(
    "detail!"        => \$detail,
    "filter=s"       => \$filter,
    "save=s"         => \$save,
    "intf=s"         => \$intf,
    "count=s"        => \$count,
    "unlimited!"     => \$unlimited,
    "files=i"        => \$files,
    "size=s"         => \&parse_size,
    "software-only"  => \$swonly,
    "capture-size=i" => \$snaplen,
    "bandwidth=i"    => \$bandwidth,
);

if ( !$result ) {
    print "Invalid option specifications\n";
    exit 1;
}

die "No interface specified!\n"
  unless defined($intf);

check_if_interface_is_tsharkable($intf);

my $existing_session = capture_show($intf);

if ($DEBUG) {
    print "TSHARK existing capture session:\n" . Dumper($existing_session);
    print "TSHARK options:\n" . Dumper(@ARGV);
}

my @args = qw(tshark -n -i);
push @args, $intf;

if ( defined($save) ) {
    die "Please name your file <filename>.pcap\n"
      unless $save =~ /.*\.pcap/;

    push @args, '-w', $save;
    push @args, '-a', "filesize:$size"
      if defined($size);

    push @args, '-b', "files:$files"
      if defined($files);
} else {
    push @args, '-c', $count
      unless $unlimited;
}

if ( defined($existing_session) and
     $existing_session->{'capture'}->{'active'} ) {
    my $capture        = $existing_session->{'capture'};
    my @ignore_options = ();

    if ( defined($snaplen) && ( $snaplen != $capture->{'snaplen'} ) ) {
        push @ignore_options, "capture-size";
        $snaplen = undef;
    }

    if ( defined($swonly) && ( $swonly != $capture->{'software-only'} ) ) {
        push @ignore_options, "software-only";
        $swonly = undef;
    }

    if ( defined($bandwidth) && ( $bandwidth != $capture->{'bandwidth'} ) ) {
        push @ignore_options, "bandwidth";
        $bandwidth = undef;
    }

    print "Interface already being monitored, ignoring options: "
      . join( ",", @ignore_options ) . "\n"
      if scalar @ignore_options;
}

push @args, '-s', $snaplen if defined($snaplen);
push @args, '-V' if $detail;
push @args, '-f', $filter if defined($filter);

#
# The following are dataplane/platform specific parameters with no
# corresponding tshark facility. Use environment variables to pass the
# values through to the libpcap dataplane plugin module (and from
# there to the dataplane itself).
#
$ENV{'VYATTA_MONITOR_SWONLY'}    = $swonly    if defined($swonly);
$ENV{'VYATTA_MONITOR_BANDWIDTH'} = $bandwidth if defined($bandwidth);

exec {$TSHARK} @args
  or die "Can't exec $TSHARK";
