#!/usr/bin/perl
#
# Module: vyatta-tshark.pl
#
# **** License ****
#
# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
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

my $TSHARK = "/usr/bin/tshark";

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

my ( $detail, $filter, $intf, $unlimited, $save, $files, $size );
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
# main
#

my $result = GetOptions(
    "detail!"    => \$detail,
    "filter=s"   => \$filter,
    "save=s"     => \$save,
    "intf=s"     => \$intf,
    "count=s"    => \$count,
    "unlimited!" => \$unlimited,
    "files=i"    => \$files,
    "size=s"     => \&parse_size
);

if ( !$result ) {
    print "Invalid option specifications\n";
    exit 1;
}

die "No interface specified!\n"
  unless defined($intf);

check_if_interface_is_tsharkable($intf);

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
}
else {
    push @args, '-c', $count
      unless $unlimited;
}

push @args, '-V' 	       if $detail;
push @args, '-f', $filter      if defined($filter);

exec { $TSHARK } @args
  or die "Can't exec $TSHARK";
