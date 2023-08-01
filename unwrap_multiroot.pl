#!/usr/bin/env perl

##
## Copyright (c) 2022, 2023 William Robinet <willi@mrobi.net>
##
## Permission to use, copy, modify, and distribute this software for any
## purpose with or without fee is hereby granted, provided that the above
## copyright notice and this permission notice appear in all copies.
##
## THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
## WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
## MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
## ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
## WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
## ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
## OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
##

use strict;
use warnings;
use Carp;
use Getopt::Long;

# Path to the openssl binary
my $openssl = `which openssl`;
chomp($openssl);
####

my $ftype = 'D';

sub print_usage {
    print "Usage:\n";
    print "\t$0 [--pem|-p] <encoded_file>\n\n";
    print "Default input file format is DER, use --pem or -p option to switch to PEM\n\n";
    exit 1
}

GetOptions(
    'pem|p'   => sub { $ftype = 'P' },
) or do { print_usage };

do { print "Missing filename !\n\n"; print_usage } if (scalar @ARGV < 1);
do { print "Too many arguments !\n\n"; print_usage } if (scalar @ARGV > 1);
do { print "File does not exist !\n\n"; print_usage } if not -f "$ARGV[0]";

my $srcfile = shift;
open(my $fh, "-|", "$openssl asn1parse -inform $ftype -in '$srcfile' 2>/dev/null")
    or croak "Error opening source file !";
my $line = <$fh>;
close($fh);

my $header_length = 0;
my $length = 0;

chomp($line);
if( $line =~ /\s*0:d=0.*hl=([0-9]+)\s+l=\s*(inf|[0-9]+)/ ) {
    $header_length = int($1);
    $length = int($2);
} else {
    print STDERR "Error could not parse input line !\n";
    exit(1);
}

my $dstfile = $srcfile.".unwrapped";
system($openssl, 'asn1parse', '-in', $srcfile, '-inform', $ftype,
    '-offset', $header_length, '-length', $length, '-noout', '-out', $dstfile);
close($fh);

print "Output written to file \"$dstfile\".\n";

