#!/usr/bin/perl

use strict;
use warnings;
use Data::Dump qw/dump/;
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

my $header_length = 0;
my $length = 0;
my $line = <$fh>;
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
