#!/usr/bin/env perl

##
## Copyright (c) 2022-2024 William Robinet <willi@mrobi.net>
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
################
# "apt install libdata-dump-perl"
# or "dnf install perl-Data-Dump"
#use Data::Dump qw/dump/;
use Carp;
use Encode qw/decode/;
use File::Temp qw/:POSIX/;
use Getopt::Long;

# Path to the openssl binary
my $openssl = `which openssl`;
chomp($openssl);
####

my $ftype = 'D';
my $multiroot = 0;
my $error_detected = 0;

sub print_usage {
    print "Usage:\n";
    print "\t$0 [--help|-h] [--pem|-p] [--multi-root|-m] <encoded_file>\n\n";
    print "Default input file format is DER, use --pem (or -p) option to switch to PEM\n";
    print "Use --multi-root (or -m) option to process multiple concatenated structures from a single input file\n";
    print "Use --help (or -h) to print this help message\n";
    exit 1
}

sub parse_file {
    my $srcfile = shift;
    my $ptr = shift;

    open(my $fh, "-|", "$openssl asn1parse -inform $ftype -in '$srcfile' 2>/dev/null")
        or croak "Error opening source file !";

    my $offset = 0;
    my $prev_indent_level = 0;
    my $indent_level = 0;
    my $header_length = 0;
    my $length = 0;
    my $class = '';
    my $type = '';
    my $data = '';
    my $line_number = 0;

    while(<$fh>) {
        $line_number++;
        chomp;

        if($multiroot) {
            $multiroot = 0;
            $indent_level = -1;
            my $array_ref = [$ptr];
            push @{$ptr}, 'SEQUENCE';
            push @{$ptr}, 'cons';
            push @{$ptr}, 'wrapping-seq';
            push @{$ptr}, $array_ref;
            $ptr = $array_ref;
        }

        $prev_indent_level = $indent_level;
        if( /\s*([0-9]+):d=([0-9]+).*hl=([0-9]+)\s+l=\s*(inf|[0-9]+)\s+([a-z]+):\s*(<ASN1|cont|appl|priv)\s*\[?\s*([0-9]+)\s*[\]>]\s*/ ) {
            $offset = int($1);
            $indent_level = int($2);
            $header_length = int($3);
            $length = int($4);
            $class = $5;
            $type = ($6 eq "<ASN1") ? "univ" : $6;
            $type = $type." ".$7;
        } elsif( /\s*([0-9]+):d=([0-9]+).*hl=([0-9]+)\s+l=\s*(inf|[0-9]+)\s+([a-z]+):\s*([A-Z0-9\s]*[A-Z0-9])\s*:?(.*)?/ ) {
            $offset = int($1);
            $indent_level = int($2);
            $header_length = int($3);
            $length = int($4);
            $class = $5;
            $type = $6;
            $data = $7 if defined($7);
        } else {
            print STDERR "Error could not parse input line #${line_number}!\n";
            $error_detected = 2;
            next;
        }

        if($length == "Inf") {
            print STDERR "Indefinite length encoding detected at line #${line_number}\n";
            $error_detected = 3;
        }

        for(my $i = 0; $i < $prev_indent_level - $indent_level; $i++) {
            $ptr = ${$ptr}[0];
        }

        if($class eq 'cons') {
            my $array_ref = [$ptr];
            push @{$ptr}, $type;
            push @{$ptr}, $class;
            push @{$ptr}, "$offset-$header_length-$length";
            push @{$ptr}, $array_ref;
            $ptr = $array_ref if $length > 0;
        } else {
            push @{$ptr}, $type;
            push @{$ptr}, $class;
            push @{$ptr}, "$offset-$header_length-$length";

            if($type eq 'BIT STRING' or
               $type eq 'UTF8STRING' or
               $type eq 'BMPSTRING' or
               $type =~ /^(cont|appl|priv|univ)\s+[0-9]+/) {
	            if($length > 0) {
                    my $tmp_filename = tmpnam();
                    system($openssl, 'asn1parse', '-in', $srcfile, '-inform', $ftype,
                        '-offset', $offset + $header_length, '-length', $length, '-noout', '-out', $tmp_filename);
                    open(my $tmpfh, "<", $tmp_filename)
                        or croak "Error opening tmp file!";

                    if($type eq 'BIT STRING' or $type =~ /^(cont|appl|priv|univ)\s+[0-9]+/) {
                        $data = "";
                        $data .= uc unpack "H*", $_ while(<$tmpfh>);
                        $data = $data =~ /^00(.*)/ ? $1 : $data if($type eq 'BIT STRING');
                    } elsif ($type eq 'UTF8STRING') {
                        $data = <$tmpfh>;
                    } elsif ($type eq 'BMPSTRING') {
                        $data = decode("UTF-16BE", <$tmpfh>);
                    }
                    close($tmpfh);
                    unlink $tmp_filename;
                } else {
                    $data = "";
                }
            }
            push @{$ptr}, $data if $type ne 'NULL';
        }
    }
    close($fh);
    return
}

# Display only vars
my $indent_level_display;
my $ptr_display;
my $class;
my ($fieldid, $fieldlabel);
my ($sid, $slabel);
my $stype_stack = [];
####

sub dump_template;
sub dump_template {
    my $length = scalar @{$ptr_display};
    my $queue = [];
    for(my $i = 1; $i < $length; $i++) {
        my $item = ${$ptr_display}[$i];
        if(ref $item eq 'ARRAY') {
            push @{$queue}, $item;
            push @{$queue}, "$sid\@$slabel";
        } else {
            $i++;
            $fieldid++;
            $class = ${$ptr_display}[$i];
            $i++;
            $fieldlabel = ${$ptr_display}[$i];

            if($class eq 'cons') {
                my $stype = ($item =~ /^SE([QT])/) ? lc($1) : "q";
                push @{$stype_stack}, $stype ;
                $sid++;
                $slabel = ${$ptr_display}[$i];

                $item = "IMPLICIT:$2".uc($1).",SEQUENCE" if $item =~ /^([capu])[ontplriv]+\s+([0-9]+)/;

                if($sid == 1) {
                    print "asn1 = $item:se$stype$sid\@$slabel\n";
                } else {
                    print "field$fieldid\@$fieldlabel = $item:se".$stype."$sid\@$slabel\n";
                }
            } else {
                $i++;

                if($item =~ /^([capu])[ontplriv]+\s+([0-9]+)/) {
                    my $hexfmt = (${$ptr_display}[$i] eq "") ? "" : ",FORMAT:HEX";
                    print "field$fieldid\@$fieldlabel = IMPLICIT:$2".uc($1)."$hexfmt,OCTETSTRING:${$ptr_display}[$i]\n";
                } elsif($item eq 'NULL') {
                    print "field$fieldid\@$fieldlabel = $item\n";
                } elsif ($item eq 'OCTET STRING') {
                    if(${$ptr_display}[$i] =~ /\:([A-F0-9]+)/) {
                        print "field$fieldid\@$fieldlabel = FORMAT:HEX,"."OCTETSTRING:$1\n";
                    } else {
                        print "field$fieldid\@$fieldlabel = OCTETSTRING:".${$ptr_display}[$i]."\n";
                    }
                } elsif ($item eq 'INTEGER') {
                    ${$ptr_display}[$i] =~ /^(-?[A-F0-9]+)/;
                    print "field$fieldid\@$fieldlabel = $item:0x$1\n";
                } elsif ($item eq 'BOOLEAN') {
                    if(${$ptr_display}[$i] =~ /255/) {
                        print "field$fieldid\@$fieldlabel = $item:true\n";
                    } else {
                        print "field$fieldid\@$fieldlabel = $item:false\n";
                    }
                } elsif ($item eq 'BIT STRING') {
                    print "field$fieldid\@$fieldlabel = FORMAT:HEX,"."BITSTRING:${$ptr_display}[$i]\n";
                } elsif ($item eq 'UTF8STRING') {
                    print "field$fieldid\@$fieldlabel = FORMAT:UTF8,"."UTF8String:\"".quotemeta(${$ptr_display}[$i])."\"\n";
                } elsif ($item eq 'BMPSTRING') {
                    print "field$fieldid\@$fieldlabel = FORMAT:UTF8,"."BMPSTRING:\"${$ptr_display}[$i]\"\n";
                } elsif ($item eq 'PRINTABLESTRING' or $item eq 'T61STRING' or $item eq 'IA5STRING') {
                    print "field$fieldid\@$fieldlabel = $item:\"".quotemeta(${$ptr_display}[$i])."\"\n";
                } elsif ($item eq 'EOC') {
                    print "field$fieldid\@$fieldlabel = IMPLICIT:0U,PRINTABLESTRING:\"\"\n"
                } else {
                    print "field$fieldid\@$fieldlabel = $item:${$ptr_display}[$i]\n";
                }
            }
        }
    }
    while (scalar @{$queue} > 0) {
        $ptr_display = shift((@{$queue}));
        my $tmpseqref = shift((@{$queue}));
        my $stype = pop(@{$stype_stack});
        print "[se$stype$tmpseqref]\n";
        $indent_level_display++;
        dump_template();
        $indent_level_display--;
        $ptr_display = ${$ptr_display}[0];
    }
    return
}

sub dump_template_wrapper {
    $ptr_display = shift;
    $indent_level_display = 0;
    $fieldid = 0;
    $sid = 0;
    dump_template();
    return
}

my $asn1 = [];
${$asn1}[0] = $asn1;

GetOptions(
    'help|h'   => sub { print_usage },
    'pem|p'   => sub { $ftype = 'P' },
    'multi-root|m'   => sub { $multiroot = 1 },
) or do { print_usage };

do { print "Missing filename !\n\n"; print_usage } if (scalar @ARGV < 1);
do { print "Too many arguments !\n\n"; print_usage } if (scalar @ARGV > 1);
do { print "File does not exist !\n\n"; print_usage } if not -f "$ARGV[0]";

parse_file($ARGV[0], $asn1);
#dump($asn1);
dump_template_wrapper($asn1);

exit $error_detected ;

