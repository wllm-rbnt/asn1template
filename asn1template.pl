#!/usr/bin/perl

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
my $error_detected = 0;

sub print_usage {
    print "Usage:\n";
    print "\t$0 [--pem|-p] <encoded_file>\n\n";
    print "Default input file format is DER, use --pem or -p option to switch to PEM\n\n";
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
            $error_detected = 1;
            next;
        }

        if($length == "Inf") {
            print STDERR "Indefinite length encoding detected at line #${line_number}\n";
            $error_detected = 2;
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
                        $data = $data =~ /^00(.*)/ ? $1 : $data;
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
my ($seqid, $seqlabel);
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
            push @{$queue}, "$seqid\@$seqlabel";
        } else {
            $i++;
            $fieldid++;
            $class = ${$ptr_display}[$i];
            $i++;
            $fieldlabel = ${$ptr_display}[$i];

            if($class eq 'cons') {
                my $stype = ($item =~ /^SE([QT])/) ? lc($1) : "q";
                push @{$stype_stack}, $stype ;
                $seqid++;
                $seqlabel = ${$ptr_display}[$i];

                $item = "IMPLICIT:$2".uc($1).",SEQUENCE" if $item =~ /^([capu])[ontplriv]+\s+([0-9]+)/;

                if($seqid == 1) {
                    print "asn1 = $item:seq$seqid\@$seqlabel\n";
                } else {
                    print "field$fieldid\@$fieldlabel = $item:se".$stype."$seqid\@$seqlabel\n";
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
    $seqid = 0;
    dump_template();
    return
}

my $asn1 = [];
${$asn1}[0] = $asn1;

GetOptions(
    'pem|p'   => sub { $ftype = 'P' },
) or do { print_usage };

do { print "Missing filename !\n\n"; print_usage } if (scalar @ARGV < 1);
do { print "Too many arguments !\n\n"; print_usage } if (scalar @ARGV > 1);
do { print "File does not exist !\n\n"; print_usage } if not -f "$ARGV[0]";

parse_file($ARGV[0], $asn1);
#dump($asn1);
dump_template_wrapper($asn1);

exit $error_detected ;

