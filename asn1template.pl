#!/usr/bin/perl

use strict;
use warnings;
#use Data::Dump qw/dump/;
use Encode qw/decode/;
use File::Temp qw/:POSIX/;

my $derfile;
my $tmpfile = tmpnam();
my $error_detected = 0;

sub print_usage() {
	print "Usage:\n";
	print "\t$0 [DER|PEM encoded file]\n\n";
	exit(1);
}

sub test_format($) {
    my $srcfile = shift;
    $tmpfile = tmpnam();
    if(system("openssl asn1parse -in $srcfile -inform P -out $tmpfile >/dev/null 2>&1")) {
        if(system("openssl asn1parse -in $srcfile -inform D -out $tmpfile >/dev/null 2>&1")) {
            unlink $tmpfile;
            print "Error: File format not recognized !\n\n";
            print_usage();
        } else {
            $derfile = $srcfile;
        }
    } else {
        $derfile = $tmpfile;
    }
}

sub parse_file($$) {
    my $srcfile = shift;
    my $ptr = shift;

    my $offset = 0;
    my $prev_indent_level = 0;
    my $indent_level = 0;
    my $header_length = 0;
    my $length = 0;
    my $type = '';
    my $data = '';
    my $line_number = 0;

    open(SRCDER, "openssl asn1parse -inform D -in $srcfile |") or die 'Open failed !';
    while(<SRCDER>) {
        $line_number++;
        chomp;
        $prev_indent_level = $indent_level;
        if( /\s*([0-9]+):d=([0-9]+).*hl=([0-9]+)\s+l=\s*([0-9]+)\s+[a-z]+:\s*(cont|appl|priv)\s*\[\s*([0-9]*)\s*\]\s*/ ) {
            $offset = int($1);
            $indent_level = int($2);
            $header_length = int($3);
            $length = int($4);
            $type = $5." ".$6;
        } elsif( /\s*([0-9]+):d=([0-9]+).*hl=([0-9]+)\s+l=\s*([0-9]+)\s+[a-z]+:\s*([A-Z0-9\s]*[A-Z0-9])\s*:?(.*)?/ ) {
            $offset = int($1);
            $indent_level = int($2);
            $header_length = int($3);
            $length = int($4);
            $type = $5;
            $data = $6 if defined($6);
        } else {
            print STDERR "Error could not parse input line #${line_number}!\n";
            $error_detected = 1;
            next;
        }

        for(my $i = 0; $i < $prev_indent_level - $indent_level; $i++) {
            $ptr = ${$ptr}[0];
        }

        if($type eq 'SEQUENCE' or $type eq 'SET' or $type =~ /^cont|^appl|^priv/) {
            my $array_ref = [$ptr];
            push(@{$ptr}, $type);
            push(@{$ptr}, "$offset-$header_length-$length");
            push(@{$ptr}, $array_ref);
            $ptr = $array_ref if $length > 0;
        } elsif($type eq 'INTEGER' or
                $type eq 'OBJECT' or
                $type eq 'PRINTABLESTRING' or
                $type eq 'NULL' or
                $type eq 'BOOLEAN' or
                $type eq 'BIT STRING' or
                $type eq 'UTCTIME' or
                $type eq 'OCTET STRING' or
                $type eq 'T61STRING' or
                $type eq 'UTF8STRING' or
                $type eq 'IA5STRING' or
                $type eq 'BMPSTRING' or
                $type eq 'GENERALIZEDTIME') {

            push(@{$ptr}, $type);
            push(@{$ptr}, "$offset-$header_length-$length");


            if($type eq 'BIT STRING' or
               $type eq 'UTF8STRING' or
               $type eq 'BMPSTRING') {
                my $tmp_filename = tmpnam();
                system 'openssl', 'asn1parse', '-in', $srcfile, '-inform', 'D', '-offset', $offset + $header_length, '-length', $length, '-noout', '-out', $tmp_filename;
                open(FD, $tmp_filename);

                if($type eq 'BIT STRING') {
                    $data = "";
                    $data .= uc unpack "H*", $_ while(<FD>);
                    $data = $data =~ /^00(.*)/ ? $1 : $data;
                } elsif ($type eq 'UTF8STRING') {
                    $data = <FD>;
                } elsif ($type eq 'BMPSTRING') {
                    $data = decode("UTF-16BE", <FD>);
                }
                close(FD);
                unlink $tmp_filename;
            }
            push(@{$ptr}, $data) if $type ne 'NULL';
        }
    }
    close(SRCDER);
    unlink $tmpfile;
}

# Display only vars
my $indent_level_display;
my $ptr_display;
my ($fieldid, $fieldlabel);
my ($stype, $seqid, $seqlabel);
####

sub dump_template_wrapper($) {
    $ptr_display = shift;
    $indent_level_display = 0;
    $fieldid = 0;
    $seqid = 0;
    
    sub dump_template();
    sub dump_template() {
        my $length = scalar @{$ptr_display};
        my $queue = [];
        for(my $i = 1; $i < $length; $i++) {
            my $item = ${$ptr_display}[$i];
            if(ref $item eq 'ARRAY') {
                push(@{$queue}, $item);
                push(@{$queue}, "$seqid\@$seqlabel");
            } else {
                $i++;
                $fieldid++;
                $fieldlabel = ${$ptr_display}[$i];
    
                if($item =~ /^SE([QT])|^cont|^appl|^priv/) {
                    $stype = ($1) ? lc($1) : "q";
                    $seqid++;
                    $seqlabel = ${$ptr_display}[$i];
    
                    $item = "IMPLICIT:$2".uc($1).",SEQUENCE" if $item =~ /^([cap])[ontpplriv]+\s+([0-9]+)/;
    
                    if($seqid == 1) {
                        print "asn1 = $item:seq$seqid\@$seqlabel\n";
                    } else {
                        print "field$fieldid\@$fieldlabel = $item:se".$stype."$seqid\@$seqlabel\n";
                    }
                } else {
                    $i++;
    
                    if($item eq 'NULL') {
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
                    } else {
                        print "field$fieldid\@$fieldlabel = $item:${$ptr_display}[$i]\n";
                    }
                }
            }
        }
        while (scalar @{$queue} > 0) {
            $ptr_display = shift((@{$queue}));
            my $tmpseqref = shift((@{$queue}));
            print "[se$stype$tmpseqref]\n";
            $indent_level_display++;
            dump_template();
            $indent_level_display--;
            $ptr_display = ${$ptr_display}[0];
        }
    }
    dump_template();
}


my $asn1 = [];
${$asn1}[0] = $asn1;

print_usage if scalar @ARGV != 1;
print_usage if not -f $ARGV[0];

test_format($ARGV[0]);
parse_file($derfile, $asn1);
#dump($asn1);
dump_template_wrapper($asn1);

exit($error_detected);

