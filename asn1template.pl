#!/usr/bin/perl

use strict;
use warnings;
use Data::Dump qw/dump/;
use File::Temp qw/:POSIX/;

my $derfile;

sub test_format($) {
    my $srcfile = shift;
    my $tmp_filename = tmpnam();
    if(system("openssl asn1parse -in $srcfile -inform PEM -out $tmp_filename >/dev/null 2>&1")) {
        unlink $tmp_filename;
        $derfile = $srcfile;
    } else {
        $derfile = $tmp_filename;
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

    open(SRCDER, "openssl asn1parse -inform DER -in $srcfile |") or die 'Open failed !';
    while(<SRCDER>) {
        chomp;
        $prev_indent_level = $indent_level;
        if( /\s*([0-9]+):d=([0-9]+).*hl=([0-9]+)\s+l=\s*([0-9]+)\s+[a-z]+:\s*(cont|appl|priv)\s*\[\s*([0-9]*)\s*\]\s*/ ) {
            $offset = int($1);
            $indent_level = int($2);
            $header_length = int($3);
            $length = int($4);
            $type = $5." ".$6;
        } elsif( /\s*([0-9]+):d=([0-9]+).*hl=([0-9]+)\s+l=\s*([0-9]+)\s+[a-z]+:\s*(appl)\s*\[\s*([0-9]*)\s*\]\s*/ ) {
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
            print "Error could not parse input line !\n";
            print "\t".$_."\n";
            next;
        }

        for(my $i = 0; $i < $prev_indent_level - $indent_level; $i++) {
            $ptr = ${$ptr}[0];
        }
    
        if($type eq 'SEQUENCE' or $type eq 'SET' or $type =~ /^cont/ or $type =~ /^appl/ or $type =~ /^priv/) {
            my $array_ref = [$ptr];
            push(@{$ptr}, $type);
            push(@{$ptr}, $array_ref);
            $ptr = $array_ref;
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
                $type eq 'IA5STRING') {

            push(@{$ptr}, $type);
            if($type eq 'BIT STRING') {
                my $tmp_filename = tmpnam();
                system 'openssl', 'asn1parse', '-in', $srcfile, '-inform', 'DER', '-offset', $offset + $header_length, '-length', $length, '-noout', '-out', $tmp_filename;
                open(FD, "od -t x1 $tmp_filename | cut -d ' ' -s -f 2- | tr -d '\n' | sed -e 's/ //g' | tr a-z A-Z |");
                $data = <FD>;
                $data = $data =~ /^00(.*)/ ? $1 : $data;
                close(FD);
                unlink $tmp_filename;
            } elsif ($type eq 'UTF8STRING') {
                my $tmp_filename = tmpnam();
                system 'openssl', 'asn1parse', '-in', $srcfile, '-inform', 'DER', '-offset', $offset + $header_length, '-length', $length, '-noout', '-out', $tmp_filename;
                open(FD, $tmp_filename);
                $data = <FD>;
                close(FD);
                unlink $tmp_filename;
            }
            push(@{$ptr}, $data) if $type ne 'NULL';
        }
    }
    close(SRCDER);
}

# Display only vars
my $indent_level_display;
my $ptr_display;
my $fieldid;
my $seqid;
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
            my $item =${$ptr_display}[$i];
            if(ref $item eq 'ARRAY') {
                push(@{$queue}, $item);
                push(@{$queue}, $seqid);
            } else {
                $fieldid++;
    
                if($item =~ /^SE[QT]|^cont|^appl|^priv/) {
                    $seqid++;
    
                    $item = "IMPLICIT:$2".uc($1).",SEQUENCE" if $item =~ /^([cap])[ontpplriv]+\s+([0-9]+)/;
    
                    if($fieldid == 1) {
                        print "asn1 = $item:seq$seqid\n";
                    } else {
                        print "field$fieldid = $item:seq$seqid\n";
                    }
                } else {
                    $i++;
    
                    if($item eq 'NULL') {
                        print "field$fieldid = $item\n";
                    } elsif ($item eq 'OCTET STRING') {
                        ${$ptr_display}[$i] =~ /\:([A-F0-9]+)/;
                        print "field$fieldid = FORMAT:HEX,"."OCTETSTRING:$1\n";
                    } elsif ($item eq 'INTEGER') {
                        ${$ptr_display}[$i] =~ /^([A-F0-9]+)/;
                        print "field$fieldid = $item:0x$1\n";
                    } elsif ($item eq 'BOOLEAN') {
                        if(${$ptr_display}[$i] =~ /255/) {
                            print "field$fieldid = $item:true\n";
                        } else {
                            print "field$fieldid = $item:false\n";
                        }
                    } elsif ($item eq 'BIT STRING') {
                        print "field$fieldid = FORMAT:HEX,"."BITSTRING:${$ptr_display}[$i]\n";
                    } elsif ($item eq 'UTF8STRING') {
                        print "field$fieldid = FORMAT:UTF8,"."UTF8String:\"${$ptr_display}[$i]\"\n";
                    } elsif ($item eq 'PRINTABLESTRING' or $item eq 'T61STRING') {
                        print "field$fieldid = $item:\"${$ptr_display}[$i]\"\n";
                    } else {
                        print "field$fieldid = $item:${$ptr_display}[$i]\n";
                    }
                }
            }
        }
        while (scalar @{$queue} > 0) {
            $ptr_display = shift((@{$queue}));
            my $tmpseqid = shift((@{$queue}));
            print "[seq$tmpseqid]\n";
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

test_format($ARGV[0]);
parse_file($derfile, $asn1);
#dump($asn1);
dump_template_wrapper($asn1);

