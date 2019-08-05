#! /usr/bin/perl

# Data format is RFC3447, part A.1.2
@fields = ('N','E','D','P','Q','DP','DQ','QP');

$count = 0;
while (<>) {
	next unless /prim:\s*INTEGER\s*:([0-9A-F]+)/;
	$count++;
	next if $count < 2;
	print "$fields[$count-2] = $1\n";
}
