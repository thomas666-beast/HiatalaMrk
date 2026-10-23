#!/usr/bin/env perl
use strict;
use warnings;
use Time::HiRes qw(time);
use HiatalaMrk qw(:all);

my $pw = shift // 'correct horse battery staple';
my $m  = shift // 1024;
my $t  = shift // 3;

printf "Backend: %s\n", backend();
printf "Params:  m=%d KiB, t=%d\n", $m, $t;
printf "Password (plain): %s\n", $pw;

my $t0  = time;
my $enc = hiatala_mrk_hash(password => $pw, memory => $m, passes => $t);
printf "Took:    %.2fs\n", time - $t0;
printf "Hash:    %s\n", $enc;
print "verify right: ", hiatala_mrk_verify($enc, $pw)    ? "yes" : "no", "\n";
print "verify wrong: ", hiatala_mrk_verify($enc, "$pw!") ? "yes" : "no", "\n";
