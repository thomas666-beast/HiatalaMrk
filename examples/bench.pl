#!/usr/bin/env perl
use strict;
use warnings;
use Time::HiRes qw(time);
use HiatalaMrk qw(:all);

print "Backend: ", backend(), "\n\n";

my @cases = (
    [   512, 3 ], [  1024, 3 ], [  2048, 3 ], [  4096, 3 ],
    [  8192, 3 ], [ 16384, 3 ],
);

printf "%-8s %-6s %-12s %-12s %-10s\n",
    'memory', 'passes', 'pure (s)', 'xs (s)', 'speedup';
printf "%s\n", '-' x 54;

for my $case (@cases) {
    my ($m, $t) = @$case;
    my %args = (
        password => 'bench', salt => 'benchmark-salt-16',
        memory => $m, passes => $t,
    );

    my $t0 = time;
    hiatala_mrk_raw_pureperl(%args);
    my $pure = time - $t0;

    my $xs;
    if (backend() eq 'xs') {
        my $t1 = time;
        hiatala_mrk_raw_xs(%args);
        $xs = time - $t1;
    }

    printf "%-8d %-6d %-12.4f %-12s %-10s\n",
        $m, $t, $pure,
        defined $xs ? sprintf('%.4f', $xs) : 'n/a',
        defined $xs ? sprintf('%.1fx', $pure / $xs) : 'n/a';
}
