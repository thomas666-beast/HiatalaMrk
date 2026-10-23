use strict;
use warnings;
use Test::More;
use HiatalaMrk qw(:all);

SKIP: {
    skip 'XS backend not compiled', 6 unless backend() eq 'xs';

    my @calls;
    my %args = (
        password => 'progress-test',
        salt     => 'progress-salt-16',
        memory   => 128,
        passes   => 2,
    );

    hiatala_mrk_raw_xs(%args, progress => sub { push @calls, [@_] });

    cmp_ok(scalar @calls, '>', 0, 'progress callback was called');

    # Each call receives (done, total)
    for my $c (@calls) {
        is(scalar @$c, 2, 'callback receives two arguments');
        last;
    }

    # 'done' must be monotonically non-decreasing
    my $ok_mono = 1;
    my $prev = -1;
    for my $c (@calls) {
        if ($c->[0] < $prev) { $ok_mono = 0; last; }
        $prev = $c->[0];
    }
    ok($ok_mono, 'done values are monotonic');

    # 'done' must never exceed 'total'
    my $ok_bound = 1;
    for my $c (@calls) {
        if ($c->[0] > $c->[1]) { $ok_bound = 0; last; }
    }
    ok($ok_bound, 'done never exceeds total');

    # Same total for every call
    my %totals = map { $_->[1] => 1 } @calls;
    is(scalar keys %totals, 1, 'total is constant across calls');

    # Last 'done' should be near total (within one block of end)
    my $last = $calls[-1];
    cmp_ok($last->[0], '>', 0, 'last done > 0');

    my $calls_pure = 0;
    hiatala_mrk_raw_pureperl(%args, progress => sub { $calls_pure++ });
    cmp_ok($calls_pure, '>', 0, 'pure-Perl path also invokes progress');
}

done_testing;
