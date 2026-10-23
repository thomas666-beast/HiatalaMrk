use strict;
use warnings;
use Test::More;
use Time::HiRes qw(time);
use HiatalaMrk qw(:all);

diag "backend: " . backend();

SKIP: {
    skip 'XS backend not compiled', 7 unless backend() eq 'xs';

    my %args = (
        password => 'parity-test',
        salt     => 'somesalt-16bytes!',
        memory   => 64,
        passes   => 2,
    );

    my $pure = hiatala_mrk_raw_pureperl(%args);
    my $xs   = hiatala_mrk_raw_xs(%args);
    is($xs, $pure, 'XS output matches pure Perl (v=3)');

    my %args_legacy = (%args, alg_id => 6);
    my $pure_legacy = hiatala_mrk_raw_pureperl(%args_legacy);
    my $xs_legacy   = hiatala_mrk_raw_xs(%args_legacy);
    is($xs_legacy, $pure_legacy, 'XS matches pure Perl (legacy a=6)');

    my $calls = 0;
    hiatala_mrk_raw_xs(%args, progress => sub { $calls++ });
    cmp_ok($calls, '>', 0, 'progress callback fired');

    my $t0 = time;
    hiatala_mrk_raw_xs(%args);
    my $dt_xs = time - $t0;

    my $t1 = time;
    hiatala_mrk_raw_pureperl(%args);
    my $dt_pure = time - $t1;

    note sprintf("pure=%.4fs  xs=%.4fs  speedup=%.1fx",
        $dt_pure, $dt_xs, $dt_pure / ($dt_xs || 1e-9));

    cmp_ok($dt_xs, '<', $dt_pure,     'XS is faster');
    cmp_ok($dt_xs, '<', $dt_pure / 2, 'XS is at least 2x faster');

    my $enc = hiatala_mrk_hash(%args);
    ok(hiatala_mrk_verify($enc, $args{password}), 'verify works via XS path');
    like($enc, qr/\$v=3\$a=7\$/, 'encoded form is v=3, a=7');
}

done_testing;
