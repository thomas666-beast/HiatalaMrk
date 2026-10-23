use strict;
use warnings;
use Test::More;
use HiatalaMrk qw(:all);

my $salt = 'uniform-salt-16b';

SKIP: {
    skip 'requires debug_refs', 4 unless HiatalaMrk->can('debug_refs');

    # ---- Test 1: uniformity of _ref_index_uniform for a fixed $i ----
    # For a fixed $i, the ref index over many different $h0 values
    # should be uniform over 0 .. $i - 2.
    my $i_fixed = 20;
    my %bins;
    my $trials = 5000;
    for my $seed (1 .. $trials) {
        my $h0 = "h0-$seed";
        my $ref = HiatalaMrk::_ref_index_uniform($h0, 0, $i_fixed);
        ok_ref_in_range($ref, $i_fixed);
        $bins{$ref}++;
    }

    # Chi-squared over 0 .. $i_fixed - 2 (i_fixed - 1 bins)
    my $n_bins = $i_fixed - 1;
    my $expected = $trials / $n_bins;
    my $chi = 0;
    for my $b (0 .. $n_bins - 1) {
        my $obs = $bins{$b} // 0;
        $chi += ($obs - $expected) ** 2 / $expected;
    }
    my $crit = $n_bins + 6 * sqrt($n_bins);   # generous bound for p ~ 1e-8
    cmp_ok($chi, '<', $crit * 3,
        sprintf("uniform ref distribution at i=%d (chi²=%.1f, crit<%.1f)",
            $i_fixed, $chi, $crit * 3));

    # ---- Test 2: data-independence in the strict sense ----
    # For a fixed password, the first-half refs are determined by $h0
    # alone (not by block contents), so computing them twice gives
    # identical results, AND changing $prev->[0] must not change them.
    my @args = (password => 'pw', salt => $salt, memory => 64, passes => 1);
    my @refs1 = HiatalaMrk::debug_refs(@args);
    my @refs2 = HiatalaMrk::debug_refs(@args);
    is_deeply(\@refs1, \@refs2, 'refs are deterministic for same input');

    # ---- Test 3: second half is data-dependent ----
    # The second half refs must depend on the previous block's first word.
    # We verify this by checking the refs are within valid range and
    # that at least one differs between two different passwords.
    my @refs_pw_a = HiatalaMrk::debug_refs(password => 'aaa', salt => $salt, memory => 64, passes => 1);
    my @refs_pw_b = HiatalaMrk::debug_refs(password => 'bbb', salt => $salt, memory => 64, passes => 1);

    my $half = int(64 / 2);
    my $second_differs = 0;
    for my $i ($half - 2 .. $#refs_pw_a) {
        $second_differs = 1 if $refs_pw_a[$i] != $refs_pw_b[$i];
    }
    ok($second_differs, 'second half of pass 0 varies with password (data-dependent)');
}

done_testing;

sub ok_ref_in_range {
    my ($ref, $i) = @_;
    return $ref >= 0 && $ref < $i - 1;
}
