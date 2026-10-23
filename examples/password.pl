#!/usr/bin/env perl
use strict;
use warnings;
use Time::HiRes qw(time);
use HiatalaMrk qw(:all);
use Crypt::Argon2 qw(argon2id_pass argon2_verify);

# ---------------------------------------------------------------------------
# 1. Progress-aware hashing (TTY only, silent otherwise)
# ---------------------------------------------------------------------------
sub hash_with_progress {
    my ($cfg) = @_;
    my $m     = $cfg->{memory} // 2048;
    my $t     = $cfg->{passes} // 3;
    my $total = $m * $t;

    my $is_tty = -t STDERR;
    my $last   = 0;
    my $bar    = sub {
        my ($done) = @_;
        return unless $is_tty;
        my $pct = int(100 * $done / $total);
        return if $pct == $last;
        $last = $pct;
        printf STDERR "\r[%-20s] %3d%%", '#' x int($pct / 5), $pct;
    };

    my $enc = hiatala_mrk_hash({
        %$cfg,
        progress => sub { $bar->($_[0]) },
    });
    print STDERR "\r", " " x 30, "\r" if $is_tty;
    return $enc;
}

# ---------------------------------------------------------------------------
# 2. Auto-tune memory so a hash takes ~target seconds
# ---------------------------------------------------------------------------
sub tune_config {
    my (%opt) = @_;
    my $target = $opt{target_seconds} // 0.8;
    my $passes = $opt{passes}         // 3;
    my $outlen = $opt{outlen}         // 32;
    my $salt   = 'tune-benchmark-16';

    my $m = 512;
    while ($m <= 65536) {
        my $t0 = time;
        hiatala_mrk_raw(
            password => 'benchmark', salt => $salt,
            memory   => $m, passes => $passes, outlen => $outlen,
        );
        my $dt = time - $t0;
        last if $dt >= $target;
        $m *= 2;
    }
    return { memory => $m, passes => $passes, outlen => $outlen };
}

# ---------------------------------------------------------------------------
# 3. Production path: Argon2 (C implementation, fast, audited)
# ---------------------------------------------------------------------------
sub argon2_hash {
    my ($password, %opt) = @_;
    my $m    = $opt{memory} // 65536;   # KiB
    my $t    = $opt{passes} // 3;
    my $salt = $opt{salt} // do {
        require Crypt::PRNG;
        Crypt::PRNG::random_bytes(16);
    };
    return argon2id_pass($password, $salt, $t, $m, 1, 32);
}

sub argon2_check {
    my ($encoded, $password) = @_;
    return argon2_verify($encoded, $password) ? 1 : 0;
}

# ---------------------------------------------------------------------------
# 4. Demo
# ---------------------------------------------------------------------------
my $pw = 'correct horse battery staple';

printf "Backend: %s\n\n", backend();

print "=== Auto-tune (target 0.8s) ===\n";
my $tuned = tune_config(target_seconds => 0.8);
printf "Tuned: m=%d KiB, t=%d\n\n", $tuned->{memory}, $tuned->{passes};

print "=== HiatalaMrk with progress ===\n";
printf "Password (plain): %s\n", $pw;
printf "Password length:  %d bytes\n", length($pw);
my $t0  = time;
my $enc = hash_with_progress({ password => $pw, %$tuned });
printf "Took:             %.2fs\n", time - $t0;
printf "Hash (encoded):   %s\n", $enc;
printf "Hash length:      %d chars\n", length($enc);
printf "Verify:           %s\n\n", hiatala_mrk_verify($enc, $pw) ? "ok" : "FAIL";

print "=== Argon2 (production path) ===\n";
printf "Password (plain): %s\n", $pw;
printf "Password length:  %d bytes\n", length($pw);
my $t1 = time;
my $a  = argon2_hash($pw);
printf "Took:             %.3fs\n", time - $t1;
printf "Hash (encoded):   %s\n", $a;
printf "Hash length:      %d chars\n", length($a);
printf "Verify:           %s\n", argon2_check($a, $pw)     ? "ok" : "FAIL";
printf "Reject:           %s\n", argon2_check($a, 'wrong') ? "FAIL" : "ok";
