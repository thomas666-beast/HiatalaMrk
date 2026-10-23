package HiatalaMrk;

use strict;
use warnings;

use Digest::SHA qw(sha512);
use MIME::Base64 qw(encode_base64 decode_base64);
use Exporter 'import';

our $VERSION   = '0.06';
our @EXPORT_OK = qw(
    hiatala_mrk_raw hiatala_mrk_raw_pureperl hiatala_mrk_raw_xs
    hiatala_mrk_hash hiatala_mrk_verify hiatala_mrk_verify_detail
    DEFAULT_CONFIG %HIATALA_DEFAULTS backend debug_refs
);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

use constant {
    WORDS             => 128,
    ALG_ID_CURRENT    => 7,
    ALG_ID_LEGACY     => 6,
    MIN_MEMORY        => 8,
    MIN_PASSES        => 1,
    DEF_MEMORY        => 16384,
    DEF_PASSES        => 3,
    DEF_OUTLEN        => 32,
    DEF_SALTLEN       => 16,
    MAX_MEMORY        => 2**22,
    MAX_PASSES        => 1000,
};

our %HIATALA_DEFAULTS = (
    memory  => DEF_MEMORY,
    passes  => DEF_PASSES,
    outlen  => DEF_OUTLEN,
    saltlen => DEF_SALTLEN,
    alg_id  => ALG_ID_CURRENT,
);

sub DEFAULT_CONFIG { return { %HIATALA_DEFAULTS } }

die "HiatalaMrk needs a perl with 64-bit integer support\n"
    unless length(pack('Q', 0)) == 8;

# ---------------------------------------------------------------------------
# XS backend detection
# ---------------------------------------------------------------------------
our $USE_XS = 0;
if (eval { require XSLoader; XSLoader::load('HiatalaMrk', $VERSION); 1 }) {
    $USE_XS = 1 if defined &HiatalaMrk::compress && defined &HiatalaMrk::xs_backend;
}

sub backend { $USE_XS ? 'xs' : 'pureperl' }

# ---------------------------------------------------------------------------
# Pure-Perl reference compression
# ---------------------------------------------------------------------------
{
    use integer;

    sub _rotr {
        my ($x, $n) = @_;
        return (($x >> $n) & ((1 << (64 - $n)) - 1)) | ($x << (64 - $n));
    }

    sub _gb {
        my ($v, $a, $b, $c, $d) = @_;
        $v->[$a] = $v->[$a] + $v->[$b] + 2 * ($v->[$a] & 0xFFFFFFFF) * ($v->[$b] & 0xFFFFFFFF);
        $v->[$d] = _rotr($v->[$d] ^ $v->[$a], 32);
        $v->[$c] = $v->[$c] + $v->[$d] + 2 * ($v->[$c] & 0xFFFFFFFF) * ($v->[$d] & 0xFFFFFFFF);
        $v->[$b] = _rotr($v->[$b] ^ $v->[$c], 24);
        $v->[$a] = $v->[$a] + $v->[$b] + 2 * ($v->[$a] & 0xFFFFFFFF) * ($v->[$b] & 0xFFFFFFFF);
        $v->[$d] = _rotr($v->[$d] ^ $v->[$a], 16);
        $v->[$c] = $v->[$c] + $v->[$d] + 2 * ($v->[$c] & 0xFFFFFFFF) * ($v->[$d] & 0xFFFFFFFF);
        $v->[$b] = _rotr($v->[$b] ^ $v->[$c], 63);
        return;
    }

    sub _round16 {
        my ($v) = @_;
        _gb($v, 0, 4,  8, 12);
        _gb($v, 1, 5,  9, 13);
        _gb($v, 2, 6, 10, 14);
        _gb($v, 3, 7, 11, 15);
        _gb($v, 0, 5, 10, 15);
        _gb($v, 1, 6, 11, 12);
        _gb($v, 2, 7,  8, 13);
        _gb($v, 3, 4,  9, 14);
        return;
    }

    sub _compress_pureperl {
        my ($x, $y) = @_;
        my @r = map { $x->[$_] ^ $y->[$_] } 0 .. WORDS - 1;
        my @z = @r;
        for my $g (0 .. 7) {
            my @grp = @z[ $g * 16 .. $g * 16 + 15 ];
            _round16(\@grp);
            @z[ $g * 16 .. $g * 16 + 15 ] = @grp;
        }
        for my $j (0 .. 7) {
            my @idx = map { $j + 8 * $_ } 0 .. 15;
            my @grp = @z[@idx];
            _round16(\@grp);
            @z[@idx] = @grp;
        }
        return [ map { $z[$_] ^ $r[$_] } 0 .. WORDS - 1 ];
    }
}

sub _compress {
    my ($x, $y) = @_;
    if ($USE_XS) {
        my @out;
        HiatalaMrk::compress($x, $y, \@out);
        return \@out;
    }
    return _compress_pureperl($x, $y);
}

# ---------------------------------------------------------------------------
# Byte helpers
# ---------------------------------------------------------------------------
sub _expand {
    my ($seed, $n) = @_;
    my ($out, $ctr) = ('', 0);
    $out .= sha512($seed . pack('V', $ctr++)) while length($out) < $n;
    return substr($out, 0, $n);
}

sub _b2blk { return [ unpack('Q<128', $_[0]) ] }
sub _blk2b { return pack('Q<128', @{ $_[0] }) }

sub _b64   { my $s = encode_base64($_[0], ''); $s =~ s/=+$//; return $s }
sub _unb64 { return decode_base64($_[0]) }

sub _random_bytes {
    my ($n) = @_;
    if (eval { require Crypt::PRNG; 1 }) {
        return Crypt::PRNG::random_bytes($n);
    }
    open my $fh, '<:raw', '/dev/urandom'
        or die "HiatalaMrk: no Crypt::PRNG and cannot open /dev/urandom: $!\n";
    read($fh, my $buf, $n) == $n
        or die "HiatalaMrk: short read from /dev/urandom\n";
    close $fh;
    return $buf;
}

sub _ct_equal {
    my ($a, $b) = @_;
    return 0 unless defined $a && defined $b && length($a) == length($b);
    my $diff = 0;
    $diff |= ord(substr($a, $_, 1)) ^ ord(substr($b, $_, 1)) for 0 .. length($a) - 1;
    return $diff == 0;
}

sub _check_params {
    my ($m, $t, $len) = @_;
    die "HiatalaMrk: memory must be an integer >= " . MIN_MEMORY . " KiB\n"
        unless defined $m && $m =~ /^\d+$/ && $m >= MIN_MEMORY && $m <= MAX_MEMORY;
    die "HiatalaMrk: passes must be an integer >= " . MIN_PASSES . " and <= " . MAX_PASSES . "\n"
        unless defined $t && $t =~ /^\d+$/ && $t >= MIN_PASSES && $t <= MAX_PASSES;
    die "HiatalaMrk: outlen must be between 4 and 1024 bytes\n"
        unless defined $len && $len =~ /^\d+$/ && $len >= 4 && $len <= 1024;
    return;
}

# ---------------------------------------------------------------------------
# Reference block selection
# ---------------------------------------------------------------------------
sub _ref_index_uniform {
    my ($h0, $pass, $i) = @_;
    my $j1 = unpack('V', sha512($h0 . pack('VVV', $pass, 0, $i)));
    my $j2 = unpack('V', sha512($h0 . pack('VVV', $pass, 1, $i)));
    my $j  = $j1 * 0x200000 + ($j2 & 0x1FFFFF);
    return $j % ($i - 1);
}

sub _ref_index_legacy {
    my ($h0, $pass, $i) = @_;
    my $j = unpack('V', sha512($h0 . pack('VV', $pass, $i)));
    return $j % ($i - 1);
}

# Data-dependent. In pass 0, refs must point to already-initialized blocks
# (0 .. i-1). In later passes, refs wrap freely but exclude self.
sub _ref_index_datadep {
    my ($prev, $i, $m, $pass) = @_;
    my $j = $prev->[0] & 0xFFFFFFFF;
    if ($pass == 0) {
        return $j % $i;               # 0 .. i-1, all initialized
    }
    return ($i + 1 + ($j % ($m - 2))) % $m;
}

# ---------------------------------------------------------------------------
# Core KDF
# ---------------------------------------------------------------------------
sub _raw_with_compress {
    my ($compress, $args, $alg_id) = @_;

    my $pw   = $args->{password};
    my $salt = $args->{salt};
    die "HiatalaMrk: password required\n" unless defined $pw;
    die "HiatalaMrk: salt of at least 8 bytes required\n"
        unless defined $salt && length($salt) >= 8;

    my $m   = $args->{memory} // DEF_MEMORY;
    my $t   = $args->{passes} // DEF_PASSES;
    my $len = $args->{outlen} // DEF_OUTLEN;
    _check_params($m, $t, $len);

    $alg_id //= ALG_ID_CURRENT;

    utf8::encode($pw) if utf8::is_utf8($pw);

    my $h0 = sha512(
        pack('V4', $alg_id, $t, $m, $len)
        . pack('V', length $pw)   . $pw
        . pack('V', length $salt) . $salt
    );

    my @mem;
    $mem[0] = _b2blk(_expand($h0 . pack('V', 0), 1024));
    $mem[1] = _b2blk(_expand($h0 . pack('V', 1), 1024));

    my $first_half = int($m / 2);

    for my $pass (0 .. $t - 1) {
        my $start = $pass == 0 ? 2 : 0;
        for my $i ($start .. $m - 1) {
            my $prev = $mem[ ($i - 1) % $m ];
            my $ref;

            if ($alg_id == ALG_ID_LEGACY) {
                if ($pass == 0) {
                    $ref = _ref_index_legacy($h0, $pass, $i);
                } else {
                    $ref = _ref_index_datadep($prev, $i, $m, $pass);
                }
            } else {
                if ($pass == 0 && $i < $first_half) {
                    $ref = _ref_index_uniform($h0, $pass, $i);
                } else {
                    $ref = _ref_index_datadep($prev, $i, $m, $pass);
                }
            }

            die "HiatalaMrk: uninitialized ref (pass=$pass, i=$i, ref=$ref, m=$m)\n"
                unless defined $mem[$ref] && ref $mem[$ref] eq 'ARRAY';

            my $new = $compress->($prev, $mem[$ref]);
            if ($pass == 0) {
                $mem[$i] = $new;
            } else {
                my $old = $mem[$i];
                $mem[$i] = [ map { $old->[$_] ^ $new->[$_] } 0 .. WORDS - 1 ];
            }

            if ($args->{progress} && (($pass * $m + $i) % 64 == 0)) {
                $args->{progress}->($pass * $m + $i, $m * $t);
            }
        }
    }

    return _expand(sha512(_blk2b($mem[ $m - 1 ]) . $h0), $len);
}

sub hiatala_mrk_raw {
    my $args = @_ == 1 && ref $_[0] eq 'HASH' ? $_[0] : { @_ };
    my $alg  = $args->{alg_id} // ALG_ID_CURRENT;
    return _raw_with_compress(\&_compress, $args, $alg);
}

sub hiatala_mrk_raw_pureperl {
    my $args = @_ == 1 && ref $_[0] eq 'HASH' ? $_[0] : { @_ };
    my $alg  = $args->{alg_id} // ALG_ID_CURRENT;
    return _raw_with_compress(\&_compress_pureperl, $args, $alg);
}

sub hiatala_mrk_raw_xs {
    my $args = @_ == 1 && ref $_[0] eq 'HASH' ? $_[0] : { @_ };
    die "HiatalaMrk: XS backend not available\n" unless $USE_XS;
    my $alg = $args->{alg_id} // ALG_ID_CURRENT;
    return _raw_with_compress(\&_compress, $args, $alg);
}

# ---------------------------------------------------------------------------
# Debug helper: return reference indices used by pass 0
# ---------------------------------------------------------------------------
sub debug_refs {
    my $args = @_ == 1 && ref $_[0] eq 'HASH' ? $_[0] : { @_ };
    my $pw   = $args->{password} // '';
    my $salt = $args->{salt} or die "HiatalaMrk: salt required\n";
    my $m    = $args->{memory} // DEF_MEMORY;
    my $t    = $args->{passes} // 1;
    my $len  = $args->{outlen} // DEF_OUTLEN;
    my $alg  = $args->{alg_id} // ALG_ID_CURRENT;
    _check_params($m, $t, $len);

    utf8::encode($pw) if utf8::is_utf8($pw);

    my $h0 = sha512(
        pack('V4', $alg, $t, $m, $len)
        . pack('V', length $pw)   . $pw
        . pack('V', length $salt) . $salt
    );

    my @mem;
    $mem[0] = _b2blk(_expand($h0 . pack('V', 0), 1024));
    $mem[1] = _b2blk(_expand($h0 . pack('V', 1), 1024));

    my $first_half = int($m / 2);
    my @refs;

    for my $i (2 .. $m - 1) {
        my $prev = $mem[$i - 1];
        my $ref;
        if ($alg == ALG_ID_LEGACY) {
            $ref = _ref_index_legacy($h0, 0, $i);
        } else {
            if ($i < $first_half) {
                $ref = _ref_index_uniform($h0, 0, $i);
            } else {
                $ref = _ref_index_datadep($prev, $i, $m, 0);
            }
        }
        push @refs, $ref;
        $mem[$i] = _compress($prev, $mem[$ref]);
    }
    return @refs;
}

# ---------------------------------------------------------------------------
# Encoded format
# ---------------------------------------------------------------------------
sub _normalize_config {
    my ($cfg) = @_;
    $cfg ||= {};
    die "HiatalaMrk: config must be a hashref\n" if ref $cfg ne 'HASH';
    return {
        memory  => $cfg->{memory}  // DEF_MEMORY,
        passes  => $cfg->{passes}  // DEF_PASSES,
        outlen  => $cfg->{outlen}  // DEF_OUTLEN,
        saltlen => $cfg->{saltlen} // DEF_SALTLEN,
        alg_id  => $cfg->{alg_id}  // ALG_ID_CURRENT,
    };
}

sub hiatala_mrk_hash {
    my $args = @_ == 1 && ref $_[0] eq 'HASH' ? $_[0] : { @_ };
    my $cfg  = _normalize_config($args);
    my $salt = $args->{salt} // _random_bytes($cfg->{saltlen});
    die "HiatalaMrk: salt too short\n" if length($salt) < 8;

    my $raw = _raw_with_compress(
        \&_compress,
        {
            password => $args->{password},
            salt     => $salt,
            memory   => $cfg->{memory},
            passes   => $cfg->{passes},
            outlen   => $cfg->{outlen},
            progress => $args->{progress},
        },
        $cfg->{alg_id},
    );

    return sprintf(
        '$hiatalamrk$v=3$a=%d$m=%d,t=%d,l=%d$%s$%s',
        $cfg->{alg_id}, $cfg->{memory}, $cfg->{passes}, $cfg->{outlen},
        _b64($salt), _b64($raw),
    );
}

sub hiatala_mrk_verify {
    my ($encoded, $password, $cfg) = @_;
    my $d = hiatala_mrk_verify_detail($encoded, $password, $cfg);
    return $d->{ok} ? 1 : 0;
}

sub hiatala_mrk_verify_detail {
    my ($encoded, $password, $cfg) = @_;
    my %out = (ok => 0, reason => 'unknown');

    return { %out, reason => 'undef encoded' }  unless defined $encoded;
    return { %out, reason => 'undef password' } unless defined $password;

    my ($v, $a, $m, $t, $l, $salt_b64, $hash_b64);
    if ($encoded =~ /^\$hiatalamrk\$v=3\$a=(\d+)\$m=(\d+),t=(\d+),l=(\d+)\$([A-Za-z0-9+\/]+)\$([A-Za-z0-9+\/]+)$/) {
        ($v, $a, $m, $t, $l, $salt_b64, $hash_b64) = (3, $1, $2, $3, $4, $5, $6);
    } elsif ($encoded =~ /^\$hiatalamrk\$v=2\$a=(\d+)\$m=(\d+),t=(\d+),l=(\d+)\$([A-Za-z0-9+\/]+)\$([A-Za-z0-9+\/]+)$/) {
        ($v, $a, $m, $t, $l, $salt_b64, $hash_b64) = (2, $1, $2, $3, $4, $5, $6);
    } elsif ($encoded =~ /^\$hiatalamrk\$v=1\$m=(\d+),t=(\d+)\$([A-Za-z0-9+\/]+)\$([A-Za-z0-9+\/]+)$/) {
        ($v, $a, $m, $t, $salt_b64, $hash_b64) = (1, ALG_ID_LEGACY, $1, $2, $3, $4);
        $l = undef;
    } else {
        return { %out, reason => 'malformed encoded string' };
    }

    return { %out, reason => "unsupported alg id $a" }
        unless $a == ALG_ID_CURRENT || $a == ALG_ID_LEGACY;

    $a = ALG_ID_LEGACY if $v < 3;

    my $salt     = _unb64($salt_b64);
    my $expected = _unb64($hash_b64);
    $l //= length $expected;

    my $got = eval {
        _raw_with_compress(
            \&_compress,
            {
                password => $password, salt => $salt,
                memory => $m, passes => $t, outlen => $l,
                alg_id => $a,
            },
            $a,
        );
    };
    return { %out, reason => "recomputation died: $@" } unless defined $got;
    return { %out, reason => 'hash mismatch' } unless _ct_equal($got, $expected);

    return {
        ok     => 1,
        reason => 'ok',
        params => { v => $v, a => $a, m => $m, t => $t, l => $l },
    };
}

1;

__END__

=head1 NAME

HiatalaMrk - experimental memory-hard password hashing (Argon2-inspired)

=head1 STATUS

B<Research prototype. Not for production use.>

=head1 SYNOPSIS

    use HiatalaMrk qw(:all);

    printf "backend: %s\n", backend();

    my $enc = hiatala_mrk_hash({ password => 'hunter2' });
    print "ok\n" if hiatala_mrk_verify($enc, 'hunter2');

=head1 ENCODED FORMAT

    $hiatalamrk$v=3$a=7$m=16384,t=3,l=32$<salt_b64>$<hash_b64>

=cut
