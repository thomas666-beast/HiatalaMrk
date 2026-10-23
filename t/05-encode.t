use strict;
use warnings;
use Test::More;
use HiatalaMrk qw(:all);

my $enc = hiatala_mrk_hash(password => 'encode-test', memory => 32, passes => 2);

like($enc, qr/^\$hiatalamrk\$v=3\$a=7\$m=32,t=2,l=32\$/, 'encoded form has expected fields');

my ($v, $a, $m, $t, $l, $salt_b64, $hash_b64) =
    $enc =~ /^\$hiatalamrk\$v=(\d+)\$a=(\d+)\$m=(\d+),t=(\d+),l=(\d+)\$([A-Za-z0-9+\/]+)\$([A-Za-z0-9+\/]+)$/;

is($v, 3,  'version is 3');
is($a, 7,  'alg id is 7');
is($m, 32, 'memory encoded correctly');
is($t, 2,  'passes encoded correctly');
is($l, 32, 'outlen encoded correctly');
cmp_ok(length($salt_b64), '>', 0, 'salt b64 is non-empty');
cmp_ok(length($hash_b64), '>', 0, 'hash b64 is non-empty');

my $fixed_salt = 'fixed-salt-16byt';
my $enc2 = hiatala_mrk_hash(password => 'x', salt => $fixed_salt, memory => 16, passes => 1);
like($enc2, qr/\$hiatalamrk\$v=3\$/, 'explicit salt accepted');
ok(hiatala_mrk_verify($enc2, 'x'), 'explicit salt verifies');

my $tampered = $enc;
my $tail = substr($tampered, -1, 1);
substr($tampered, -1, 1) = ($tail eq 'A' ? 'B' : 'A');
isnt($tampered, $enc, 'tampered string differs');
ok(!hiatala_mrk_verify($tampered, 'encode-test'), 'tampered encoding rejected');

my $trunc = substr($enc, 0, length($enc) - 4);
ok(!hiatala_mrk_verify($trunc, 'encode-test'), 'truncated encoding rejected');

ok(hiatala_mrk_verify($enc, 'encode-test'), 'correct password verifies');
ok(!hiatala_mrk_verify($enc, 'wrong'),       'wrong password rejected');

my $d = hiatala_mrk_verify_detail($enc, 'wrong');
is($d->{reason}, 'hash mismatch', 'wrong password reason is hash mismatch');

# Legacy v=2 encoding still verifies
my $legacy_salt = 'legacy-salt-16b';
my $legacy_hash = do {
    my $raw = _legacy_raw(password => 'legacy-pw', salt => $legacy_salt);
    sprintf('$hiatalamrk$v=2$a=6$m=32,t=2,l=32$%s$%s',
        _b64_for_test($legacy_salt), _b64_for_test($raw));
};
ok(hiatala_mrk_verify($legacy_hash, 'legacy-pw'), 'legacy v=2 hash verifies');
ok(!hiatala_mrk_verify($legacy_hash, 'wrong'),    'legacy v=2 rejects wrong password');

done_testing;

sub _b64_for_test {
    require MIME::Base64;
    my $s = MIME::Base64::encode_base64($_[0], '');
    $s =~ s/=+$//;
    return $s;
}

sub _legacy_raw {
    my (%o) = @_;
    return HiatalaMrk::hiatala_mrk_raw(
        %o, memory => 32, passes => 2, outlen => 32, alg_id => 6,
    );
}
