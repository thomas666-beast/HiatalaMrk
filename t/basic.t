use strict;
use warnings;
use Test::More;
use HiatalaMrk qw(:all);

my $salt = 'somesalt-16bytes!';

my $a = hiatala_mrk_raw(password => 'x', salt => $salt, memory => 64, passes => 2);
my $b = hiatala_mrk_raw(password => 'x', salt => $salt, memory => 64, passes => 2);
is($a, $b, 'deterministic');

my $c = hiatala_mrk_raw({ password => 'x', salt => $salt, memory => 64, passes => 2 });
is($c, $a, 'hashref and flat list give same result');

my %base = (password => 'x', salt => $salt, memory => 64, passes => 2);
for my $change (
    [ password => 'y' ],
    [ salt     => 'othersalt-16byte' ],
    [ memory   => 65 ],
    [ passes   => 3 ],
) {
    my $d = hiatala_mrk_raw(%base, @$change);
    isnt($d, $a, "changing $change->[0] changes output");
}

is(length hiatala_mrk_raw(%base, outlen => 80), 80, 'outlen 80');
is(length hiatala_mrk_raw(%base, outlen => 4),   4, 'outlen 4');

my $enc = hiatala_mrk_hash(password => 'hunter2', memory => 64, passes => 2);
like($enc, qr/^\$hiatalamrk\$v=3\$a=7\$m=64,t=2,l=32\$/, 'v=3 encoded format');
ok( hiatala_mrk_verify($enc, 'hunter2'),     'verify correct password');
ok(!hiatala_mrk_verify($enc, 'hunter3'),     'reject wrong password');
ok(!hiatala_mrk_verify('garbage', 'hunter2'), 'reject malformed');
ok(!hiatala_mrk_verify($enc, undef),          'reject undef password');

my $d = hiatala_mrk_verify_detail($enc, 'hunter3');
ok(!$d->{ok}, 'detail: wrong password fails');
is($d->{reason}, 'hash mismatch', 'detail: reason is hash mismatch');

my $d2 = hiatala_mrk_verify_detail('garbage', 'hunter2');
is($d2->{reason}, 'malformed encoded string', 'detail: malformed reason');

my $e2 = hiatala_mrk_hash(password => 'hunter2', memory => 64, passes => 2);
isnt($enc, $e2, 'random salts differ');

for my $bad (
    { password => 'x', salt => 'short' },
    { password => 'x', salt => $salt, memory => 4 },
    { password => 'x', salt => $salt, passes => 0 },
    { password => 'x', salt => $salt, outlen => 2 },
    { salt => $salt },
) {
    ok(!eval { hiatala_mrk_raw(%$bad); 1 }, 'rejects bad params');
}

my $u1 = hiatala_mrk_raw(password => "caf\x{e9}\x{263a}", salt => $salt, memory => 16, passes => 1);
my $u2 = hiatala_mrk_raw(
    password => do { my $s = "caf\x{e9}\x{263a}"; utf8::encode($s); $s },
    salt => $salt, memory => 16, passes => 1,
);
is($u1, $u2, 'utf8 password handling consistent');

my $def = DEFAULT_CONFIG();
is($def->{memory}, 16384, 'default memory is 16 MiB');
is($def->{passes}, 3,    'default passes is 3');
is($def->{alg_id}, 7,    'default alg id is 7');

done_testing;
