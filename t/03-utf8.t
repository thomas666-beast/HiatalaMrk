use strict;
use warnings;
use Test::More;
use HiatalaMrk qw(:all);

my $salt = 'utf8-test-salt-16';

# A non-ASCII password should hash identically whether or not
# it carries the UTF-8 flag, because the module encodes first.
my $flagged   = "caf\x{e9} \x{263a} \x{1F600}";
my $unflagged = do { my $s = $flagged; utf8::encode($s); $s };

my $h1 = hiatala_mrk_raw(password => $flagged,   salt => $salt, memory => 32, passes => 2);
my $h2 = hiatala_mrk_raw(password => $unflagged, salt => $salt, memory => 32, passes => 2);

is($h1, $h2, 'flagged and unflagged UTF-8 password produce same hash');

# Changing even one non-ASCII byte should change the output
my $alt = "caf\x{e8} \x{263a} \x{1F600}";
my $h3  = hiatala_mrk_raw(password => $alt, salt => $salt, memory => 32, passes => 2);
isnt($h3, $h1, 'different non-ASCII character changes hash');

# Empty password: allowed by hiatala_mrk_raw (only salt is required)
my $empty = hiatala_mrk_raw(password => '', salt => $salt, memory => 8, passes => 1);
is(length($empty), 32, 'empty password produces 32-byte output');

# Verify that empty password round-trips through the encoded form
my $enc = hiatala_mrk_hash(password => '', memory => 8, passes => 1);
ok(hiatala_mrk_verify($enc, ''), 'empty password verifies');
ok(!hiatala_mrk_verify($enc, 'x'), 'empty password rejects non-empty');

done_testing;
