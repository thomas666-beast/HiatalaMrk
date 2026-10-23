use strict;
use warnings;
use Test::More;
use HiatalaMrk qw(:all);

my %db;
my $password = 'correct horse battery staple';
$db{alice} = hiatala_mrk_hash({
    password => $password,
    memory   => 64,
    passes   => 2,
});
ok(defined $db{alice}, 'stored hash for alice');
ok(hiatala_mrk_verify($db{alice}, $password), 'alice logs in with correct password');
ok(!hiatala_mrk_verify($db{alice}, 'wrong password'), 'alice rejected with wrong password');
ok(!hiatala_mrk_verify($db{alice}, ''), 'alice rejected with empty password');

$db{bob} = hiatala_mrk_hash({ password => $password, memory => 64, passes => 2 });
isnt($db{bob}, $db{alice}, 'same password produces different hash for bob');

SKIP: {
    skip 'XS not compiled', 3 unless backend() eq 'xs';

    my $enc_pure = hiatala_mrk_hash(
        password => 'backend-agnostic',
        salt     => 'backend-salt-16',
        memory   => 32,
        passes   => 2,
    );

    my $pure_raw = hiatala_mrk_raw_pureperl(
        password => 'backend-agnostic',
        salt     => 'backend-salt-16',
        memory   => 32,
        passes   => 2,
    );
    my $xs_raw = hiatala_mrk_raw_xs(
        password => 'backend-agnostic',
        salt     => 'backend-salt-16',
        memory   => 32,
        passes   => 2,
    );

    is($xs_raw, $pure_raw, 'pure-Perl and XS produce identical raw bytes');
    ok(hiatala_mrk_verify($enc_pure, 'backend-agnostic'), 'cross-backend verify works');

    like($enc_pure, qr/\$v=3\$a=7\$/, 'integration hash uses v=3, a=7');
}

done_testing;
