use strict;
use warnings;
use Test::More;
use HiatalaMrk qw(:all);

my $salt = 'bounds-test-salt';

# Lowest accepted values
ok(eval { hiatala_mrk_raw(password => 'x', salt => $salt, memory => 8, passes => 1, outlen => 4); 1 },
   'minimum valid params accepted');

# Highest accepted values (avoid actually running the largest)
ok(eval { hiatala_mrk_raw(password => 'x', salt => $salt, memory => 8, passes => 1, outlen => 1024); 1 },
   'outlen 1024 accepted');

# Memory below minimum
ok(!eval { hiatala_mrk_raw(password => 'x', salt => $salt, memory => 7); 1 },
   'memory 7 rejected');

# Passes below minimum
ok(!eval { hiatala_mrk_raw(password => 'x', salt => $salt, passes => 0); 1 },
   'passes 0 rejected');

# Passes above maximum
ok(!eval { hiatala_mrk_raw(password => 'x', salt => $salt, passes => 1001); 1 },
   'passes 1001 rejected');

# Outlen below minimum
ok(!eval { hiatala_mrk_raw(password => 'x', salt => $salt, outlen => 3); 1 },
   'outlen 3 rejected');

# Outlen above maximum
ok(!eval { hiatala_mrk_raw(password => 'x', salt => $salt, outlen => 1025); 1 },
   'outlen 1025 rejected');

# Salt too short
ok(!eval { hiatala_mrk_raw(password => 'x', salt => 'short'); 1 },
   'salt shorter than 8 bytes rejected');

# No password
ok(!eval { hiatala_mrk_raw(salt => $salt); 1 },
   'missing password rejected');

# No salt
ok(!eval { hiatala_mrk_raw(password => 'x'); 1 },
   'missing salt rejected');

# Non-numeric params
ok(!eval { hiatala_mrk_raw(password => 'x', salt => $salt, memory => 'many'); 1 },
   'non-numeric memory rejected');

# Sanity: all four outlen values produce distinct outputs
my @outs = map { hiatala_mrk_raw(password => 'x', salt => $salt, memory => 16, passes => 1, outlen => $_) }
           (4, 8, 16, 32);
is(scalar @outs, 4, 'four outlen values accepted');
isnt($outs[0], $outs[1], 'outlen 4 vs 8 differ');
isnt($outs[1], $outs[2], 'outlen 8 vs 16 differ');
isnt($outs[2], $outs[3], 'outlen 16 vs 32 differ');

done_testing;
