use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'HiatalaMrk',
    VERSION_FROM     => 'lib/HiatalaMrk.pm',
    ABSTRACT         => 'Experimental memory-hard password hashing',
    LICENSE          => 'perl',
    MIN_PERL_VERSION => '5.010',
    PREREQ_PM        => {
        'Digest::SHA'  => 0,
        'MIME::Base64' => 0,
        'Test::More'   => 0,
    },
    XS               => { 'HiatalaMrk.xs' => 'HiatalaMrk.c' },
    clean            => { FILES => 'HiatalaMrk.c' },
);
