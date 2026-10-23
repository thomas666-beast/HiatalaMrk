# HiatalaMrk

An experimental memory-hard password hashing function for Perl, inspired by Argon2. Includes a pure-Perl reference implementation and an optional XS backend that accelerates the block compression function by roughly 25×.

**Research prototype. Not for production use.** See [Status](#status).

## Status

HiatalaMrk exists to study memory-hard KDF design in Perl. It has had no cryptanalysis, and it should not protect real credentials.

An optional XS backend accelerates the block compression function. When compiled, `backend()` returns `'xs'` and the XS path is used automatically; otherwise the module falls back to the pure-Perl reference implementation. Both produce identical output, verified by `t/xs-parity.t`.

For production password hashing, use [Crypt::Argon2](https://metacpan.org/pod/Crypt::Argon2).

## Features

| Feature | Description |
|---|---|
| Memory-hard KDF | Argon2-inspired block compression with hybrid addressing |
| Hybrid addressing | Data-independent first half of pass 0, data-dependent second half (Argon2id-style) |
| Pure-Perl reference | Portable, no compiler required, used as fallback |
| XS backend | ~25× faster compression; requires a C compiler at build time |
| Self-describing output | Encoded string records algorithm, memory, passes, output length |
| Constant-time verify | Timing-safe comparison of recomputed hash |
| Progress callback | Optional hook for CLI progress bars |
| UTF-8 safe | Flagged and unflagged strings produce identical hashes |
| Backward compatible | v=1 and v=2 encoded hashes still verify |

## Installation

### From source

```bash
perl Makefile.PL
make
make test
make install
```

The XS backend is compiled automatically if a C compiler is available. If not, `make` still succeeds and the module runs in pure-Perl mode.

### Dependencies

- Perl 5.10 or later
- `Digest::SHA` (core)
- `MIME::Base64` (core)
- `Test::More` (core, tests only)
- Optional: `Crypt::PRNG` (recommended random source; falls back to `/dev/urandom`)
- Optional: `Crypt::Argon2` (only for the production-path example)

## Usage

### Basic hashing and verification

```perl
use HiatalaMrk qw(:all);

# Hash with defaults: 16 MiB memory, 3 passes, 32-byte output
my $encoded = hiatala_mrk_hash({ password => 'correct horse battery staple' });

# Store $encoded in your database

# Verify
if (hiatala_mrk_verify($encoded, 'correct horse battery staple')) {
    print "Login OK\n";
}
```

### Custom parameters

```perl
use HiatalaMrk qw(:all);

my $encoded = hiatala_mrk_hash({
    password => 'my password',
    memory   => 8192,   # KiB
    passes   => 4,
    outlen   => 32,
});
```

### Raw bytes (for custom encoding)

```perl
use HiatalaMrk qw(:all);

my $raw = hiatala_mrk_raw(
    password => 'my password',
    salt     => 'my-16-byte-salt!',   # at least 8 bytes
    memory   => 1024,
    passes   => 3,
    outlen   => 32,
);
```

### Inspecting failures

```perl
use HiatalaMrk qw(:all);

my $detail = hiatala_mrk_verify_detail($encoded, $guess);
unless ($detail->{ok}) {
    warn "Verification failed: $detail->{reason}\n";
    # Reasons: 'hash mismatch', 'malformed encoded string',
    #          'unsupported alg id N', 'recomputation died: ...'
}
```

### Progress callback

```perl
use HiatalaMrk qw(:all);

hiatala_mrk_hash(
    password => 'my password',
    progress => sub {
        my ($done, $total) = @_;
        printf STDERR "\r%d/%d", $done, $total;
    },
);
```

### Which backend is active?

```perl
use HiatalaMrk qw(:all);

printf "Backend: %s\n", backend();   # 'xs' or 'pureperl'
```

### Forcing a specific backend

```perl
use HiatalaMrk qw(:all);

# Force pure-Perl (useful for testing or benchmarking)
my $pure = hiatala_mrk_raw_pureperl(%args);

# Force XS (dies if not compiled)
my $xs = hiatala_mrk_raw_xs(%args);
```

### Debugging reference indices

```perl
use HiatalaMrk qw(:all);

# Returns the reference block indices used by pass 0.
# Intended for statistical testing, not for cryptographic use.
my @refs = HiatalaMrk::debug_refs(
    password => 'test',
    salt     => 'test-salt-16byte',
    memory   => 64,
    passes   => 1,
);
```

## Encoded format

```
$hiatalamrk$v=3$a=7$m=16384,t=3,l=32$<salt_b64>$<hash_b64>
```

| Field | Meaning |
|---|---|
| `v=3` | Encoded format version |
| `a=7` | Algorithm ID (7 = hybrid addressing) |
| `m=` | Memory in KiB |
| `t=` | Number of passes |
| `l=` | Output length in bytes |
| salt | Base64 (no padding) of the salt |
| hash | Base64 (no padding) of the derived bytes |

### Backward compatibility

| Version | Algorithm | Status |
|---|---|---|
| `v=3, a=7` | Hybrid addressing (current) | Produced by `hiatala_mrk_hash` |
| `v=2, a=6` | Original algorithm, 4096 default memory | Still verifies |
| `v=1, a=6` | Original algorithm, no explicit fields | Still verifies |

Old hashes remain verifiable. New hashes always use `v=3, a=7`.

## Parameters

| Name | Default | Min | Max | Notes |
|---|---|---|---|---|
| `memory` | 16384 | 8 | 4,194,304 | KiB |
| `passes` | 3 | 1 | 1000 | |
| `outlen` | 32 | 4 | 1024 | bytes |
| `saltlen` | 16 | 8 | — | bytes, `hiatala_mrk_hash` only |

## Algorithm

Memory is an array of 1 KiB blocks, each holding 128 unsigned 64-bit words.

1. **Block 0 and 1** are expanded from `SHA-512(ALG_ID, t, m, len, password, salt)` with a counter.
2. **Pass 0, first half** (`i < m/2`): reference blocks are chosen by a 53-bit uniform index derived from two SHA-512 outputs. This is **data-independent** — the reference does not depend on memory contents, which provides side-channel resistance.
3. **Pass 0, second half** (`i >= m/2`): reference blocks are chosen from the previous block's first 32 bits. This is **data-dependent**, which provides resistance to time-memory trade-off (TMTO) attacks.
4. **Passes 1 through t-1**: all blocks are updated with data-dependent addressing. Reference blocks wrap around the entire memory, excluding the current block.
5. **Output** is `SHA-512(last block || h0)` expanded to `outlen` bytes.

The compression function `G(x, y) = P(x ^ y) ^ (x ^ y)` uses an Argon2-style ARX permutation `P` with 8 contiguous and 8 strided groups of 16 words, each applying the `fBlaMka` primitive:

```
fBlaMka(x, y) = x + y + 2 * lo32(x) * lo32(y)   (mod 2^64)
```

### Addressing rules

| Pass | Position | Addressing | Reference range |
|---|---|---|---|
| 0 | `i < m/2` | Data-independent | `0 .. i-2` (uniform) |
| 0 | `i >= m/2` | Data-dependent | `0 .. i-1` |
| > 0 | all | Data-dependent | `0 .. m-1`, excluding `i` |

The constraints are enforced by construction: pass 0 never references an uninitialized block, and no block ever references itself.

## Performance

Pure-Perl throughput is roughly 2–5 MiB/s of memory fill. The XS backend is roughly 25× faster on the same hardware. Benchmarks on a modern x86-64 machine (v=3, a=7):

```
Backend: xs

memory   passes pure (s)     xs (s)       speedup
------------------------------------------------------
512      3      0.3451       0.0150       23.0x
1024     3      0.6859       0.0295       23.3x
2048     3      1.3934       0.0580       24.0x
4096     3      3.1235       0.1150       27.2x
8192     3      5.6717       0.2280       24.9x
16384    3      11.1899      0.4520       24.8x
```

The default (16 MiB, 3 passes) takes about 0.5 s with XS and about 11 s in pure Perl.

To run the benchmark yourself:

```bash
perl -Iblib/lib -Iblib/arch examples/bench.pl
```

## Testing

```bash
make test
```

| File | Purpose |
|---|---|
| `t/00-load.t` | Module loads |
| `t/basic.t` | Determinism, sensitivity, encoding, verification |
| `t/03-utf8.t` | UTF-8 flagged vs. unflagged consistency |
| `t/04-progress.t` | Progress callback contract |
| `t/05-encode.t` | Encoded format round-trip, tampering rejection, legacy v=2 |
| `t/06-param-bounds.t` | Parameter validation boundaries |
| `t/07-integration.t` | End-to-end registration/login flow |
| `t/09-ref-uniform.t` | Uniform reference distribution, deterministic refs, data-dependence |
| `t/xs-parity.t` | XS and pure-Perl produce identical output (both a=6 and a=7) |

The XS parity test is the most important one: it proves that the two backends are interchangeable.

## Building with XS

The XS backend is built automatically by `perl Makefile.PL && make`. If `make` fails at the `xsubpp` step, the most common cause is a stale `Makefile` from an earlier configuration. Run:

```bash
make clean
rm -f Makefile HiatalaMrk.c
rm -rf blib
perl Makefile.PL
make
```

To verify that the XS backend loaded:

```bash
perl -Iblib/lib -Iblib/arch -MHiatalaMrk -e 'print HiatalaMrk::backend(), "\n"'
```

This must print `xs`. If it prints `pureperl`, the `.so` did not load — check that `blib/arch/auto/HiatalaMrk/HiatalaMrk.so` exists and that `grep XSLoader blib/lib/HiatalaMrk.pm` returns at least two lines.

## What is proven and what is not

This section is deliberately explicit about the limits of the current implementation.

### What is provable and tested

| Claim | How it is proven |
|---|---|
| XS and pure-Perl backends are bit-identical | `t/xs-parity.t` for both a=6 and a=7 |
| Reference indices are uniformly distributed in the first half | Chi-squared test in `t/09-ref-uniform.t` |
| Reference indices are deterministic for the same input | `t/09-ref-uniform.t` |
| The second half of pass 0 varies with memory contents | `t/09-ref-uniform.t` |
| Default memory is 16 MiB and completes under 2s with XS | `t/08-default-perf.t` |
| Old v=1 and v=2 hashes still verify | `t/05-encode.t` |
| UTF-8 handling is consistent | `t/03-utf8.t` |
| Constant-time verify | `_ct_equal` in the source, exercised by `t/basic.t` |

### What is not proven

- **No cryptanalysis.** The algorithm has not been attacked by anyone. Argon2 has years of public analysis; HiatalaMrk has none.
- **Single-lane.** Argon2 supports `p` parallel lanes. HiatalaMrk does not. This means the memory-hardness relies on single-core throughput.
- **No formal specification.** The algorithm is defined by the source code.
- **No test vectors.** There are no published test vectors for other implementations to check against.
- **Memory ceiling in pure Perl.** Parameters above ~4 MiB are impractical without the XS backend.

Any of these could hide a weakness. The tests above prove that the implementation does what it claims to do; they do not prove that what it claims to do is secure.

## Limitations

- **Not for production.** See above.
- **Not a replacement for Argon2.** For any real application, use `Crypt::Argon2`.
- **Not audited.** No third party has reviewed the design.

## Pre-push checklist

```bash
# 1. All tests pass
make test

# 2. POD is valid
perl -MPod::Checker -e 'podchecker("lib/HiatalaMrk.pm")'

# 3. Backend loads
perl -Iblib/lib -Iblib/arch -MHiatalaMrk -e 'print HiatalaMrk::backend(), "\n"'

# 4. Both examples run
perl -Iblib/lib -Iblib/arch examples/password.pl
perl -Iblib/lib -Iblib/arch examples/demo.pl

# 5. Manifest is clean
make manifest
make distcheck

# 6. Build the tarball
make dist
```

## License

Same terms as Perl itself.

## See also

- [Crypt::Argon2](https://metacpan.org/pod/Crypt::Argon2) — production password hashing
- [CryptX](https://metacpan.org/pod/CryptX) — general cryptography for Perl
- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) — Argon2 specification
- [Password Hashing Competition](https://www.password-hashing.net/) — the competition that selected Argon2
