package com.github.pcarrier.cryptoj;

import java.util.Arrays;
import java.util.Random;

public final class NaCl {
  // "const u8[16]", "{0}"
  private static final byte[] _0 = {
          0, 0, 0, 0,
          0, 0, 0, 0,
          0, 0, 0, 0,
          0, 0, 0, 0,
  };

  // "const u8[32]", "{9}"
  private static final byte[] _9 = {
          9, 9, 9, 9, 9, 9, 9, 9,
          9, 9, 9, 9, 9, 9, 9, 9,
          9, 9, 9, 9, 9, 9, 9, 9,
          9, 9, 9, 9, 9, 9, 9, 9
  };

  // "const gf", "{0}"
  private static final long gf0[] = {
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000
  };

  // "const gf", "{1}"
  private static final long gf1[] = {
          0x0001, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000
  };

  // "const gf", "{0xDB41,1}"
  private static final long _121665[] = {
          0xDB41, 0x0001, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000
  };

  // "const gf", "Edwards curve parameter"
  private static final long D[] = {
          0x78a3, 0x1359, 0x4dca, 0x75eb,
          0xd8ab, 0x4141, 0x0a4d, 0x0070,
          0xe898, 0x7779, 0x4079, 0x8cc7,
          0xfe73, 0x2b6f, 0x6cee, 0x5203
  };

  // "const gf", "Edwards curve parameter, doubled"
  private static final long D2[] = {
          0xf159, 0x26b2, 0x9b94, 0xebd6,
          0xb156, 0x8283, 0x149a, 0x00e0,
          0xd130, 0xeef3, 0x80f2, 0x198e,
          0xfce7, 0x56df, 0xd9dc, 0x2406
  };

  // "const gf", "x-coordinate of base point"
  private static final long X[] = {
          0xd51a, 0x8f25, 0x2d60, 0xc956,
          0xa7b2, 0x9525, 0xc760, 0x692c,
          0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
          0x53fe, 0xcd6e, 0x36d3, 0x2169};

  // "const gf", "y-coordinate of base point"
  private static final long Y[] = {
          0x6658, 0x6666, 0x6666, 0x6666,
          0x6666, 0x6666, 0x6666, 0x6666,
          0x6666, 0x6666, 0x6666, 0x6666,
          0x6666, 0x6666, 0x6666, 0x6666
  };

  // "const gf", "\sqrt{-1} mod 2^{255} - 19"
  private static final long I[] = {
          0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
          0xe478, 0xad2f, 0x1806, 0x2f43,
          0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
          0xdf0b, 0x4fc1, 0x2480, 0x2b83
  };

  // "i64 [16], representing 256-bit integer in radix 2^{16}"
  private static long[] gf() {
    return new long[16];
  }

  // "rotate 32-bit integer left"
  private static int L32(final int x, final int c) {
    return (x << c) | (x >>> (32 - c));
  }

  // "load 32-bit integer little-endian"
  private static int ld32(final byte[] x, final int xp) {
    int u = x[xp + 3];
    u = (u << 8) | x[xp + 2];
    u = (u << 8) | x[xp + 1];
    return (u << 8) | x[xp];
  }

  // "load 64-bit integer big-endian"
  private static long dl64(final byte[] x, final int xp) {
    long u = 0;
    for (int i = 0; i < 8; i++) {
      u = (u << 8) | x[xp + i];
    }
    return u;
  }

  // "store 32-bit integer little-endian"
  private static void st32(final byte[] x, final int xp,
                           int u) {
    for (int i = 0; i < 4; i++) {
      x[xp + i] = (byte) (u & 0xFF);
      u >>>= 8;
    }
  }

  // "store 64-bit integer big-endian"
  private static void ts64(final byte[] x, final int xp,
                           long u) {
    for (int i = 7; i >= 0; i--) {
      x[xp + i] = (byte) (u & 0xFF);
      u >>>= 8;
    }
  }

  // "merged crypto_verify_16, crypto_verify_32"
  // constant-time comparison of bytes
  private static boolean vn(final byte[] x, final int xp,
                            final byte[] y, final int yp,
                            final int n) {
    int d = 0;
    for (int i = 0; i < n; i++) {
      d |= x[xp + i] ^ y[yp + i];
    }
    return (1 & ((d - 1) >>> 8)) - 1 != 0;
  }

  static boolean crypto_verify_16(final byte[] x, final int xp,
                                  final byte[] y, final int yp) {
    return vn(x, xp, y, yp, 16);
  }

  static boolean crypto_verify_32(final byte[] x, final int xp,
                                  final byte[] y, final int yp) {
    return vn(x, xp, y, yp, 32);
  }

  // "merged crypto_core_salsa20, crypto_core_hsalsa20"
  private static void core(final byte[] out,
                           final byte[] in,
                           final byte[] k,
                           final byte[] c,
                           final boolean h) {
    final int[] w = new int[16],
            x = new int[16],
            y = new int[16],
            t = new int[4];
    for (int i = 0; i < 4; i++) {
      x[5 * i] = ld32(c, 4 * i);
      x[1 + i] = ld32(k, 4 * i);
      x[6 + i] = ld32(in, 4 * i);
      x[11 + i] = ld32(k, 16 + 4 * i);
    }
    System.arraycopy(x, 0, y, 0, 16);
    for (int i = 0; i < 20; i++) {
      for (int j = 0; j < 4; j++) {
        for (int m = 0; m < 4; m++) {
          t[m] = x[(5 * j + 4 * m) % 16];
        }
        t[1] ^= L32(t[0] + t[3], 7);
        t[2] ^= L32(t[1] + t[0], 9);
        t[3] ^= L32(t[2] + t[1], 13);
        t[0] ^= L32(t[3] + t[2], 18);
        for (int m = 0; m < 4; m++) {
          w[4 * j + (j + m) % 4] = t[m];
        }
      }
      System.arraycopy(w, 0, x, 0, 16);
    }

    if (h) {
      for (int i = 0; i < 16; i++) {
        x[i] += y[i];
      }
      for (int i = 0; i < 4; i++) {
        x[5 * i] -= ld32(c, 4 * i);
        x[6 + i] -= ld32(in, 4 * i);
      }
      for (int i = 0; i < 4; i++) {
        st32(out, 4 * i, x[5 * i]);
        st32(out, 16 + 4 * i, x[6 + i]);
      }
    } else {
      for (int i = 0; i < 16; i++) {
        st32(out, 4 * i, x[i] + y[i]);
      }
    }
  }

  static void crypto_core_salsa20(final byte[] out,
                                  final byte[] in,
                                  final byte[] k,
                                  final byte[] c) {
    core(out, in, k, c, false);
  }

  static void crypto_core_hsalsa20(final byte[] out,
                                   final byte[] in,
                                   final byte[] k,
                                   final byte[] c) {
    core(out, in, k, c, true);
  }


  // "expand 32-byte k" in ASCII
  private static final byte[] sigma = {
          0x65, 0x78, 0x70, 0x61,
          0x6e, 0x64, 0x20, 0x33,
          0x32, 0x2d, 0x62, 0x79,
          0x74, 0x65, 0x20, 0x6b
  };

  static void crypto_stream_salsa20_xor(final byte[] c, int cp,
                                        final byte[] m, int mp,
                                        long b,
                                        final byte[] n, final int np,
                                        final byte[] k) {
    final byte[] z = new byte[16], x = new byte[64];
    if (b == 0)
      return;
    System.arraycopy(n, np, z, 0, 8);
    while (b >= 64) {
      crypto_core_salsa20(x, z, k, sigma);
      for (int i = 0; i < 64; i++) {
        c[cp + i] = (byte) ((m == null ? 0 : m[mp + i]) ^ x[i]);
      }
      for (int i = 8, u = 1; i < 16; i++) {
        u += z[i];
        z[i] = (byte) (u & 0xFF);
        u >>>= 8;
      }
      b -= 64;
      cp += 64;
      if (m != null) {
        mp += 64;
      }
    }
    if (b > 0) {
      crypto_core_salsa20(x, z, k, sigma);
      for (int i = 0; i < b; i++) {
        c[cp + i] = (byte) ((m == null ? 0 : m[mp + i]) ^ x[i]);
      }
    }
  }

  static void crypto_stream_salsa20(final byte[] c, final int cp,
                                    final long d,
                                    final byte[] n, final int np,
                                    final byte[] k) {
    crypto_stream_salsa20_xor(
            c, cp,
            null, 0,
            d,
            n, np,
            k);
  }

  static void crypto_stream(
          final byte[] c, final int cp,
          final long d,
          final byte[] n,
          final byte[] k) {
    final byte s[] = new byte[32];
    crypto_core_hsalsa20(s, n, k, sigma);
    crypto_stream_salsa20(
            c, cp,
            d,
            n, 16,
            s);
  }

  static void crypto_stream_xor(
          final byte[] c, final int cp,
          final byte[] m, final int mp,
          final long d,
          final byte[] n,
          final byte[] k) {
    final byte s[] = new byte[32];
    crypto_core_hsalsa20(s, n, k, sigma);
    crypto_stream_salsa20_xor(
            c, cp,
            m, mp,
            d,
            n, 16,
            s);
  }

  // "add 136-bit integers, radix 2^8"
  private static void add1305(final int[] h, final int[] c) {
    int u = 0;
    for (int j = 0; j < 17; j++) {
      u += h[j] + c[j];
      h[j] = u & 0xff;
      u >>>= 8;
    }
  }

  // "const u32[17]", "{5,0,...,0,252}"
  private static int[] minusp = {
          5, 0, 0, 0,
          0, 0, 0, 0,
          0, 0, 0, 0,
          0, 0, 0, 0,
          252
  };

  static void crypto_onetimeauth(final byte[] out, final int outp,
                                 final byte[] m, int mp,
                                 long n,
                                 final byte[] k) {
    final int[] x = new int[17],
            r = new int[17],
            h = new int[17],
            c = new int[17],
            g = new int[17];

    for (int i = 0; i < 16; i++) {
      r[i] = k[i];
    }

    r[3] &= 15;
    r[4] &= 252;
    r[7] &= 15;
    r[8] &= 252;
    r[11] &= 15;
    r[12] &= 252;
    r[15] &= 15;

    while (n > 0) {
      int j;
      for (j = 0; (j < 16) && (j < n); j++) {
        c[j] = m[mp + j];
      }
      c[j] = 1;
      mp += j;
      n -= j;
      add1305(h, c);
      for (int i = 0; i < 17; i++) {
        x[i] = 0;
        for (j = 0; j < 17; j++) {
          x[i] += h[j] *
                  ((j <= i) ?
                          r[i - j] :
                          320 * r[i + 17 - j]);
        }
      }
      System.arraycopy(x, 0, h, 0, 17);
      int u = 0;
      for (j = 0; j < 16; j++) {
        u += h[j];
        h[j] = u & 0xff;
        u >>>= 8;
      }
      u += h[16];
      h[16] = u & 3;
      u = 5 * (u >>> 2);
      for (j = 0; j < 16; j++) {
        u += h[j];
        h[j] = u & 255;
        u >>>= 8;
      }
      u += h[16];
      h[16] = u;
    }
    System.arraycopy(h, 0, g, 0, 17);
    add1305(h, minusp);
    int s = -(h[16] >>> 7);
    for (int j = 0; j < 17; j++) {
      h[j] ^= s & (g[j] ^ h[j]);
    }
    for (int j = 0; j < 16; j++) {
      c[j] = k[j + 16];
    }
    c[16] = 0;
    add1305(h, c);
    for (int j = 0; j < 16; j++) {
      out[outp + j] = (byte) (h[j] & 0xff);
    }
  }

  static boolean crypto_onetimeauth_verify(final byte[] h, final int hp,
                                           final byte[] m, final int mp,
                                           final long n,
                                           final byte[] k) {
    final byte[] x = new byte[16];
    crypto_onetimeauth(x, 0, m, mp, n, k);
    return crypto_verify_16(h, hp, x, 0);
  }

  static void crypto_secretbox(final byte[] c,
                               final byte[] m,
                               final long d,
                               final byte[] n,
                               final byte[] k)
          throws NaclException {
    if (d < 32) {
      throw E;
    }
    crypto_stream_xor(c, 0, m, 0, d, n, k);
    crypto_onetimeauth(c, 16, c, 32, d - 32, c);
    Arrays.fill(m, 0, 16, (byte) 0);
  }

  static void crypto_secretbox_open(final byte[] m,
                                    final byte[] c,
                                    final long d,
                                    final byte[] n,
                                    final byte[] k)
          throws NaclException {
    byte[] x = new byte[32];
    if (d < 32) {
      throw E;
    }
    crypto_stream(x, 0, 32, n, k);
    if (!crypto_onetimeauth_verify(c, 16, c, 32, d - 32, x)) {
      throw E;
    }
    crypto_stream_xor(m, 0, c, 0, d, n, k);
    Arrays.fill(m, 0, 32, (byte) 0);
  }

  // "copy 256-bit integer"
  private static void set25519(final long[] r, final long[] a) {
    System.arraycopy(a, 0, r, 0, 16);
  }

  // reduce mod 2^{255} - 19, radix 2^{16}
  private static void car25519(final long[] o, final int op) {
    long c;
    for (int i = 0; i < 16; i++) {
      o[op + i] += (1L << 16);
      c = o[op + i] >>> 16;
      o[op + (i + 1) * (i < 15 ? 1 : 0)] += c - 1 +
              37 * (c - 1) * (i == 15 ? 1 : 0);
      o[op + i] -= c << 16;
    }
  }

  // "256-bit conditional swap"
  private static void sel25519(final long[] p, final long[] q, final int b) {
    long c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
      long t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  }

  // "freeze integer mod 2^{255} − 19 and store"
  private static void pack25519(final byte[] o,
                                final long[] n, final int np) {
    long[] m = gf(), t = gf();
    System.arraycopy(n, np, t, 0, 16);
    car25519(t, 0);
    car25519(t, 0);
    car25519(t, 0);
    for (int j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (int i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >>> 16) & 1);
        m[i - 1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >>> 16) & 1);
      int b = (int) ((m[15] >>> 16) & 1);
      m[14] &= 0xffff;
      sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
      o[2 * i] = (byte) (t[i] & 0xff);
      o[2 * i + 1] = (byte) (t[i] >>> 8);
    }
  }

  // "compare mod 2^{255} - 19"
  private static boolean neq25519(final long[] a, final long[] b) {
    byte[] c = new byte[32], d = new byte[32];
    pack25519(c, a, 0);
    pack25519(d, b, 0);
    return crypto_verify_32(
            c, 0,
            d, 0);
  }

  // "parity of integer mod 2^{255} - 19"
  private static byte par25519(final long[] a) {
    byte[] d = new byte[32];
    pack25519(d, a, 0);
    return (byte) (d[0] & 1);
  }

  // "load integer mod 2^{255} − 19"
  private static void unpack25519(final long[] o, final byte[] n) {
    for (int i = 0; i < 16; i++) {
      o[i] = n[2 * i] + ((long) (n[2 * i + 1]) << 8);
    }
    o[15] &= 0x7fff;
  }

  // "add 256-bit integers, radix 2^{16}"
  private static void A(final long[] o, final long[] a, final long[] b) {
    for (int i = 0; i < 16; i++) {
      o[i] = a[i] + b[i];
    }
  }

  // "substract 256-bit integers, radix 2^{16}"
  private static void Z(final long[] o, final long[] a, final long[] b) {
    for (int i = 0; i < 16; i++) {
      o[i] = a[i] - b[i];
    }
  }

  // "multiply mod 2^{255} − 19, radix 2^{16}"
  private static void M(final long[] o, final int op,
                        final long[] a, final int ap,
                        final long[] b, final int bp) {
    final long[] t = new long[31];
    for (int i = 0; i < 16; i++) {
      for (int j = 0; j < 16; j++) {
        t[i + j] += a[ap + i] * b[bp + j];
      }
    }
    for (int i = 0; i < 15; i++) {
      t[i] += 38 * t[i + 16];
    }
    System.arraycopy(t, 0, o, op, 16);
    car25519(o, op);
    car25519(o, op);
  }

  // "square mod 2^{255} − 19, radix 2^{16}"
  private static void S(final long[] o, final long[] a) {
    M(o, 0, a, 0, a, 0);
  }

  // "power 2^{255} - 21 mod 2^{255} - 19"
  private static void inv25519(final long[] o, final int op,
                               final long[] i, final int ip) {
    final long[] c = gf();
    System.arraycopy(i, ip, c, 0, 16);
    for (int a = 253; a >= 0; a--) {
      S(c, c);
      if (a != 2 && a != 4) {
        M(c, 0, c, 0, i, 0);
      }
    }
    System.arraycopy(c, 0, o, op, 16);
  }

  // "power 2^{252} − 3 mod 2^{255} − 19"
  private static void pow2523(final long[] o, final long[] i) {
    final long[] c = gf();
    System.arraycopy(i, 0, c, 0, 16);
    for (int a = 250; a >= 0; a--) {
      S(c, c);
      if (a != 1) {
        M(c, 0, c, 0, i, 0);
      }
    }
    System.arraycopy(c, 0, o, 0, 6);
  }

  static void crypto_scalarmult(final byte[] q, final byte[] n, final byte[] p) {
    final byte[] z = new byte[32];
    final long[] x = new long[80];
    final long[] a = gf(), b = gf(), c = gf(), d = gf(), e = gf(), f = gf();
    System.arraycopy(n, 0, z, 0, 31);
    z[31] = (byte) ((n[31] & 127) | 64);
    z[0] &= 248;
    unpack25519(x, p);
    System.arraycopy(x, 0, b, 0, 16);
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; i--) {
      int r = (z[i >>> 3] >>> (i & 7)) & 1;
      sel25519(a, b, r);
      sel25519(c, d, r);
      A(e, a, c);
      Z(a, a, c);
      A(c, b, d);
      Z(b, b, d);
      S(d, e);
      S(f, a);
      M(a, 0, c, 0, a, 0);
      M(c, 0, b, 0, e, 0);
      A(e, a, c);
      Z(a, a, c);
      S(b, a);
      Z(c, d, f);
      M(a, 0, c, 0, _121665, 0);
      A(a, a, d);
      M(c, 0, c, 0, a, 0);
      M(a, 0, d, 0, f, 0);
      M(d, 0, b, 0, x, 0);
      S(b, e);
      sel25519(a, b, r);
      sel25519(c, d, r);
    }
    for (int i = 0; i < 16; i++) {
      x[i + 16] = a[i];
      x[i + 32] = c[i];
      x[i + 48] = b[i];
      x[i + 64] = d[i];
    }
    inv25519(x, 32, x, 32);
    M(x, 16, x, 16, x, 32);
    pack25519(q, x, 16);
  }

  static void crypto_scalarmult_base(final byte[] q, final byte[] n) {
    crypto_scalarmult(q, n, _9);
  }

  static void crypto_box_keypair(final byte[] y, final byte[] x, final Random r) {
    r.nextBytes(x); // 32 bytes
    crypto_scalarmult_base(y, x);
  }

  static void crypto_box_beforenm(final byte[] k, final byte[] y, final byte[] x) {
    final byte[] s = new byte[32];
    crypto_scalarmult(s, x, y);
    crypto_core_hsalsa20(k, _0, s, sigma);
  }

  static void crypto_box_afternm(final byte[] c,
                                 final byte[] m,
                                 final long d,
                                 final byte[] n,
                                 final byte[] k) throws NaclException {
    crypto_secretbox(c, m, d, n, k);
  }

  static void crypto_box_open_afternm(final byte[] m,
                                      final byte[] c,
                                      final long d,
                                      final byte[] n,
                                      final byte[] k) throws NaclException {
    crypto_secretbox_open(m, c, d, n, k);
  }

  static void crypto_box(final byte[] c,
                         final byte[] m,
                         final long d,
                         final byte[] n,
                         final byte[] y,
                         final byte[] x)
          throws NaclException {
    final byte[] k = new byte[32];
    crypto_box_beforenm(k, y, x);
    crypto_box_afternm(c, m, d, n, k);
  }

  static void crypto_box_open(final byte[] m,
                              final byte[] c,
                              final long d,
                              final byte[] n,
                              final byte[] y,
                              final byte[] x)
          throws NaclException {
    final byte[] k = new byte[32];
    crypto_box_beforenm(k, y, x);
    crypto_box_open_afternm(m, c, d, n, k);
  }

  // "rotate 64-bit integer right"
  private static long R(final long x, final int c) {
    return (x >>> c) | (x << (64 - c));
  }

  private static long Ch(final long x, final long y, final long z) {
    return (x & y) ^ (~x & z);
  }

  private static long Maj(final long x, final long y, final long z) {
    return (x & y) ^ (x & z) ^ (y & z);
  }

  private static long Sigma0(final long x) {
    return R(x, 28) ^ R(x, 34) ^ R(x, 39);
  }

  private static long Sigma1(final long x) {
    return R(x, 14) ^ R(x, 18) ^ R(x, 41);
  }

  private static long sigma0(final long x) {
    return R(x, 1) ^ R(x, 8) ^ (x >>> 7);
  }

  private static long sigma1(final long x) {
    return R(x, 19) ^ R(x, 61) ^ (x >>> 6);
  }

  private static final long[] K = {
          0x428a2f98d728ae22l, 0x7137449123ef65cdl, 0xb5c0fbcfec4d3b2fl, 0xe9b5dba58189dbbcl,
          0x3956c25bf348b538l, 0x59f111f1b605d019l, 0x923f82a4af194f9bl, 0xab1c5ed5da6d8118l,
          0xd807aa98a3030242l, 0x12835b0145706fbel, 0x243185be4ee4b28cl, 0x550c7dc3d5ffb4e2l,
          0x72be5d74f27b896fl, 0x80deb1fe3b1696b1l, 0x9bdc06a725c71235l, 0xc19bf174cf692694l,
          0xe49b69c19ef14ad2l, 0xefbe4786384f25e3l, 0x0fc19dc68b8cd5b5l, 0x240ca1cc77ac9c65l,
          0x2de92c6f592b0275l, 0x4a7484aa6ea6e483l, 0x5cb0a9dcbd41fbd4l, 0x76f988da831153b5l,
          0x983e5152ee66dfabl, 0xa831c66d2db43210l, 0xb00327c898fb213fl, 0xbf597fc7beef0ee4l,
          0xc6e00bf33da88fc2l, 0xd5a79147930aa725l, 0x06ca6351e003826fl, 0x142929670a0e6e70l,
          0x27b70a8546d22ffcl, 0x2e1b21385c26c926l, 0x4d2c6dfc5ac42aedl, 0x53380d139d95b3dfl,
          0x650a73548baf63del, 0x766a0abb3c77b2a8l, 0x81c2c92e47edaee6l, 0x92722c851482353bl,
          0xa2bfe8a14cf10364l, 0xa81a664bbc423001l, 0xc24b8b70d0f89791l, 0xc76c51a30654be30l,
          0xd192e819d6ef5218l, 0xd69906245565a910l, 0xf40e35855771202al, 0x106aa07032bbd1b8l,
          0x19a4c116b8d2d0c8l, 0x1e376c085141ab53l, 0x2748774cdf8eeb99l, 0x34b0bcb5e19b48a8l,
          0x391c0cb3c5c95a63l, 0x4ed8aa4ae3418acbl, 0x5b9cca4f7763e373l, 0x682e6ff3d6b2b8a3l,
          0x748f82ee5defb2fcl, 0x78a5636f43172f60l, 0x84c87814a1f0ab72l, 0x8cc702081a6439ecl,
          0x90befffa23631e28l, 0xa4506cebde82bde9l, 0xbef9a3f7b2c67915l, 0xc67178f2e372532bl,
          0xca273eceea26619cl, 0xd186b8c721c0c207l, 0xeada7dd6cde0eb1el, 0xf57d4f7fee6ed178l,
          0x06f067aa72176fbal, 0x0a637dc5a2c898a6l, 0x113f9804bef90dael, 0x1b710b35131c471bl,
          0x28db77f523047d84l, 0x32caab7b40c72493l, 0x3c9ebe0a15c9bebcl, 0x431d67c49c100d4cl,
          0x4cc5d4becb3e42b6l, 0x597f299cfc657e2al, 0x5fcb6fab3ad6faecl, 0x6c44198c4a475817l,
  };

  static final int crypto_hashblocks(final byte[] x,
                                     byte[] m, int mp,
                                     long n) {
    final long[] z = new long[8], b = new long[8], a = new long[8], w = new long[16];

    for (int i = 0; i < 8; i++) {
      z[i] = a[i] = dl64(x, 8 * i);
    }

    while (n >= 128) {
      for (int i = 0; i < 16; i++) {
        w[i] = dl64(m, mp + 8 * i);
      }

      for (int i = 0; i < 80; i++) {
        System.arraycopy(a, 0, b, 0, 8);
        long t = a[7] +
                Sigma1(a[4]) +
                Ch(a[4], a[5], a[6]) +
                K[i] + w[i % 16];
        b[7] = t +
                Sigma0(a[0]) +
                Maj(a[0], a[1], a[2]);
        b[3] += t;
        for (int j = 0; j < 8; j++) {
          a[(j + 1) % 8] = b[j];
        }

        if (i % 16 == 15) {
          for (int j = 0; j < 16; j++) {
            w[j] += w[(j + 9) % 16] +
                    sigma0(w[(j + 1) % 16]) +
                    sigma1(w[(j + 14) % 16]);
          }
        }
      }

      for (int i = 0; i < 8; i++) {
        a[i] += z[i];
        z[i] = a[i];
      }

      mp += 128;
      n -= 128;
    }

    for (int i = 0; i < 8; i++) {
      ts64(x, 8 * i, z[i]);
    }
    return (int) n;
  }

  private static final byte[] iv = {
          (byte) 0x6a, (byte) 0x09, (byte) 0xe6, (byte) 0x67,
          (byte) 0xf3, (byte) 0xbc, (byte) 0xc9, (byte) 0x08,

          (byte) 0xbb, (byte) 0x67, (byte) 0xae, (byte) 0x85,
          (byte) 0x84, (byte) 0xca, (byte) 0xa7, (byte) 0x3b,

          (byte) 0x3c, (byte) 0x6e, (byte) 0xf3, (byte) 0x72,
          (byte) 0xfe, (byte) 0x94, (byte) 0xf8, (byte) 0x2b,

          (byte) 0xa5, (byte) 0x4f, (byte) 0xf5, (byte) 0x3a,
          (byte) 0x5f, (byte) 0x1d, (byte) 0x36, (byte) 0xf1,

          (byte) 0x51, (byte) 0x0e, (byte) 0x52, (byte) 0x7f,
          (byte) 0xad, (byte) 0xe6, (byte) 0x82, (byte) 0xd1,

          (byte) 0x9b, (byte) 0x05, (byte) 0x68, (byte) 0x8c,
          (byte) 0x2b, (byte) 0x3e, (byte) 0x6c, (byte) 0x1f,

          (byte) 0x1f, (byte) 0x83, (byte) 0xd9, (byte) 0xab,
          (byte) 0xfb, (byte) 0x41, (byte) 0xbd, (byte) 0x6b,

          (byte) 0x5b, (byte) 0xe0, (byte) 0xcd, (byte) 0x19,
          (byte) 0x13, (byte) 0x7e, (byte) 0x21, (byte) 0x79,
  };

  static final void crypto_hash(final byte[] out, int outp,
                                final byte[] m, int mp,
                                int n) {
    final byte[] h = iv.clone(),
            x = new byte[256];
    int b = n;

    crypto_hashblocks(h, m, 0, n);
    mp += n;
    n &= 127;
    mp -= n;

    System.arraycopy(m, mp, x, 0, n);
    x[n] = (byte) 128;

    n = 256 - (n < 112 ? 1 : 0);
    x[n - 9] = (byte) (b >>> 61);
    ts64(x, n - 8, b << 3);
    crypto_hashblocks(h, x, 0, n);

    System.arraycopy(h, 0, out, outp, 64);
  }

  private static void add(final long[][] p,
                          final long[][] q) {
    long[] a = gf(), b = gf(), c = gf(), d = gf(), t = gf(),
            e = gf(), f = gf(), g = gf(), h = gf();

    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, 0, a, 0, t, 0);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, 0, b, 0, t, 0);
    M(c, 0, p[3], 0, q[3], 0);
    M(c, 0, c, 0, D2, 0);
    M(d, 0, p[2], 0, q[2], 0);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);

    M(p[0], 0, e, 0, f, 0);
    M(p[1], 0, h, 0, g, 0);
    M(p[2], 0, g, 0, f, 0);
    M(p[3], 0, e, 0, h, 0);
  }

  // "conditionally swap curve points"
  private static void cswap(final long[][] p,
                            final long[][] q,
                            final byte b) {
    for (int i = 0; i < 4; i++) {
      sel25519(p[i], q[i], b);
    }
  }

  // "freeze and store curve point"
  private static void pack(final byte[] r,
                           final long[][] p) {
    final long[] tx = gf(), ty = gf(), zi = gf();
    inv25519(zi, 0, p[2], 0);
    M(tx, 0, p[0], 0, zi, 0);
    M(tx, 0, p[1], 0, zi, 0);
    pack25519(r, ty, 0);
    r[31] ^= par25519(tx) << 7;
  }

  // "scalar multiplication on Edwards curve"
  private static void scalarmult(final long[][] p,
                                 final long[][] q,
                                 final byte[] s, int sp) {
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (int i = 255; i >= 0; --i) {
      byte b = (byte) ((s[sp + (i >>> 3)] >>> (i & 7)) & 1);
      cswap(p, q, b);
      add(q, p);
      add(p, p);
      cswap(p, q, b);
    }
  }

  // "scalar multiplication by base point on Edwards curve"
  private static void scalarbase(final long[][] p,
                                 final byte[] s, final int sp) {
    final long[][] q = {gf(), gf(), gf(), gf()};
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], 0, X, 0, Y, 0);
    scalarmult(p, q, s, sp);
  }

  static void crypto_sign_keypair(final byte[] pk,
                                  final byte[] sk,
                                  final Random r) {
    final byte[] d = new byte[64];
    final long[][] p = {gf(), gf(), gf(), gf()};

    r.nextBytes(sk); // 32 bytes
    crypto_hash(d, 0, sk, 0, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(p, d, 0);
    pack(pk, p);
    System.arraycopy(pk, 0, sk, 32, 32);
  }

  // "prime order of base point"
  private static final long[] L = {
          0xed, 0xd3, 0xf5, 0x5c,
          0x1a, 0x63, 0x12, 0x58,
          0xd6, 0x9c, 0xf7, 0xa2,
          0xde, 0xf9, 0xde, 0x14,
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x10
  };

  // "freeze mod order of base point, radix 2^8"
  private static void modL(final byte[] r, final int rp,
                           final long[] x) {
    long carry;
    for (int i = 63; i >= 32; i--) {
      carry = 0;
      int j;
      for (j = i - 32; j < i - 12; j++) {
        x[j] += carry - 16 * x[i] * L[j - (i - 32)];
        carry = (x[j] + 128) >>> 8;
        x[j] -= carry << 8;
      }
      x[j] += carry;
      x[i] = 0;
    }
    carry = 0;
    for (int j = 0; j < 32; j++) {
      x[j] += carry - (x[31] >>> 4) * L[j];
      carry = x[j] >>> 8;
      x[j] &= 255;
    }
    for (int j = 0; j < 32; j++) {
      x[j] -= carry * L[j];
    }
    for (int i = 0; i < 32; i++) {
      x[i + 1] += x[i] >>> 8;
      r[rp + i] = (byte) (x[i] & 255);
    }
  }

  // "freeze 512-bit string mod order of base point"
  private static void reduce(final byte[] r) {
    final long[] x = new long[64];
    for (int i = 0; i < 64; i++) {
      x[i] = r[i];
    }
    // 32 first bytes seem unnecessary (modL will set)
    Arrays.fill(r, 0, 64, (byte) 0);
    modL(r, 0, x);
  }

  static void crypto_sign(final byte[] sm,
                          final long[] smlen, // long[1], "pointer"; TODO:cleanup
                          final byte[] m,
                          final int n,
                          final byte[] sk) {
    final byte[] d = new byte[64],
            h = new byte[64],
            r = new byte[64];

    final long[] x = new long[64];
    final long[][] p = {gf(), gf(), gf(), gf()};

    crypto_hash(d, 0, sk, 0, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    smlen[0] = n + 64;
    System.arraycopy(m, 0, sm, 64, n);
    System.arraycopy(d, 32, sm, 32, 32);

    crypto_hash(r, 0, sm, 32, n + 32);
    reduce(h);
    scalarbase(p, r, 0);
    pack(sm, p);

    System.arraycopy(sk, 32, sm, 32, 32);
    crypto_hash(h, 0, sm, 0, n + 64);
    reduce(h);

    Arrays.fill(x, 0, 64, 0);
    for (int i = 0; i < 32; i++) {
      x[i] = r[i];
    }
    for (int i = 0; i < 32; i++) {
      for (int j = 0; j < 32; j++) {
        x[i + j] += h[i] * d[j];
      }
    }
    modL(sm, 32, x);
  }

  private static void unpackneg(final long[][] r,
                                final byte[] p)
          throws NaclException {
    final long[] t = gf(),
            chk = gf(),
            num = gf(),
            den = gf(),
            den2 = gf(),
            den4 = gf(),
            den6 = gf();

    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, 0, num, 0, D, 0);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, 0, den4, 0, den2, 0);
    M(t, 0, den6, 0, num, 0);
    M(t, 0, t, 0, den, 0);

    pow2523(t, t);
    M(t, 0, t, 0, num, 0);
    M(t, 0, t, 0, den, 0);
    M(t, 0, t, 0, den, 0);
    M(r[0], 0, t, 0, den, 0);

    S(chk, r[0]);
    M(chk, 0, chk, 0, den, 0);
    if (neq25519(chk, num)) {
      M(r[0], 0, r[0], 0, I, 0);
    }

    S(chk, r[0]);
    M(chk, 0, chk, 0, den, 0);
    if (neq25519(chk, num))
      throw E;

    if (par25519(r[0]) == (p[31] >>> 7)) {
      Z(r[0], gf0, r[0]);
    }

    M(r[3], 0, r[0], 0, r[1], 0);
  }

  static void crypto_sign_open(final byte[] m,
                               final long[] mlen, // long[1], "pointer"; TODO:cleanup
                               final byte[] sm,
                               int n,
                               final byte[] pk)
          throws NaclException {
    final byte[] t = new byte[32], h = new byte[64];
    final long[][] p = {gf(), gf(), gf(), gf()},
            q = {gf(), gf(), gf(), gf()};
    mlen[0] = -1;
    if (n < 64) {
      throw E;
    }
    unpackneg(q, pk);

    System.arraycopy(sm, 0, m, 0, n);
    System.arraycopy(pk, 0, m, 32, 32);

    crypto_hash(h, 0, m, 0, n);
    reduce(h);
    scalarmult(p, q, h, 0);

    scalarbase(q, sm, 32);
    add(p, q);
    pack(t, p);

    n -= 64;
    if (crypto_verify_32(sm, 0, t, 0)) {
      Arrays.fill(m, 0, n, (byte) 0);
      throw E;
    }

    for (int i = 0; i < n; i++) {
      m[i] = sm[i + 64];
      mlen[0] = n;
    }
  }

  private static class NaclException extends Exception {
  }

  private static NaclException E = new NaclException();
}