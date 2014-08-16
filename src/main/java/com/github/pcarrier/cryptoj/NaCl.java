package com.github.pcarrier.cryptoj;

public final class NaCl {
  private static final long gf0[] = {
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000
  };

  private static final long gf1[] = {
          0x0001, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000
  };

  private static final long _121665[] = {
          0xDB41, 0x0001, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000,
          0x0000, 0x0000, 0x0000, 0x0000
  };

  private static final long D[] = {
          0x78a3, 0x1359, 0x4dca, 0x75eb,
          0xd8ab, 0x4141, 0x0a4d, 0x0070,
          0xe898, 0x7779, 0x4079, 0x8cc7,
          0xfe73, 0x2b6f, 0x6cee, 0x5203
  };

  private static final long D2[] = {
          0xf159, 0x26b2, 0x9b94, 0xebd6,
          0xb156, 0x8283, 0x149a, 0x00e0,
          0xd130, 0xeef3, 0x80f2, 0x198e,
          0xfce7, 0x56df, 0xd9dc, 0x2406
  };

  private static final long X[] = {
          0xd51a, 0x8f25, 0x2d60, 0xc956,
          0xa7b2, 0x9525, 0xc760, 0x692c,
          0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
          0x53fe, 0xcd6e, 0x36d3, 0x2169};

  private static final long Y[] = {
          0x6658, 0x6666, 0x6666, 0x6666,
          0x6666, 0x6666, 0x6666, 0x6666,
          0x6666, 0x6666, 0x6666, 0x6666,
          0x6666, 0x6666, 0x6666, 0x6666
  };

  private static final long I[] = {
          0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
          0xe478, 0xad2f, 0x1806, 0x2f43,
          0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
          0xdf0b, 0x4fc1, 0x2480, 0x2b83
  };

  private static int L32(int x, int c) {
    return (x << c) | (x >>> (32 - c));
  }

  private static int ld32(byte[] src, int pos) {
    int u = src[pos + 3];
    u = (u << 8) | src[pos + 2];
    u = (u << 8) | src[pos + 1];
    return (u << 8) | src[pos];
  }

  private static long dl64(byte[] x, int xp) {
    long u = 0;
    for (int i = 0; i < 8; i++) {
      u = (u << 8) | x[xp + i];
    }
    return u;
  }

  private static void st32(
          byte[] x, int xp,
          int u
  ) {
    for (int i = 0; i < 4; i++) {
      x[xp + i] = (byte) (u & 0xFF);
      u >>>= 8;
    }
  }

  private static void ts64(
          byte[] x, int xp,
          long u
  ) {
    for (int i = 7; i >= 0; i--) {
      x[xp + i] = (byte) (u & 0xFF);
      u >>>= 8;
    }
  }

  private static boolean vn(
          byte[] x, int xp,
          byte[] y, int yp,
          int n
  ) {
    int d = 0;
    for (int i = 0; i < n; i++) {
      d |= x[xp + i] ^ y[yp + i];
    }
    return (1 & ((d - 1) >>> 8)) - 1 != 0;
  }

  private static boolean crypto_verify_16(
          byte[] x, int xp,
          byte[] y, int yp
  ) {
    return vn(x, xp, y, yp, 16);
  }

  private static boolean crypto_verify_32(
          byte[] x, int xp,
          byte[] y, int yp
  ) {
    return vn(x, xp, y, yp, 32);
  }

  private static void core(byte[] out, byte[] in, byte[] k, byte[] c, boolean h) {
    final int[] w = new int[16], x = new int[16], y = new int[16], t = new int[4];
    int i, j, m;

    for (i = 0; i < 4; i++) {
      x[5 * i] = ld32(c, 4 * i);
      x[1 + i] = ld32(k, 4 * i);
      x[6 + i] = ld32(in, 4 * i);
      x[11 + i] = ld32(k, 16 + 4 * i);
    }

    for (i = 0; i < 16; i++) {
      y[i] = x[i];
    }

    for (i = 0; i < 20; i++) {
      for (j = 0; j < 4; j++) {
        for (m = 0; m < 4; m++) {
          t[m] = x[(5 * j + 4 * m) % 16];
        }
        t[1] ^= L32(t[0] + t[3], 7);
        t[2] ^= L32(t[1] + t[0], 9);
        t[3] ^= L32(t[2] + t[1], 13);
        t[0] ^= L32(t[3] + t[2], 18);
        for (m = 0; m < 4; m++) {
          w[4 * j + (j + m) % 4] = t[m];
        }
      }
      for (m = 0; m < 16; m++) {
        x[m] = w[m];
      }
    }

    if (h) {
      for (i = 0; i < 16; i++) {
        x[i] += y[i];
      }
      for (i = 0; i < 4; i++) {
        x[5 * i] -= ld32(c, 4 * i);
        x[6 + i] -= ld32(in, 4 * i);
      }
      for (i = 0; i < 4; i++) {
        st32(out, 4 * i, x[5 * i]);
        st32(out, 16 + 4 * i, x[6 + i]);
      }
    } else {
      for (i = 0; i < 16; i++) {
        st32(out, 4 * i, x[i] + y[i]);
      }
    }
  }


  private static void crypto_core_salsa20(
          byte[] out,
          byte[] in,
          byte[] k,
          byte[] c
  ) {
    core(out, in, k, c, false);
  }

  private static void crypto_core_hsalsa20(byte[] out, byte[] in, byte[] k, byte[] c) {
    core(out, in, k, c, true);
  }


  // "expand 32-byte k" in ASCII
  private static final byte[] sigma = {
          0x65, 0x78, 0x70, 0x61,
          0x6e, 0x64, 0x20, 0x33,
          0x32, 0x2d, 0x62, 0x79,
          0x74, 0x65, 0x20, 0x6b
  };

  private static void crypto_stream_salsa20_xor(
          byte[] c, int cp,
          byte[] m, int mp,
          long b,
          byte[] n, int np,
          byte[] k
  ) {
    byte[] z = new byte[16], x = new byte[64];
    int u, i;

    if (b == 0)
      return;

    for (i = 0; i < 8; i++) {
      z[i] = n[np + i];
    }

    while (b >= 64) {
      crypto_core_salsa20(x, z, k, sigma);
      for (i = 0; i < 64; i++) {
        c[cp + i] = (byte) ((m == null ? 0 : m[mp + i]) ^ x[i]);
      }
      u = 1;
      for (i = 8; i < 16; i++) {
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
      for (i = 0; i < b; i++) {
        c[cp + i] = (byte) ((m == null ? 0 : m[mp + i]) ^ x[i]);
      }
    }
  }

  private static void crypto_stream_salsa20(
          byte[] c, int cp,
          long d,
          byte[] n, int np,
          byte[] k
  ) {
    crypto_stream_salsa20_xor(
            c, cp,
            null, 0,
            d,
            n, np,
            k);
  }

  private static void crypto_stream(
          byte[] c, int cp,
          long d,
          byte[] n,
          byte[] k
  ) {
    byte s[] = new byte[32];
    crypto_core_hsalsa20(s, n, k, sigma);
    crypto_stream_salsa20(
            c, cp,
            d,
            n, 16,
            s);
  }

  private static void crypto_stream_xor(
          byte[] c, int cp,
          byte[] m, int mp,
          long d,
          byte[] n,
          byte[] k
  ) {
    byte s[] = new byte[32];
    crypto_core_hsalsa20(s, n, k, sigma);
    crypto_stream_salsa20_xor(
            c, cp,
            m, mp,
            d,
            n, 16,
            s);
  }

  private static void add1305(int[] h, int[] c) {
    int j, u = 0;
    for (j = 0; j < 17; j++) {
      u += h[j] + c[j];
      h[j] = u & 0xff;
      u >>>= 8;
    }
  }

  private static int[] minusp = {
          5, 0, 0, 0,
          0, 0, 0, 0,
          0, 0, 0, 0,
          0, 0, 0, 0,
          252
  };

  private static void crypto_onetimeauth(
          byte[] out, int outp,
          byte[] m, int mp,
          long n,
          byte[] k
  ) {
    int s, i, j, u;
    int[] x = new int[17], r = new int[17], h = new int[17], c = new int[17], g = new int[17];
    for (j = 0; j < 16; j++) {
      r[j] = k[j];
    }
    r[3] &= 15;
    r[4] &= 252;
    r[7] &= 15;
    r[8] &= 252;
    r[11] &= 15;
    r[12] &= 252;
    r[15] &= 15;

    while (n > 0) {
      for (j = 0; (j < 16) && (j < n); j++) {
        c[j] = m[mp + j];
      }
      c[j] = 1;
      mp += j;
      n -= j;
      add1305(h, c);
      for (i = 0; i < 17; i++) {
        x[i] = 0;
        for (j = 0; j < 17; j++) {
          x[i] += h[j] *
                  ((j <= i) ?
                          r[i - j] :
                          320 * r[i + 17 - j]);
        }
      }
      for (j = 0; j < 17; j++) {
        h[i] = x[i];
      }
      u = 0;
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
    for (j = 0; j < 17; j++) {
      g[j] = h[j];
    }
    add1305(h, minusp);
    s = -(h[16] >>> 7);
    for (j = 0; j < 17; j++) {
      h[j] ^= s & (g[j] ^ h[j]);
    }
    for (j = 0; j < 16; j++) {
      c[j] = k[j + 16];
    }
    c[16] = 0;
    add1305(h, c);
    for (j = 0; j < 16; j++) {
      out[outp + j] = (byte) (h[j] & 0xff);
    }
  }

  private static boolean crypto_onetimeauth_verify(
          byte[] h, int hp,
          byte[] m, int mp,
          long n,
          byte[] k
  ) {
    byte[] x = new byte[16];
    crypto_onetimeauth(x, 0, m, mp, n, k);
    return crypto_verify_16(h, hp, x, 0);
  }

  private static void crypto_secretbox(byte[] c, byte[] m, long d, byte[] n, byte[] k)
          throws NaclException {
    if (d < 32) {
      throw E;
    }
    crypto_stream_xor(
            c, 0,
            m, 0,
            d,
            n,
            k
    );
    crypto_onetimeauth(
            c, 16,
            c, 32,
            d - 32,
            c
    );
    for (int i = 0; i < 16; i++) {
      m[i] = 0;
    }
  }



  private static class NaclException extends Exception {
  }

  private static NaclException E = new NaclException();

  // line 256 / 810
}