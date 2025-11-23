---
title: "Deep Dive into WinRAR License Verification Scheme"
description: "In this post I deep dive into analyzing the license verification scheme of the popular freeware WinRAR."
date: 2025-03-08T22:52:50+02:00
slug: 2025-03-08-winrar-license-verification-scheme-analysis
type: posts
draft: false
katex: true
summary: "In this post I deep dive into analyzing the license verification scheme of the popular freeware WinRAR."
categories:
  - projects
tags:
  - real-world
  - sage
  - reverse-engineering
  - crypto
---

{{< toc >}}

# Introduction

Upon reverse engineering WinRAR to understand its internal workings and how the license key validation works, I discovered that all versions utilise a pretty ancient library for performing public key encryption and authentication — namely [`Pegwit (v8)`](https://web.archive.org/web/19990117082016/http://ds.dial.pipex.com:80/george.barwood/v8/pegwit.htm). Thankfully, its source code has now been uploaded to [Github](https://github.com/t-crest/patmos-benchmarks/tree/master/Mediabench/pegwit/src) so no need for the reader to hassle with a local copy.

Pegwit implements Elliptic Curve Cryptography (ECC) over finite fields and uses a variant of the Nyberg-Rueppel signature scheme for signing and verifying data. During my reversing, I wasn't able to find any SageMath implementation (or python at all) of the WinRAR signature scheme so this is where the fun began. By the way, this post was my main source of inspiration and motivation for making my previous post about [Inverse Ring Homomorphisms](https://rasti37.github.io/posts/2025-03-07-computing-inverse-ring-homomorphisms-diy/). We'll see how this is related shortly.

In this post, we will dive into how WinRAR's signature scheme works and we will re-implement it in SageMath. For this project, I worked with WinRAR 3.60 and the binary's sha256 checksum is: `8f0be63e34e412f339b625529361ac1576be5e84b4571c1cfafad9c6f4675645`.

# Signature Scheme Overview

Let $E$ be an elliptic curve with the following equation:

$$
E : y^2 + xy = x^3 + 161
$$

defined over the finite field $K = \text{GF}((2^{15})^{17})$. Using SageMath, we find the order of $E$ (source: Trust Me Bro):

$$q = 57896044618658097711785492504343953927113495037180187459668330685293304062220$$

```python
sage: factor(57896044618658097711785492504343953927113495037180187459668330685293304062220)
2^2 * 3 * 5 * 541 * 1783611972232227286253403958852247502375646797202100661111162374777982257
```

It turns out that, the ECC arithmetic for WinRAR is done in the $n$-torsion subgroup of prime order:

$$n = 1783611972232227286253403958852247502375646797202100661111162374777982257$$

An $n$-torsion subgroup is simply a subgroup of the group $E(K)$ that contains all the points of order $n$.

Let's define some notation first.

- $M$ -- the message to be signed and $h = H(M)$ the hash digest of $M$. More on the internals of $H$ later.
- $x$ -- the private key used to sign $M$.
- $(r, s)$ -- the signature of $M$.
- $G$ -- a fixed point of order $n$ defined in Pegwit.
- $P$ -- the public key used to verify $(r,s)$ along with $M$. $P$ is computed as $x \cdot G$.
- $[A]_x$ -- the x-coordinate of the point $A$.

## Signature Generation Algorithm Overview

For each signature, a unique, $240$-bit nonce $k$ is generated and the signature is computed as:

$$\quad\quad\quad\quad\ \ r = [k \cdot G]_x + h \pmod n\quad\quad(1)\\\
s = k - r \cdot x \pmod n$$
Final signature: $(r,s)$

## Signature Verification Algorithm Overview

Given a signature $(r,s)$, the hash digest $h = H(M)$ and the public key $P = x \cdot G$, the message $M$ is verified if and only if:

$$r - [s \cdot G + r \cdot P]_x \stackrel{?}{=} h$$

### Proof of Correctness

Why does this equation verify the signature? Working with the left-hand side, our goal is to end up with $h$. That would mean that the equation holds.

First, let's substitute $P$ with $x \cdot G$:

$$r - [s \cdot G + r \cdot x \cdot G]_x = r - [(s + r \cdot x) \cdot G]_x$$

Then, we substitute $s$:

$$r - [(k - r \cdot x + r \cdot x) \cdot G]_x = r - [k \cdot G]_x$$

Looking at how $r$ is defined in , we know that:

$$h = r - [k \cdot G]_x$$

This concludes the proof.

At this point, we have enough information to write a high-level pseudocode of this signature scheme in SageMath.

```python
n = 0x1026dd85081b82314691ced9bbec30547840e4bf72d8b5e0d258442bbcd31

def sign(privkey, M):
    k = get_nonce()
    h = hash_message(M)
    P = G * k
    r = (int(P.x()) + h) % n
    s = (k - privkey * r) % n
    return (r, s)

def verify(pubkey, M, sig):
    h = hash_message(M)
    r, s = sig
    t1 = G * s
    t2 = pubkey * r
    t1 = (t1 + t2).x() % n
    return h == r - t1.x()
```

But this is far from complete and accurate. Well ... to be 100% honest with you, the final version of the class will look like:

```python
class NybergRueppelScheme:
    def __init__(self, seed):
        self.ecc = ECC()
        self.seed = seed

    def sign(self, msg: bytes):
        self.prng = PRNG(self.seed)
        x = self.prng.gen_random()
        h = self.prng.hash_data(msg)
        while True:
            k = self.prng.gen_random()
            r, s = self.sign_internal(x, k, h)
            if r > 0 and s > 0:
                break
        return (r, s)

    def sign_internal(self, x, k, h):
        P = self.ecc.G * k
        Px = self.ecc.gfPoint2Int(P.x())
        r = (int(Px) + h) % self.ecc.n
        s = (k - x * r) % self.ecc.n
        return (r, s)

    def verify(self, pubkey, msg, sig):
        self.prng = PRNG(self.seed)
        h = self.prng.hash_data(msg)
        return self.verify_internal(pubkey, h, sig)
    
    def verify_internal(self, pubkey, h, sig):
        r, s = sig
        t1 = self.ecc.G * s
        t2 = pubkey * r
        t1 = self.ecc.gfPoint2Int((t1 + t2).x()) % self.ecc.n
        return h == r - self.ecc.gfPoint2Int(t1.x())
```

What is `gfPoint2Int`? How is the message actually hashed? What is this PRNG? How is it seeded? Hang in there — we still have a long way to go and I will explain everything in detail.

# Mapping source code to decompiled code

As aforementioned, thankfully, there is no need for hardcore reverse engineering, since most of the scheme's logic and implementation derive directly from Pegwit, which is open-source. For example, with a bit of targeted reverse engineering and audit of Pegwit's codebase, one can map Pegwit elements to their counterparts in the WinRAR decompilation through a bit of debugging and structural similarities. Some of the mapped components are shown below:

| Virtual Address | Name   | Type | Description |
| --------------- | ----------- | ---- | ----------- |
| 0x406CB8 | `cpVerify`  | Method | Internal method for signature verification using $P$ |
| 0x4A09D4 | $(G_x, G_y)$ | Array | $(x,y)$ coordinates of the base point $G$ |
| 0x4A0988 | Prime order $n$ | Array | The prime order of the subgroup generated by $G$ |
| 0x407F6C | `prng_hash_data` | Method | Internal method for computing the raw data hash $h$ |
| 0x407E7C | `prng_init` | Method | Internal method for initializing WinRAR's PRNG |
| 0x4A0B67 | $P_x$ | String | The $x$-coordinate of the public key point $P$ |
| 0x406C08 | `cpSign` | Method | Internal method for signing data using $x$ |

Moreover, having determined that `0x406C08` is `cpSign`, one can proceed to rename all of its callee functions according to Pegwit source. This process ultimately yields a decompilation nearly identical to the original implementation:

```c
void __fastcall cpSign(int vlPrivateKey, void *k, unsigned int *vlMac, cpPair *sig)
{
  int tmp[19]; // [esp+Ch] [ebp-170h] BYREF
  ecPoint P; // [esp+58h] [ebp-124h] BYREF

  ecCopy(&P, &BasePointG);
  ecMultiply(&P, k);                            // Q = P*k
  gfPack(&P, sig);                              // r = Q.x
  vlAdd(sig, vlMac);
  vlRemainder(sig, PrimeOrder);                 // r = (Qx + mac) % q
  if ( *sig->r )
  {
    vlMulMod(tmp, vlPrivateKey, sig, PrimeOrder);// tmp = (x * r) % n
    vlCopy(sig->s, k);
    if ( vlGreater(tmp, sig->s) )
      vlAdd(sig->s, PrimeOrder);
    vlSubtract(sig->s, tmp);                    // s = k - x * r
  }
}
```

where `cpPair`, `ecPoint` are helper structs that enhance readibility:

```c
struct cpPair {
    _BYTE r[76];
    _BYTE s[76];
};

struct ecPoint {
    _WORD x[72];
    _WORD y[72];
};
```

# WinRAR Signature Scheme Component Analysis

Having established some decent background knowledge, let's dive deep into the WinRAR internals.

## Analysis of the hash function $H$

Let's begin by analyzing how the raw data are hashed. In other words, how $h = H(M)$ is computed.

For this purpose, we are interested in `prng_hash_data`.

```c
void prng_hash_data(prng *p, char *data, unsigned int data_length)
{
    hash_context HashContext[2];
    unsigned char i[1];

    hash_initial(HashContext);
    hash_initial(HashContext + 1);
    *i = 1;
    hash_process(&HashContext[*i], i, 1);
    
    hash_process(HashContext, (unsigned char*) data, data_length);
    hash_process(HashContext+1, (unsigned char*) data, data_length);
    
    hash_final(HashContext, p->state + 6);
    hash_final(HashContext, p->state + 11);
    p->count = 16;
}
```

where `hash_initial` is implemented as:

```c
void hash_initial(hash_context* context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}
```

This strongly indicates that the backbone hashing is done by the SHA1 hash function. Note that even if the comment was missing, researching any constant, such as `0xC3D2E1F0`, would fetch results related to SHA-1.

For completeness, I will also copy/paste from the decompiler (address: `0x408235`), a code snippet where `prng_hash_data` is called:

```c
if ( a3 )
    prng_set_mac(&prng, a3, 2);
else
    prng_hash_data(&prng, Data, DataSize, 2);
hash_to_vlong(&prng.state[6], GeneratedMAC);
```

For our purposes, consider `a3` always equal to $0$. This can be derived by looking at the arguments of the function `0x4081F0`. Thus, this can be reduced to:

```c
prng_hash_data(&prng, Data, DataSize, 2);
hash_to_vlong(&prng.state[6], GeneratedMAC);
```

For now, don't worry about `hash_to_vlong`, treat it as a black-box that converts some data (first argument) to an integer that can be used mathematically for signing/verification operations (second argument). We will define such an integer as `vlong`.

The `prng` struct is defined as:

```c
typedef unsigned long word32;

typedef struct /* Whole structure will be hashed */
{
  unsigned count;        /* Count of words */
  word32 state[17];   /* Used to crank prng */
} prng;
```

It should be obvious until now that the PRNG and the data hashing are closely related. The PRNG state consists of 17 dwords and the final hash $h = H(M)$ is derived from the PRNG as follows:

<img src="prng-state-hash.png" style="width:80%" />

Now we have everything we know to define mathematically how the final hash is computed. The call to `hash_process`:

```c
hash_process(HashContext, (unsigned char*) data, data_length);
```

hashes our raw data and the final hash overwrites the state indices $[6,\ \cdots,\ 10]$. This is because a SHA-1 hash is $5 \cdot 4 = 20$ bytes long, corresponding to $5$ dwords.

```c
hash_final(HashContext, p->state + 6);
```

Here comes the tricky part. There appears to be a discrepancy between Pegwit's source and WinRAR's decompilation, which initially confused me and made it difficult for me to grasp what was going on. Just like that, I ended upspending several hours debugging in x64dbg🙂. In hindsight, this was probably a static-analysis skill issue on my part as I don't believe that the library itself is buggy — but hey, when static analysis fails, you gain more debugging experience (and lose a bit of hair) which is always really fun!

It turns out that shit happens with the first call to `hash_process`:

```c
*i = 1;
hash_process(&HashContext[*i], i, 1);

// ...

hash_process(HashContext+1, (unsigned char*) data, data_length);
```

These calls produce the fixed (magic) hash: `438dfd0f7c3ce3b4d11b465346a5270f0dd95010`, which corresponds to an empty byte-string input. This digest overwrites the state indices $[11,\ \dots,\ 15]$.

```c
hash_final(HashContext, p->state + 11);
```

(also check this [issue](https://github.com/micropython/micropython/issues/4119) which explains more about this magic hash).

Finally, as we mentioned already, the final hash is obtained by converting $[S_6,\ \dots,\ S_{13}]$ to a `vlong` integer.

The hashing process can be summarized with the following code:

```python
from hashlib import sha1

def H(m):
    return sha1(m).digest()

def dwordize(b: bytes) -> list:
    return [int.from_bytes(b[i:i+4], byteorder='big') for i in range(0, len(b), 4)]

def vlToInteger(vl):
    return Integer(vl[1:], base=2^16)

def hashToVlPoint(h : list):
    return [0x0f] + [x for i in range(8) for x in [h[i] & 0xffff, h[i] >> 16]][:0x0f]

def hash_data(self, data):
    h1 = H(data)
    h2 = bytes.fromhex('0ffd8d43b4e33c7c53461bd10f27a5461050d90d')  # zero-length input hash (?)
    self.state[0x06:] = dwordize(h1)
    self.state[0x0b:] = dwordize(h2)
    self.count = 16
    return vlToInteger(hashToVlPoint(self.state[6:14]))
```

Dang! What the heck are these `hashToVlPoint` and `vlToInteger` functions? I will explain shortly...

## Analyzing the `vlong` type

In the context of the Pegwit library, `vlong` is an array with the following form:

$$[l,\ v_1,\ \ \cdots,\ \ v_l]$$

where $v_i$ is a $16$-bit integer. In the WinRAR context, $l = 15$, which results in an array of fifteen $16$-bit integers. Pegwit performs arithmetic directly on integers of this form, as there is no natural way to work with such big integers in C; don't forget that standard integer arithmetic is limited to $64$ bits.

But why $l = 15$ ? Recall the prime order $n$. Let's compute its bit length:

```python
>>> n = 0x1026dd85081b82314691ced9bbec30547840e4bf72d8b5e0d258442bbcd31
>>> n.bit_length()
241
```

It is no coincidence that combining fifteen $16$-bit integers yields a $15 \cdot 16 = 240$-bit integer — which strongly indicates that this representation exists precisely because the scheme performs all computations modulo $n$.

Let's take a look at `hash_to_vlong` (`vlPoint` is synonym to `vlong`):

```c
typedef word16 vlPoint [VL_UNITS + 2];

void hash_to_vlong(word32* mac, vlPoint V)
{
    unsigned i;
    V[0] = 15; /* 240 bits */
    for (i=0; i<8; i+=1)
    {
        word32 x = mac[i];
        V[i*2+1] = (word16) x;
        V[i*2+2] = (word16) (x>>16);
    }
}
```

It basically sets $V_0 = l = 15$ and then iterates over each of the $8$ dwords. For the $i$-th dword, it stores its $16$ LSB to $V_{2i+1}$ and its $16$ MSB to $V_{2i+2}$. We can implement this as:

```python
def hash_to_vlong(h : list):
    return [0x0f] + [x for i in range(8) for x in [h[i] & 0xffff, h[i] >> 16]][:0x0f]
```

This concludes our Python implementation of WinRAR's data hashing process!

## Analysis of the PRNG

Let's define a base class for the PRNG.

```python
class PRNG:
    def __init__(self, seed):
        self.count = 0
        self.state = [0 for _ in range(17)]   # create memory for 1+16 dwords
```

The following questions are raised regarding the PRNG:

1. What does the internal state look like? 
2. How the seed is set?
3. How is the next output generated?

We already answered the first question; the state is an array of $1 + 16$ dwords.

For the second question, we take a look at the virtual address `0x4081F0` in our disassembler of choice. This is a wrapper method for signing the data and it looks like:

```c
void __fastcall ecc_sign_data_internal(char *Data, int DataSize, int PrecomputedMAC, char *Seed, char *Buffer)
{
    // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

    prng_init(&prng);
    prng_set_secret(&prng, Seed);
    prng_generate_random_vlong(&prng, vlPrivateKey);
    if ( PrecomputedMAC )
        prng_set_mac(&prng, PrecomputedMAC, 2);
    else
        prng_hash_data(&prng, Data, DataSize, 2);
    hash_to_vlong(&prng.state[6], GeneratedMAC);
    gfInit();
    do
    {
        prng_generate_random_vlong(&prng, k);
        cpSign(vlPrivateKey, k, GeneratedMAC, &sig);
    }
    while ( !*sig.r );
    put_vlong(sig.s, s);
    v7 = strlen(s);
    sprintf(Buffer, "%02.2d", v7);
    strcpy(Buffer + 2, s);
    put_vlong(&sig, &Buffer[v7 + 2]);
    gfQuit();
    prng_init(&prng);
    vlClear(vlPrivateKey);
    vlClear(k);
}
```

By following the cross-references of `ecc_sign_data_internal` in IDA, one can see that the `Seed` variable is a hex string sourced from the `rarreg.key` license file.

### How is the PRNG seed set

`prng_set_secret` and `prng_generate_random_vlong` are the methods of interest. Let's begin with the former. It receives the seed and sets the internal state accordingly.

```c
void prng_set_secret(prng *p, char* seed)
{
    hash_context HashContext;

    hash_initial(&HashContext);
    hash_process(&HashContext, (unsigned char*)seed, strlen((char*)seed));
    hash_final(&HashContext, p->state+1);
    p->count = 6;
}
```

It's a pretty self-explanatory function, it hashes the seed with SHA-1 and overwrites $S_1,\ \dots,\ S_5$ with the output hash. Here is the same code transpiled in python:

```python
def set_secret(self, seed):
    h = H(seed.encode())
    self.state[1:len(h)//4] = dwordize(h)
    self.count = 6
```

### How are random integers generated

As the name implies, the corresponding function for this is `prng_generate_random_vlong`. Its virtual address is `0x4080B4`.

```c
void __fastcall prng_generate_random_vlong(prng *a1, _DWORD *out)
{
  int i; // ebx

  *out = 15;
  for ( i = 1; i < 16; ++i )
    out[i] = prng_next(a1);
}
```

Ah! We identify the `vlong` format. The first element of the array is always the number of 2-byte words that follow. Each word is set to a random value returned from `prng_next`.

```c
int __fastcall prng_next(prng *a1)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  ++*a1->state;
  for ( i = 0; i < a1->count; ++i )
  {
    for ( j = 0; j < 4; ++j )
      buffer[4 * i + j] = *&a1->state[4 * i] >> (8 * j);
  }
  SHA1_init(&hash_ctxt);
  SHA1_update(hash_ctxt.state, buffer, 4 * a1->count, 0);
  SHA1_hash(hash_ctxt.state, res, 0);
  memset(buffer, 0, sizeof(buffer));
  return LOWORD(res[0]);
}
```

Again, straight-forward. Explaining this method in more detail would only create unnecessary confusion, so let's simply transpile it to Python.

```python
def gen_random(self):
    return vlToInteger([0x0f] + [self._next() for _ in range(0x0f)])

def _next(self):
    self.state[0] += 1
    buffer = [0 for _ in range(4 * self.count)]
    for i in range(self.count):
        for j in range(4):
            buffer[4 * i + j] = (self.state[i] >> (8*j)) & 0xff
    h = H(bytes(buffer))
    return int(h[2:4].hex(), 16)
```

This concludes our Python implementation of WinRAR's PRNG!

## Defining the curve in SageMath

We are almost done but we need to put the pieces of the puzzle together. We need to start considering how we can define the Pegwit curve in SageMath.

For this purpose, we will focus on the files `ec_field.*` and `ec_param.*`. From `ec_param.h`, we see:

```c
#elif GF_M == 255

#define GF_L	     15
#define GF_K	     17
#define GF_T	      3
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x00a1U
```

There is a comment on top of this file explaining what these magic numbers are:

```c
/*
GF_M	dimension of the large finite field (GF_M = GF_L*GF_K)
GF_L	dimension of the small finite field
GF_K	degree of the large field reduction trinomial
GF_T	intermediate power of the reduction trinomial
GF_RP	reduction polynomial for the small field (truncated)

...

*/
```

The smaller field is $GF(2^{15})$ and `GF_RP` tells us that it is defined over the polynomial $x + 1$ ($= 2^1 + 2^0 = 3$). However, to define it in SageMath, the irreducible polynomial must have degree $15$, so we use $x^{15} + x + 1$. Similarly, the large finite field is $GF(2^{17})$, which should be defined over the polynomial $y^{17} + y^3 + 1$. Notice that `GF_T` specifies the degree of the middle term.

Before defining the curve, I looked up the base point $G$ online and found it expressed in integer form:

```python
(0x56fdcbc6a27acee0cc2996e0096ae74feb1acf220a2341b898b549440297b8cc, 0x20da32e8afc90b7cf0e76bde44496b4d0794054e6ea60f388682463132f931a7)
```

This is kinda weird though. Looking at the Pegwit source, $G$ is defined as follows:

```c
const ecPoint curve_point = {
	{17U, 0x38ccU, 0x052fU, 0x2510U, 0x45aaU, 0x1b89U, 0x4468U, 0x4882U, 0x0d67U, 0x4febU, 0x55ceU, 0x0025U, 0x4cb7U, 0x0cc2U, 0x59dcU, 0x289eU, 0x65e3U, 0x56fdU, },
	{17U, 0x31a7U, 0x65f2U, 0x18c4U, 0x3412U, 0x7388U, 0x54c1U, 0x539bU, 0x4a02U, 0x4d07U, 0x12d6U, 0x7911U, 0x3b5eU, 0x4f0eU, 0x216fU, 0x2bf2U, 0x1974U, 0x20daU, },
}; /* curve_point */
```

So, where did this integer come from?

### Analyzing the Pegwit data types

What is this `ecPoint` type? Another struct... ? Let's take a look.

```c
typedef struct {
	gfPoint x, y;
} ecPoint;

typedef lunit gfPoint [GF_POINT_UNITS];
```

So the coordinates of a curve point are ... arrays again ? Oof... we encountered `vlPoint` previously too. What are the differences?

| `vlPoint` | `gfPoint` |
| - | - |
| Used to perform integer arithmetic operations in the prime  field $GF(n)$. | Used to do curve point arithmetic. The coordinates of any point span the entire field $GF(15^{17})$. |
| Represented as a list of fifteen 16-bit words. | Represented as a list of seventeen 15-bit words.
| Max value : $2^{240} - 1$ | Max value : $2^{255} - 1$ (this is roughly true as field elements are polynomials; more on that later) |

Looking at `curve_point` above, one might notice that `ecPoint` is a list of seventeen 16-bit words but this is misleading🙂.

It turns out that there are a couple methods for converting between the `gfPoint` and `vlPoint` types.

- `gfPack` : Packs a field point into a `vlPoint` (compression required since a field point is larger)
- `gfUnpack` : Unpacks a `vlPoint` into a field point (undoes `gfPack`)

There are also:

- `ecPack` : Packs a curve point into a `vlPoint` (essentially a wrapper to `gfPack`)
- `ecUnpack` : Unpacks a `vlPoint` into a curve point (essentially a wrapper to `gfUnpack`)

Let's look at `gfPack` briefly.

```c
void gfPack(const gfPoint p, vlPoint k)
	/* packs a field point into a vlPoint */
{
	int i;
	vlPoint a;

	assert (p != NULL);
	assert (k != NULL);
	vlClear (k); a[0] = 1;
	for (i = p[0]; i > 0; i--) {
		vlShortLshift (k, 15);
		a[1] = p[i];
		vlAdd (k, a);
	}
} /* gfPack */
```

As you might notice from `vlShortLshift`, it operates in groups of 15 bits. We will implement `gfPoint2Int` and `int2gfPoint` later, as doing so requires the curve to be defined first.

### First try (failed)

Initially, we (me and @macz) attempted to define the curve as follows and we were surprised to see that it worked like a charm.

```python
sage: F1.<k> = GF(2^15, modulus=x^15+x+1)
sage: F2.<u> = F1.extension(x^17+x^3+1)
sage: b = 0xa1
sage: E = EllipticCurve(F2, [1,0,0,0,F1.from_integer(b)])
```

... but there was a problem:

```python
sage: E.order()
---------------------------------------------------------------------------
KeyError                                  Traceback (most recent call last)
File sage/structure/category_object.pyx:857, in sage.structure.category_object.CategoryObject.getattr_from_category()

KeyError: 'order'

During handling of the above exception, another exception occurred:

AttributeError                            Traceback (most recent call last)

# redacted

AttributeError: 'EllipticCurve_field_with_category' object has no attribute 'order'
```

Calling other methods, such as `E.random_point()`, leads to similar errors.

I was really not satisfied with this result, at all. I wanted to define the curve and be able to do all elliptic curve related thingies without errors. I knew it is possible to define it but I obviously had SageMath skill issue.

It was really a shame because we were even able to verify that $G$ is a point of the curve and do operations with it.

```python
Gi = (0x56fdcbc6a27acee0cc2996e0096ae74feb1acf220a2341b898b549440297b8cc, 0x20da32e8afc90b7cf0e76bde44496b4d0794054e6ea60f388682463132f931a7)

# next lines convert the integers to gf points
Gp = (Gi[0].digits(base=2^15), Gi[1].digits(base=2^15) )
Gx = sum(F1.from_integer(a) * u**i for i, a in enumerate(Gp[0]))
Gy = sum(F1.from_integer(a) * u**i for i, a in enumerate(Gp[1]))

assert E.is_on_curve(Gx, Gy)
```

### Second try

To better understand this method, check my other post about [inverse ring homomorphisms](https://rasti37.github.io/posts/2025-03-07-computing-inverse-ring-homomorphisms-diy/). Bibbidi bobbidi, the curve can be defined as follows without any errors:

```python
F1 = GF(2^15, modulus=[1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1], names='a')
R1 = PolynomialRing(F1, 'y')
y = R1.gen()
IP = y^17 + y^3 + 1
Q = R1.quotient(IP)
SF = IP.splitting_field('z')
b = 0xa1
E = EllipticCurve(SF, [1,0,0,0,F1.from_integer(b)])
```

We can verify this is the correct curve, since $n$ is a factor of the order:

```python
sage: factor(E.order())
2^2 * 3 * 5 * 541 * 1783611972232227286253403958852247502375646797202100661111162374777982257
```

### Final Boss

Having setup the curve, we can now define `gfPoint2Int` and `int2gfPoint`:

```python
def int2gfPoint(n):
    packed = n.digits(base=2**15)
    return sum(F1.from_integer(a) * Q.gen()**i for i, a in enumerate(packed))

def gfPoint2Int(p):
    coeffs = list(p)
    packed_coeffs = [c.to_integer() for c in coeffs]
    return Integer(packed_coeffs, base=2**15)
```

However, another problem arises:

```python
sage: Q = R1.quotient(IP)
sage: Gi = (0x56fdcbc6a27acee0cc2996e0096ae74feb1acf220a2341b898b549440297b8cc, 0x20da32e8afc90b7cf0e76bde44496b4d0794054e6ea60f388682463132f931a7)
sage: Gx = int2gfPoint(Gi[0])
sage: Gy = int2gfPoint(Gi[1])
sage: assert E.is_on_curve(Gx, Gy)
---------------------------------------------------------------------------
TypeError                                 Traceback (most recent call last)
----> 1 assert E.is_on_curve(Gx, Gy)

# redacted

TypeError: unsupported operand parent(s) for *: 'Finite Field in z of size 2^255' and 'Univariate Quotient Polynomial Ring in ybar over Finite Field in a of size 2^15 with modulus y^17 + y^3 + 1'
```

This is where it gets tricky😵.

Let's generate a random curve point and see what it looks like.

```python
sage: E.random_point()
(z^253 + z^252 + z^251 + z^250 + z^249 + z^248 + z^247 + z^246 + z^245 + z^242 + z^241 + z^239 + z^238 + z^237 + z^236 + z^231 + z^230 + z^225 + z^223 + z^222 + z^218 + z^216 + z^215 + z^213 + z^212 + z^211 + z^209 + z^208 + z^206 + z^205 + z^203 + z^200 + z^199 + z^198 + z^196 + z^195 + z^192 + z^188 + z^182 + z^181 + z^178 + z^175 + z^174 + z^172 + z^170 + z^169 + z^166 + z^165 + z^164 + z^163 + z^162 + z^161 + z^160 + z^159 + z^157 + z^155 + z^153 + z^152 + z^150 + z^145 + z^144 + z^143 + z^142 + z^139 + z^138 + z^135 + z^134 + z^129 + z^127 + z^125 + z^123 + z^119 + z^117 + z^115 + z^113 + z^111 + z^110 + z^109 + z^108 + z^105 + z^101 + z^98 + z^97 + z^94 + z^93 + z^92 + z^91 + z^90 + z^89 + z^84 + z^83 + z^82 + z^79 + z^78 + z^77 + z^74 + z^71 + z^70 + z^68 + z^67 + z^63 + z^62 + z^61 + z^60 + z^59 + z^58 + z^50 + z^48 + z^44 + z^42 + z^38 + z^37 + z^36 + z^35 + z^34 + z^31 + z^30 + z^28 + z^23 + z^17 + z^15 + z^14 + z^11 + z^9 + z^7 + z^5 + z^3 + z^2 + 1 : z^254 + z^253 + z^251 + z^249 + z^248 + z^247 + z^245 + z^244 + z^243 + z^242 + z^240 + z^239 + z^236 + z^234 + z^233 + z^232 + z^230 + z^229 + z^224 + z^223 + z^220 + z^219 + z^217 + z^216 + z^215 + z^213 + z^208 + z^206 + z^204 + z^203 + z^199 + z^198 + z^196 + z^195 + z^191 + z^190 + z^187 + z^185 + z^183 + z^182 + z^181 + z^180 + z^178 + z^177 + z^176 + z^174 + z^173 + z^171 + z^170 + z^168 + z^167 + z^165 + z^163 + z^159 + z^156 + z^155 + z^153 + z^151 + z^150 + z^144 + z^141 + z^139 + z^137 + z^136 + z^135 + z^134 + z^131 + z^126 + z^122 + z^118 + z^117 + z^116 + z^111 + z^110 + z^109 + z^107 + z^106 + z^105 + z^103 + z^102 + z^101 + z^97 + z^96 + z^95 + z^93 + z^92 + z^91 + z^88 + z^81 + z^80 + z^77 + z^74 + z^72 + z^68 + z^67 + z^63 + z^61 + z^60 + z^57 + z^56 + z^55 + z^52 + z^51 + z^48 + z^47 + z^46 + z^43 + z^40 + z^38 + z^37 + z^35 + z^33 + z^29 + z^25 + z^24 + z^19 + z^17 + z^11 + z^8 + z^7 + z^6 + z^5 + z^4 + 1 : 1)
```

I thought we were dealing with the field $GF(15^{17})$, where each element is a degree-$17$ polynomial whose coefficients are themselves degree-$15$ polynomials. This is what the elements appear to look like — or at least, that's how $G$ looks after calling `int2gfPoint`:

```python
sage: Gx
(a^14 + a^12 + a^10 + a^9 + a^7 + a^6 + a^5 + a^4 + a^3 + a^2 + 1)*ybar^16 + (a^14 + a^13 + a^10 + a^8 + a^7 + a^6 + a^5 + a + 1)*ybar^15 + (a^13 + a^11 + a^7 + a^4 + a^3 + a^2 + a)*ybar^14 + (a^14 + a^12 + a^11 + a^8 + a^7 + a^6 + a^4 + a^3 + a^2)*ybar^13 + (a^11 + a^10 + a^7 + a^6 + a)*ybar^12 + (a^14 + a^11 + a^10 + a^7 + a^5 + a^4 + a^2 + a + 1)*ybar^11 + (a^5 + a^2 + 1)*ybar^10 + (a^14 + a^12 + a^10 + a^8 + a^7 + a^6 + a^3 + a^2 + a)*ybar^9 + (a^14 + a^11 + a^10 + a^9 + a^8 + a^7 + a^6 + a^5 + a^3 + a + 1)*ybar^8 + (a^11 + a^10 + a^8 + a^6 + a^5 + a^2 + a + 1)*ybar^7 + (a^14 + a^11 + a^7 + a)*ybar^6 + (a^14 + a^10 + a^6 + a^5 + a^3)*ybar^5 + (a^12 + a^11 + a^9 + a^8 + a^7 + a^3 + 1)*ybar^4 + (a^14 + a^10 + a^8 + a^7 + a^5 + a^3 + a)*ybar^3 + (a^13 + a^10 + a^8 + a^4)*ybar^2 + (a^10 + a^8 + a^5 + a^3 + a^2 + a + 1)*ybar + a^13 + a^12 + a^11 + a^7 + a^6 + a^3 + a^2
sage: Gy
(a^13 + a^7 + a^6 + a^4 + a^3 + a)*ybar^16 + (a^12 + a^11 + a^8 + a^6 + a^5 + a^4 + a^2)*ybar^15 + (a^13 + a^11 + a^9 + a^8 + a^7 + a^6 + a^5 + a^4 + a)*ybar^14 + (a^13 + a^8 + a^6 + a^5 + a^3 + a^2 + a + 1)*ybar^13 + (a^14 + a^11 + a^10 + a^9 + a^8 + a^3 + a^2 + a)*ybar^12 + (a^13 + a^12 + a^11 + a^9 + a^8 + a^6 + a^4 + a^3 + a^2 + a)*ybar^11 + (a^14 + a^13 + a^12 + a^11 + a^8 + a^4 + 1)*ybar^10 + (a^12 + a^9 + a^7 + a^6 + a^4 + a^2 + a)*ybar^9 + (a^14 + a^11 + a^10 + a^8 + a^2 + a + 1)*ybar^8 + (a^14 + a^11 + a^9 + a)*ybar^7 + (a^14 + a^12 + a^9 + a^8 + a^7 + a^4 + a^3 + a + 1)*ybar^6 + (a^14 + a^12 + a^10 + a^7 + a^6 + 1)*ybar^5 + (a^14 + a^13 + a^12 + a^9 + a^8 + a^7 + a^3)*ybar^4 + (a^13 + a^12 + a^10 + a^4 + a)*ybar^3 + (a^12 + a^11 + a^7 + a^6 + a^2)*ybar^2 + (a^14 + a^13 + a^10 + a^8 + a^7 + a^6 + a^5 + a^4 + a)*ybar + a^13 + a^12 + a^8 + a^7 + a^5 + a^2 + a + 1
```

$G_x, G_y$ are polynomials in $\text{ybar}$ with the coefficients being polynomials in $a$ but the curve point coordinates are $255$-degree polynomials in $z$.

<img src="reaction.gif" style="width:60%" />

This is exactly when I realized that these two fields, i.e. $GF(2^{255})$ and $GF(15^{17})$, *MUST* be isomorphic and this is how the post about manual inverse homomorphisms was born. For more details, you can refer that [post](https://rasti37.github.io/posts/2025-03-07-computing-inverse-ring-homomorphisms-diy/). For now, trust me bro, we need to slightly modify the implementations of `int2gfPoint` and `gfPoint2Int`. The former should apply the $f$ homomorphism, and the latter should apply its inverse $f^{-1}$:

```python
IP = y**17 + y**3 + 1
domain = R1.quotient(IP)
codomain = IP.splitting_field('z')
y_ = IP.change_ring(codomain).any_root()
f = domain.hom([y_], GF(2**255, 'z'))
# for the implementation of `find_inverse_homomorphism`, check my other post.
finv = find_inverse_homomorphism(f)
```

Recall that the homomorphisms $f, f^{-1}$ are defined as:

$$f : \textbf{F}\_{1}[y] \ / \ (y^{17} + y^3 + 1) \rightarrow \textbf{F}\_{2^{255}} \\\ f^{-1} : \textbf{F}\_{2^{255}} \rightarrow \textbf{F}\_{1}[y] \ / \ (y^{17} + y^3 + 1)$$

where:

$$\textbf{F}\_{1} = \textbf{F}\_{2}[a]\ / \ (a^{15} + a + 1)$$

Finally, we need to modify `int2gfPoint` and `gfPoint2Int` accordingly:

```python
def int2gfPoint(n):
    packed = n.digits(base=2**15)
    return f(sum(F1.from_integer(a) * domain.gen()**i for i, a in enumerate(packed)))
    
def gfPoint2Int(p):
    coeffs = list(finv(p))
    packed_coeffs = [c.to_integer() for c in coeffs]
    return Integer(packed_coeffs, base=2**15)
```

AAAND ... FINALLY:

```python
sage: Gi = (0x56fdcbc6a27acee0cc2996e0096ae74feb1acf220a2341b898b549440297b8cc, 0x20da32e8afc90b7cf0e76bde44496b4d0794054e6ea60f388682463132f931a7)
sage: Gx = int2gfPoint(Gi[0])
sage: Gy = int2gfPoint(Gi[1])
sage: assert E.is_on_curve(Gx, Gy)
sage: Gx
z^254 + z^247 + z^245 + z^242 + z^240 + z^239 + z^235 + z^234 + z^233 + z^231 + z^230 + z^229 + z^226 + z^225 + z^224 + z^222 + z^220 + z^219 + z^216 + z^213 + z^209 + z^208 + z^204 + z^203 + z^202 + z^201 + z^200 + z^199 + z^198 + z^195 + z^194 + z^193 + z^191 + z^189 + z^188 + z^187 + z^183 + z^181 + z^178 + z^177 + z^176 + z^175 + z^174 + z^173 + z^172 + z^171 + z^170 + z^169 + z^168 + z^165 + z^161 + z^159 + z^157 + z^154 + z^152 + z^151 + z^150 + z^149 + z^148 + z^144 + z^141 + z^139 + z^137 + z^135 + z^133 + z^132 + z^131 + z^130 + z^128 + z^127 + z^126 + z^121 + z^118 + z^116 + z^110 + z^109 + z^108 + z^107 + z^106 + z^104 + z^102 + z^101 + z^100 + z^99 + z^95 + z^92 + z^90 + z^88 + z^84 + z^78 + z^76 + z^75 + z^73 + z^72 + z^71 + z^69 + z^68 + z^67 + z^63 + z^62 + z^61 + z^56 + z^52 + z^49 + z^48 + z^45 + z^43 + z^42 + z^41 + z^36 + z^33 + z^32 + z^31 + z^30 + z^28 + z^24 + z^23 + z^22 + z^20 + z^18 + z^16 + z^14 + z^13 + z^12 + z^10 + z^8 + z^7 + z^5 + z^4 + z^3 + z^2 + 1
```

## Implementation Sanity Check

I have grabbed a valid signature from WinRAR (via debugging) for the seed `336606507e63ec734eb7b6f75bd6be1230aa223f0d3dc42c06` and the data `r4sti7a4305372c7833238fdea689fd4c85e7a58864a691b3d2071e795feb60222311`:

```
(0x0dbc977ee85e88a1379778a5461676e6b48818e95accc458a4f70488d85c, 0x67bd89ef91e0b03f90f73331d4bc649dbd14fe05a099616ade42a3b2a6c3)
```

Now, let's run the signature scheme and verify that we get the same signature:

```python
from scheme import NybergRueppelScheme

seed = '336606507e63ec734eb7b6f75bd6be1230aa223f0d3dc42c06'
scheme = NybergRueppelScheme(seed)
r, s = scheme.sign(b'r4sti7a4305372c7833238fdea689fd4c85e7a58864a691b3d2071e795feb60222311')
assert (r, s) == (0x0dbc977ee85e88a1379778a5461676e6b48818e95accc458a4f70488d85c, 0x67bd89ef91e0b03f90f73331d4bc649dbd14fe05a099616ade42a3b2a6c3)
print('[+] thanks for reading :-)')
```

Output:

```
[+] thanks for reading :-)
```

# BONUS

After writing the post about inverse homomorphism computation, I decided to make a [pull request](https://github.com/sagemath/sage/pull/39709) to SageMath to add this missing feature and I was really happy that they accepted it😄. Extra kudos to @grhkm for his advice and suggestions for improvement🎉.

You can find my SageMath commit [here](https://github.com/sagemath/sage/commit/11ae3b1047af25849676a1073d8a938c1ea3db9f) and the full Python implementation on my GitHub [repository](https://github.com/rasti37/WinRAR-Signature-Scheme-SageMath-Implementation).

If you want to chat about anything, my Discord handle is `r4sti`, cya!