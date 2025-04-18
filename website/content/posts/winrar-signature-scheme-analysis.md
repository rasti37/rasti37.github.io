---
title: "Deep Dive into WinRAR's Signature Scheme"
date: 2025-03-08T22:52:50+02:00
slug: 2025-03-08-winrar-signature-scheme-analysis
type: posts
draft: true
katex: true
summary: 'This is test summary'
categories:
  - projects
tags:
  - real-world
  - sage
  - reverse-engineering
---

{{< toc >}}

# Introduction

Upon reverse engineering WinRAR to understand its internal workings and how the license key validation works, I discovered that all versions utilise a pretty ancient library for performing public key encryption and authentication — namely [`Pegwit (v8)`](https://web.archive.org/web/19990117082016/http://ds.dial.pipex.com:80/george.barwood/v8/pegwit.htm). Thankfully, its source code has now been uploaded to [Github](https://github.com/t-crest/patmos-benchmarks/tree/master/Mediabench/pegwit/src) so no need for the reader to hassle with a local copy.

Pegwit implements Elliptic Curve Cryptography (ECC) over finite fields and uses a variant of the Nyberg-Rueppel signature scheme for signing and verifying data. During my reversing, I wasn't able to find any SageMath implementation (or python at all) of the WinRAR signature scheme so this is where the fun began. By the way, this post was my main source of inspiration and motivation for making my previous post about [Inverse Ring Homomorphisms](https://rasti37.github.io/posts/2025-03-07-computing-inverse-ring-homomorphisms-diy/). We'll see how this is related shortly.

In this post, we will dive into how WinRAR's signature scheme works and we will re-implement it in SageMath.

# Signature Scheme Overview

Let $E$ be an elliptic curve with the following equation:

$$
E : y^2 + xy = x^3 + 161
$$

defined over the finite field $K = \text{GF}((2^{15})^{17})$. Using SageMath, we find the order of $E$ (more on how, later):

$$
q = 57896044618658097711785492504343953927113495037180187459668330685293304062220
$$

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

$$
r = [k \cdot G]_x + h \pmod n\\\
s = k - r \cdot x \pmod n
$$
Final signature: $(r,s)$

## Signature Verification Algorithm Overview

Given a signature $(r,s)$, the hash digest $h = H(M)$ and the public key $P = x \cdot G$, the equation for verification is shown below:

$$r - [s \cdot G + r \cdot P]_x \stackrel{?}{=} h$$

### Proof of Correctness

Why does this equation verify the signature? Working with the left-hand side, our goal is to end up with $h$. That would mean that the equation holds.

First, let's substitute $P$ with $x \cdot G$:

$$r - [s \cdot G + r \cdot x \cdot G]_x = r - [(s + r \cdot x) \cdot G]_x$$

Then, we substitute $s$:

$$r - [(k - r \cdot x + r \cdot x) \cdot G]_x = r - [k \cdot G]_x$$

Looking at how $r$ is defined, we know that:

$$h = r - [k \cdot G]_x$$

This concludes the proof.