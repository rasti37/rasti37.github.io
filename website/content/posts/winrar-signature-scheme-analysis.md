---
title: "Deep Dive into WinRAR's Signature Scheme"
date: 2025-03-08T22:52:50+02:00
slug: 2025-03-08-winrar-signature-scheme-analysis
type: posts
draft: true
katex: false
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

Upon reverse engineering WinRAR to understand its internal workings and how the license key validation works, I discovered that all the latest versions utilise a pretty ancient library for performing public key encryption and authentication — namely [`Pegwit (v8)`](https://web.archive.org/web/19990117082016/http://ds.dial.pipex.com:80/george.barwood/v8/pegwit.htm). Thankfully, its source code has now been uploaded to [Github](https://github.com/t-crest/patmos-benchmarks/tree/master/Mediabench/pegwit/src) so no need for the reader to hassle with a local copy.

Pegwit implements Elliptic Curve Cryptography (ECC) in the finite field $\mathbb{F}_{2^{255}}$ and uses a variant of the Nyberg-Rueppel signature scheme for signing and verifying data. There will be a separate post entirely dedicated to WinRAR so we won't dive into more detail here. So ... where is the problem? I would be pretty happy if I just sticked with the library's arithmetic and didn't attempt to reimplement this signature scheme in *SageMath*. This is where the problems arose.

Languages like C can usually do arithmetic up to $64$ bits (or $32$ depending on the architecture) but usually in cryptography we work with much larger numbers so there must be a way to do arithmetic and store such large numbers efficiently in memory without any data loss. For this purpose, the pegwit library defines two fundamental structures; namely `vlPoint` (very long point) and `gfPoint` (galois field point).
