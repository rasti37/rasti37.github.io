---
title: "V8 Engine Version Detection"
date: 2025-07-16T03:22:02+03:00
slug: 2025-07-16-v8-engine-version-detection
type: posts
draft: true
katex: false
summary: 'This is test summary'
categories:
  - real-world
  - projects
tags:
  - real-world
---

#notaigenerated

{{< toc >}}

# Introduction

- What you WILL read in this post:

How I wrote a v8 version detector for Bytenode Compiled JavaScript files (`.jsc`). This required extensive auditing of the v8 engine's codebase, as well as good understanding of some undocumented v8 internals. Its source code can be found in the official GitHub [mirror](https://github.com/v8/v8). I believe that the research process and the problems I dealt with are kinda interesting to include in a post. My ultimate goal is to make a post that I WOULD LOVE to read while I was trying to complete this project.

- What you WON'T read in this post:

Identifying or exploiting any vulnerability in the v8 engine or the `Bytenode` Node.js package.

# \<Journey\>

Everything started when I encountered a `jsc` file with JS bytecode that I had to figure out what it does. By minimal researching, I found [this](https://swarm.ptsecurity.com/how-we-bypassed-bytenode-and-decompiled-node-js-bytecode-in-ghidra/) incredible post by Sergey Fedonin which pretty much explained perfectly what I wanted to do - decompile a `jsc` file. In their next post, his colleague, Vladimir, presents the ghidra [plugin](https://github.com/PositiveTechnologies/ghidra_nodejs/) he and his team built for decompiling javascript bytecode. Little did I know that it wouldn't be that easy.

Before we continue, it's important to keep in mind that Bytenode is a Node.js package and, under the hood, Node.js utilizes the V8 engine to run JavaScript code. Therefore, the opcodes and the bytecode interpreter are components of the v8 engine so they heavily depend on the *version* of the V8 that is used to compile the JavaScript code. For example, the opcodes for the current V8 version (13.7.152.14) can be found [here](https://github.com/nodejs/node/blob/main/deps/v8/src/interpreter/bytecodes.h). By navigating through older V8 versions, you will find small and seemingly negligible differences which however, turn out to be critical for the efficiency of a decompiler or even a disassembler.

At this point, I am cooked for two reasons <s>more actually but nvm</s>:

- `ghidra_nodejs` works only with v8 version `6.2.414.77`
- I don't know which v8 was used to compile the sample I was analyzing.

I thought, *only if I knew the exact v8 version, then I could checkout the corresponding branch on GitHub and properly modify `ghidra_nodejs` so that I can decompile my sample*. Yeah - no. This project is enormous and requires very good understanding of Ghidra's decompiler internals and its codebase which was a huge extra step I had to take. The v8 version used to produce a jsc file is embedded into its header and the linked article explains how to identify that. In this blog post, we 'll work with [this](http://github.com/PositiveTechnologies/ghidra_nodejs/blob/main/samples/nodejs_x64/sample1_x64.jsc) sample.

| Offset | No. of bytes | Value | Description |
|:------:|:------------:|:----:|:------------:|
| `0x00` | `0x04` | kMagicNumber | The value `0xC0DE0000` ^ `ExternalReferenceTable::kSize` (see [here](https://github.com/v8/v8/blob/main/src/snapshot/snapshot-data.h#L46)) |
| `0x04` | `0x04` | kVersionHash | The v8 version hash (bingo!) |
| `0x08` | `0x04` | kSourceHash | The length of the source JS script in bytes |

: The x64 jsc header layout

These values are set in `SerializedCodeData` as you can see [here](https://github.com/v8/v8/blob/main/src/snapshot/code-serializer.cc#L745).