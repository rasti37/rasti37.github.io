---
title: "(Crypto) Backdoor CTF 2024 - Hashing Frenzy"
date: 2025-03-01T04:16:04+02:00
slug: 2025-03-01-backdoor-ctf-2024-hashing-frenzy-writeup
type: posts
draft: false
katex: true
summary: 'Hashing Frenzy was a cool challenge related to problem solving via lattice reduction techniques. My goal is to showcase some of the intuition required to translate linear equations to instances of lattice problems.'
categories:
  - ctf-writeups
tags:
  - ctf-writeups
  - crypto
  - LLL
---

{{< toc >}}

<html>
<style>
    table, td, th {  
        border: 1px solid #ddd;
        text-align: center;
    }
    table {
        border-collapse: collapse;
        margin: 0 auto;
    }
    th, td {
        padding: 7px;
    }
</style>
    <table>
      <tbody>
        <tr>
          <td><b>Category</b></td>
          <td>Crypto</td>
        </tr>
        <tr>
          <td><b>CTF</b></td>
          <td><a href="https://ctftime.org/event/2540/" target="_blank" class='header-footer-anchor'>BackdoorCTF</a></td>
        </tr>
        <tr>
          <td><b>Year</b></td>
          <td>2024</td>
        </tr>
        <tr>
          <td><b>Solves</b></td>
          <td>24</td>
        </tr>
        <tr>
          <td><b>Challenge Author</b></td>
          <td><code>kh4rg0sh</code></td>
        </tr>
      </tbody>
    </table>
</html>

# Description

I like the idea of trapdoor functions, so I decided to take the practice of hashing for security to the extreme.

# Synopsis

For the passers-by, there were two significant steps for solving this challenge.

- Recover the prime $p$ by signing two messages and then computing the $\text{GCD}$ of the differences of the reduced and unreduced accumulate values. Sometimes, the primality testing returned false so it was needed to eliminate some small factors too.
- Build a lattice using the $6$ flag signatures, the accumulate value and the prime $p$ to solve for the unknowns. One of these unknowns was the flag in plaintext and the rest were just hash digests of the flag from various hash functions.

# Analyzing the source code

Let's analyze the source [code](https://github.com/rasti37/CTF-Writeups-and-Notes/blob/main/crypto/BackdoorCTF%202024/Hashing%20Frenzy/src/main.py) to figure out how we can obtain the flag.

```python
from flag import flag

def menu():
    print("1. Sign a message")
    print("2. Verify a Signature for a message")

welcome_message = '''Welcome to My Extra Hashes Extra Secure Edition of my very own Message Signature and Verification Scheme. Since it's a good practice to use secure hashes, I've combined multiple hashes in this scheme.'''
print(welcome_message)

testing_message = '''To prove that the scheme works, i'll test it with a sample message.'''
print(testing_message)

signatures = generate_signatures(flag)
print(signatures)

if verify_signature(flag, signatures):
    print("Signature Verified! Your turn. The functions that are allowed are: ")
else:
    print("Signature Verification Failed!")
    exit(0)

menu()
```

The flag is used to generate some signatures and then these signatures are verified along with the flag. This works as a proof of correctness and will always return true. After that, we are asked to either sign our own message or verify our signatures for a given message.


```python
for _ in ['_', '__']:
    if _ == '_':
        print("Let's sign a message!")
    else:
        print("Now let's verify the signature!")
    response = ask() 

    if response == 1:
        message = str(input("Please enter the message to be signed: ")).encode('utf-8')

        signatures = generate_signatures(message)
        print(signatures)

    else: 
        message = str(input("Please enter the message to be verified: ")).encode('utf-8')
        signatures = list(map(int, input("Please enter the signature to be verified: ").split()))

        try:
            if len(signatures) == len(hashes) + 1:
                if verify_signature(message, signatures):
                    print("Signature Verified!")
                else:
                    print("Signature Verification Failed!")
                    exit(0)
        except:
            exit(0)
```

This loop runs two times and is intended to work in a specific manner; the first time, we sign a message and get the corresponding signatures and the second time we verify these signatures along with the message.

But, who said we must follow the intended way? Our response is not restricted so we can use it to sign messages two times or verify signatures two times. More to that, later on 😎.

## How the signatures are generated

The function that generates the signatures is the following:
```python
def generate_signatures(message):
    signatures = []
    accumulate = 0
    
    for hash_object in hashes:
        signatures.append(random.randint(2, p - 1))
        accumulate += bytes_to_long(hash_object(message).digest()) * signatures[-1] % p

    signatures.append(accumulate)
    return signatures
```

There is a loop that iterates over a `hashes` object. This object is initialized in the beginning of the script:

```python
import hashlib

class testhash:
    def __init__(self, data):
        self.data = data

    def digest(self):
        return self.data 

## more hashes, more security
hashes = []
hashes.append(testhash)
hashes.append(hashlib.md5)
hashes.append(hashlib.sha224)
hashes.append(hashlib.sha256)
hashes.append(hashlib.sha3_224)
hashes.append(hashlib.sha3_256)
```

This is basically a list of 6 elements where each element is a different hash function. The first one being a custom one where the digest $H(m)$ is just $M$. The rest functions are `MD5`, `SHA224`, `SHA256`, `SHA3-224` and `SHA3-256` with corresponding digest bit lengths: $128, 224, 256, 224, 256$.
For brevity, we will denote the `hashes` list as $h$. Note that the bit length of $h_0(\text{flag})$ as well as $h_i(\text{flag})$ are unknown since we don't have any information about the flag.

Back to the signature generation function, at iteration $i$, a random number $s_i$ is generated in $[2,\ p-1]$ and used to compute an accumulate value ($\text{A}$) $\in \mathbb{F}_p$ along with $h_i$. The signature generation process for a message $m$ can be described algebraically as:

$$A = s_6 = s_0h_0(m) + s_1h_1(m) + s_2h_2(m) + s_3h_3(m) + s_4h_4(m) + s_5h_5(m) \pmod p$$

or

$$
A = s_6 = \sum_{i = 0}^5{s_ih_i(m)} \pmod p
$$

for short.

where $s_i$ are always known and $h_i(m)$ are known only when we sign our own message. From now on, we omit $(m)$ and we write only $h_i$.

At this point, it's important to note that $p$ is a random $2048$-bit prime which is changed per connection and *is unknown*.

$p$ is essential as it is required to define $\mathbb{F}_p$ so it would be a good idea to recover it before moving on getting the flag.

# Solution

The rest of the writeup contains the solution of the challenge.

## Recovering the prime modulus

We mentioned earlier that we do not have to use the protocol as intended. We only have two options and instead of being obedient and sending $(1)$ and then $(2)$, we could send $(1)$ and $(1)$ or $(2)$ and $(2)$.

However, we don't get much information about $p$ if we send $(2)$ two times, only whether the signature is verified or not. Let's focus on the first plan.

Let's look at the signature formula for two messages $m_1, m_2$:

$$
\begin{aligned}
A_1 = \sum_{i = 0}^5 {s_ih_i} \pmod p \\\\
A_2 = \sum_{i = 0}^5 {s'_ih'_i} \pmod p
\end{aligned}
$$

where $h_i, h'_i, s_i, s'_i, A_1, A_2$ are known.

Moving the right hand side in the left hand side, we get...

$$
\begin{aligned}
A_1 - \sum_{i = 0}^5 {s_ih_i} = 0 \pmod p =  k_1p \\\\
A_2 - \sum_{i = 0}^5 {s'_ih'_i} = 0 \pmod p = k_2p
\end{aligned}
$$

... in other words, two multiples of the prime $p$. Does this ring a bell? Thanks to the one and only Euclid, we can use the GCD to recover the prime $p$ as:

$$
p = \text{GCD}(A_1 - \sum_{i = 0}^5 {s_ih_i},\ A_2 - \sum_{i = 0}^5 {s'_ih'_i})
$$

The sums are computed without reduction $\pmod p$ and $A_1, A_2$ are the corresponding reduced values $\pmod p$.

However, note the $k_1, k_2$. Sometimes the obtained $p$ will not be prime, this is due to the GCD returning $p$ multiplied with some small constant. We can simply iterate over the first $10^6$ integers ($10^4$ or $10^5$ could work too), check if they are divisible by $p$, and eliminate them by division. Let's write some code for this.

```python
def generate_nonreduced_accumulate(message, sigs):
    accumulate = 0
    for i, hash_object in enumerate(hashes):
        sig = sigs[i]
        accumulate += bytes_to_long(hash_object(message).digest()) * sig
    return accumulate

def get_data():
    io.recvuntil(b'with a sample message.\n')
    flag_sigs = eval(io.recvline().strip().decode())
    io.sendlineafter(b"choice: ", b'1')
    io.sendlineafter(b"signed: ", msg)
    m1_sigs = eval(io.recvline().strip().decode())
    io.sendlineafter(b"choice: ", b'1')
    io.sendlineafter(b"signed: ", msg)
    m2_sigs = eval(io.recvline().strip().decode())
    return flag_sigs, m1_sigs, m2_sigs

def recover_p(accumulate1, accumulate2, m1_sigs, m2_sigs):
    p = GCD(accumulate1 - m1_sigs[-1], accumulate2 - m2_sigs[-1])
    
    # eliminate small factors
    for i in range(2, 10**6):
        if p % i == 0:
            p //= i
            
    if isPrime(p) and 2047 <= p.bit_length() <= 2048:
        return p
    else:
        print('[-] fail')


msg = b'r4sti'

io = remote('34.42.147.172', 8007, level='error')
flag_sigs, m1_sigs, m2_sigs = get_data()

accumulate1 = generate_nonreduced_accumulate(msg, m1_sigs)
accumulate2 = generate_nonreduced_accumulate(msg, m2_sigs)

p = recover_p(accumulate1, accumulate2, m1_sigs, m2_sigs)

print(f'{p = }')
```

## Obtaining the flag (Lattice Reduction time = Best time)

The heading should already give you a first idea of the approach to obtain the flag. This section will try to build some intuition on problems that can be solved via lattice reduction techniques and how to approach such problems. We will know focus only on the signatures generated by $\text{M = flag}$.

First things first, let's rewrite the signature generation formula for reference, as well as what we know about each signature-related component:

$$
A = s_6 = \sum_{i = 0}^5{s_ih_i} \pmod p \quad \quad (1)
$$

where,

- $A,\ s_i,\ p$ are $2048$ bits ($< 2^{2048}$)
- $h_0$ has unknown size. We set a hypothetical upper bound of $2^{256}$ which corresponds to a $32$-byte flag.
- $h_1$ is $128$ bits ($< 2^{128}$)
- $h_2$ is $224$ bits ($< 2^{224}$)
- $h_3$ is $256$ bits ($< 2^{256}$)
- $h_4$ is $224$ bits ($< 2^{224}$)
- $h_5$ is $256$ bits ($< 2^{256}$)

This is usually the setup of a problem that requires lattice reduction to be solved; *the unknowns $h_i$ are small compared to the modulus and the rest components of the equation*. In fact, being $256$ bits while the modulus is $2048$ bits means that the top $2048-256=1792$ bits are just $0$. This is a large portion of the secret information that is leaked and is more than enough to recover the unknowns using LLL.

Let the following lattice spanned by-

No, I am joking. I will get into much detail, hoping that my thought process will be fully understood.

Lattices involve matrices and vectors so let's rewrite $(1)$ as the dot product of two vectors:

$$
A =
\begin{pmatrix}
s_0 & s_1 & s_2 & s_3 & s_4 & s_5
\end{pmatrix}
\cdot
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 & h_4 & h_5
\end{pmatrix}
\pmod p
$$

We will substitute $\pmod p$ with $kp$ where $k$ some integer. Then,

$$
A =
\begin{pmatrix}
s_0 & s_1 & s_2 & s_3 & s_4 & s_5 & p
\end{pmatrix}
\cdot
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 & h_4 & h_5 & k
\end{pmatrix}
$$

Moreover, let's move everything to the LHS and set the RHS to $0$. We will see later why we want this. Finally:

$$
\begin{pmatrix}
s_0 & s_1 & s_2 & s_3 & s_4 & s_5 & p & -A
\end{pmatrix}
\cdot
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 & h_4 & h_5 & k & 1
\end{pmatrix}
= 0
$$

The second vector contains all the unknowns while the first is known. We have 6 unknown $h_i$ but only one linear relation which is not enough to use Gaussian elimination.

### Setting up the lattice (SVP Approach)

The difficulty in lattice challenges is to figure out how to construct the lattice so that when reduced by LLL, we end up with our target vector. To construct a lattice, we need multiple vectors (i.e. a matrix) and not just a single vector. The question to ask yourself for finding the right lattice is:

*What matrix should be multiplied with the vector of the unknowns to end up with a target vector that includes some or all of the unknowns?*

Our unknown vector now is $\begin{pmatrix}h_0 & h_1 & h_2 & h_3 & h_4 & h_5 & k & 1\end{pmatrix}$ and our target vector should contain at least $h_i$. This is where the identity matrix comes in. Think of the following example with fewer unknowns:

$$
h_0
\cdot
\begin{pmatrix}
1\\\
0\\\
0
\end{pmatrix}
+
h_1
\cdot
\begin{pmatrix}
0\\\
1\\\
0
\end{pmatrix}
+
h_2
\cdot
\begin{pmatrix}
0\\\
0\\\
1
\end{pmatrix}
=\\
\begin{pmatrix}
h_0\cdot 1 + h_1 \cdot 0 + h_2 \cdot 0\\\
h_0\cdot 0 + h_1 \cdot 1 + h_2 \cdot 0\\\
h_0\cdot 0 + h_1 \cdot 0 + h_2 \cdot 1\\\
\end{pmatrix}
=\\
\begin{pmatrix}
h_0\\\
h_1\\\
h_2\\\
\end{pmatrix}
$$

In other words, this is equivalent to the following vector-matrix multiplication:

$$
\begin{pmatrix}
h_0 &
h_1 &
h_2
\end{pmatrix}
\begin{bmatrix}
1 & 0 & 0\\\
0 & 1 & 0\\\
0 & 0 & 1
\end{bmatrix}
=\\
\begin{pmatrix}
h_0\\\
h_1\\\
h_2
\end{pmatrix}
$$

It should be clear that using the identity matrix, results in the unknowns being part of the target vector.

In our case, the unknowns are $6$ so consider the following:

$$
h_0
\begin{pmatrix}
1\\\
0\\\
0\\\
0\\\
0\\\
0\\\
s_0\\\
\end{pmatrix}
+
h_1
\begin{pmatrix}
0\\\
1\\\
0\\\
0\\\
0\\\
0\\\
s_1\\\
\end{pmatrix}
+
h_2
\begin{pmatrix}
0\\\
0\\\
1\\\
0\\\
0\\\
0\\\
s_2\\\
\end{pmatrix}
+
h_3
\begin{pmatrix}
0\\\
0\\\
0\\\
1\\\
0\\\
0\\\
s_3\\\
\end{pmatrix}
+
h_4
\begin{pmatrix}
0\\\
0\\\
0\\\
0\\\
1\\\
0\\\
s_4\\\
\end{pmatrix}
+
h_5
\begin{pmatrix}
0\\\
0\\\
0\\\
0\\\
0\\\
1\\\
s_5\\\
\end{pmatrix}
+
k
\begin{pmatrix}
0\\\
0\\\
0\\\
0\\\
0\\\
0\\\
p\\\
\end{pmatrix}
+
1
\begin{pmatrix}
0\\\
0\\\
0\\\
0\\\
0\\\
0\\\
-A\\\
\end{pmatrix}
=\\
\begin{pmatrix}
h_0\\\
h_1\\\
h_2\\\
h_3\\\
h_4\\\
h_5\\\
0\\\
\end{pmatrix}
$$

We transposed the matrix because in SageMath, [the lattice is spanned by each row](https://doc.sagemath.org/html/en/reference/matrices/sage/matrix/matrix_integer_dense.html#sage.matrix.matrix_integer_dense.Matrix_integer_dense.LLL):

> Return LLL-reduced or approximated LLL reduced matrix of the lattice generated by the rows of self.

Therefore, our vectors should be the rows of the matrix:

$$
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 & h_4 & h_5 & k & 1
\end{pmatrix}
\cdot
\begin{bmatrix}
1 & 0 & 0 & 0 & 0 & 0 & s_0\\\
0 & 1 & 0 & 0 & 0 & 0 & s_1\\\
0 & 0 & 1 & 0 & 0 & 0 & s_2\\\
0 & 0 & 0 & 1 & 0 & 0 & s_3\\\
0 & 0 & 0 & 0 & 1 & 0 & s_4\\\
0 & 0 & 0 & 0 & 0 & 1 & s_5\\\
0 & 0 & 0 & 0 & 0 & 0 & p\\\
0 & 0 & 0 & 0 & 0 & 0 & -A\\\
\end{bmatrix}
=\\
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 & h_4 & h_5 & 0
\end{pmatrix}
$$

A lattice is just a set that includes all the linear combinations of its bases vectors. Constructing the matrix above, we see that the target vector is part of this set, for *some* linear combination coefficients. LLL can find this target vector, if the matrix is good enough... whatever *good* means.
Let's construct this matrix and reduce it with LLL. Hopefully, the first row of the reduced matrix is our solution vector.

```python
M = block_matrix([
        [identity_matrix(6), matrix(H).T],
        [zero_matrix(2, 6) , matrix([p, -A]).T]
    ], subdivide=False)
```

(Kudos to `Blupper` 🔥 for showing me the `block_matrix` function 💯)

Let's reduce it with LLL:

```python
sage: L = M.LLL()
sage: for i in L:
....:     print(i)
....:
(0, 0, 0, 0, 0, 0, 0)
(0, 0, 0, 0, 0, 0, 1)
(1, 0, 0, 0, 0, 0, 0)
(0, 0, 0, 1, 0, 0, 0)
(0, 0, 0, 0, -1, 0, 0)
(0, 0, 0, 0, 0, -1, 0)
(0, 0, 1, 0, 0, 0, 0)
(0, 1, 0, 0, 0, 0, 0)
```

... 🤔. This definitely does not look like the flag, or anything close to it, at all. 

What happened here?

### Weighting the lattice

The problem is here:

$$
1
\begin{pmatrix}
0\\\
0\\\
0\\\
0\\\
0\\\
0\\\
-A\\\
\end{pmatrix}
$$

The coefficients of all the other vectors are big ($\simeq 2^{256}$) but the coefficient of the vector above is just $1$. At the same time $-A$ is the only non-zero element of the vector which, it turns out that, results in LLL somehow low-prioritizing this vector. We need to make it as big as the other vectors. This can be achieved by adding an extra element in the vector which is known as a **scaling factor**. Let $B = 2^{256}$ be the scaling factor. Then:

\\[
1
\begin{pmatrix}
0\\\
0\\\
0\\\
0\\\
0\\\
0\\\
B\\\
-A\\\
\end{pmatrix}
\\]

Now, the target vector is derived as:

$$
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 & h_4 & h_5 & k & 1
\end{pmatrix}
\cdot
\begin{bmatrix}
1 & 0 & 0 & 0 & 0 & 0 & 0 & s_0\\\
0 & 1 & 0 & 0 & 0 & 0 & 0 & s_1\\\
0 & 0 & 1 & 0 & 0 & 0 & 0 & s_2\\\
0 & 0 & 0 & 1 & 0 & 0 & 0 & s_3\\\
0 & 0 & 0 & 0 & 1 & 0 & 0 & s_4\\\
0 & 0 & 0 & 0 & 0 & 1 & 0 & s_5\\\
0 & 0 & 0 & 0 & 0 & 0 & B & -A\\\
0 & 0 & 0 & 0 & 0 & 0 & 0 & p\\\
\end{bmatrix}
=\\
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 & h_4 & h_5 & B & 0
\end{pmatrix}
$$

We chose $B = 2^{256}$ because this is the upper bound of $h_i$.

Let's try again with the new matrix:

```python
B = 2**256
M = block_matrix([
        [identity_matrix(7), matrix(H + [-A]).T],
        [zero_matrix(1, 7) , matrix([p])]
    ], subdivide=False)
M[-2, -2] = B    # set scaling factor
L = M.LLL()

for row in L:
    # the solution vector should end with (..., B, 0)
    if row[-2:] == vector([B, 0]):
        print(row)
```

Output:

```python
(706900059475064292686386702602426630444324681379114804503951298062869885, 10308638735736053502715051302631358691, 4752919295672183050936727141176117974827669306505970380425030364810, 14487800823220630104530546639228420223998682568934955015092250740112699729525, 8295957536049799636308491371051629069883338278363081922835789737524, 92731167790612205135291774049473551292159822402063205170980856740372630056525, 115792089237316195423570985008687907853269984665640564039457584007913129639936, 0)
```

*Surprisingly, while writing this writeup, I noticed that even if I omit `M[-2, -2] = B`, LLL still returns the solution vector. The only crucial change was adding an additional column in the matrix; that is the second from last column*.

Recall that $h_0$ should be the flag in plaintext. Indeed:

```python
>>> Crypto.Util.number import long_to_bytes
>>> long_to_bytes(706900059475064292686386702602426630444324681379114804503951298062869885)
b'flag{more_hashes!=more_secure}'
```

That's it! 😊

Here is a function that does everything we said above:

```python
def svp_approach(H, A, p):
    B = 2**256
    M = block_matrix([
            [identity_matrix(7), matrix(H + [-A]).T],
            [zero_matrix(1, 7) , matrix([p])]
        ], subdivide=False)
    M[-2, -2] = B    # set scaling factor (turns out this is optional)
    L = M.LLL()
    assert L[0][-2:] == vector([B, 0])
    flag = abs(int(L[0][0]))
    return long_to_bytes(flag)
```

### Alternative lattice setup (CVP Approach)

We are not done yet. During the contest, I was not able to solve it with the SVP approach described in the previous section. In fact, I managed to solve it with the CVP approach which I will describe quite briefly below.

CVP stands for `Closest Vector Problem` while `SVP` for `Shortest Vector Problem`. Informally, and hopefully without making any mistakes, we can say that the SVP is more strict than CVP as it looks for the *shortest* vector while CVP looks for the *closest* one. Naturally, we understand that SVP must be more precise, while CVP is more loose.

In a nutshell, the CVP receives a lattice basis B and a target vector $t$ and returns the closest lattice vector to $t$. 

For the CVP approach we use a similar lattice as before but now, we will not bother with the scaling factor at all, we will just remove the vector with $-A$ and add $A$ to the target vector. Consider the following:

$$
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 & h_4 & h_5 & k
\end{pmatrix}
\cdot
\begin{bmatrix}
1 & 0 & 0 & 0 & 0 & 0 & s_0\\\
0 & 1 & 0 & 0 & 0 & 0 & s_1\\\
0 & 0 & 1 & 0 & 0 & 0 & s_2\\\
0 & 0 & 0 & 1 & 0 & 0 & s_3\\\
0 & 0 & 0 & 0 & 1 & 0 & s_4\\\
0 & 0 & 0 & 0 & 0 & 1 & s_5\\\
0 & 0 & 0 & 0 & 0 & 0 & p\\\
\end{bmatrix}
$$

We know this multiplication results in the vector:

$$
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 & h_4 & h_5 & A
\end{pmatrix}
$$

The good thing with CVP is that our target vector can be just the bounds of each of $h_i$. Since $h_i$ are close to $2^{256},\ 2^{128},\ 2^{224},\ 2^{256},\ 2^{224}$ and $2^{256}$ respectively, then the following two vectors should be *close enough*.

$$
\begin{pmatrix}
2^{256} & 2^{128} & 2^{224} & 2^{256} & 2^{224} & 2^{256} & A
\end{pmatrix}
\simeq
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 & h_4 & h_5 & A
\end{pmatrix}
$$

This enables CVP to find the second one which is our solution vector.

For solving the CVP, we will use a popular algorithm called `Babai's Nearest Plane algorithm` and for the time being, we treat it as black-box.

```python
def Babai_CVP(B, target):
    assert B.ncols() == len(target)
    from sage.modules.free_module_integer import IntegerLattice
    M = IntegerLattice(B, lll_reduce=True).reduced_basis
    G = M.gram_schmidt()[0]
    small = target
    for i in reversed(range(G.nrows())):
        small -= M[i] * ((small * G[i]) / (G[i] * G[i])).round()
    return target - small
```

Let's construct the matrix in SageMath and run Babai's algorithm.

```python
M = block_matrix([
        [identity_matrix(6), matrix(H).T],
        [zero_matrix(1, 6) , matrix([p])]
    ], subdivide=False)

target = vector(ZZ, [2**256, 2**128, 2**224, 2**256, 2**224, 2**256, A])

print(Babai_CVP(M, target))
```

Output:

```python
(706900059475064292686386702602426630444324681379114804503951298062869885, 10308638735736053502715051302631358691, 4752919295672183050936727141176117974827669306505970380425030364810, 14487800823220630104530546639228420223998682568934955015092250740112699729525, 8295957536049799636308491371051629069883338278363081922835789737524, 92731167790612205135291774049473551292159822402063205170980856740372630056525, 48911170339932108013619485718407510367892447794792267935080828550259429009087094840546760649202737768887965367560824173815925167093584802995045480901320956581560002877396753186042687762670165406679210923009588244233506723056455864861467069619305079410363205804749852406712544677581254447296668231428972773607666397098772112388048760495377779243295009939980812022921662292510172072761693027121859641367893074500696251520030604911216339485263866502885184043858887300510599875422170899443259698459346020550049153415005928378278014411878775673693125888128402223380942730091302013331151085677287180296798600807422752017057)
```

Again:

```python
>>> Crypto.Util.number import long_to_bytes
>>> long_to_bytes(706900059475064292686386702602426630444324681379114804503951298062869885)
b'flag{more_hashes!=more_secure}'
```

Let's write a SageMath function that recovers the flag using Babai algorithm.

```python
def cvp_approach(H, A, p):
    M = block_matrix([
        [identity_matrix(6), matrix(H).T],
        [zero_matrix(1, 6), matrix([p])]
    ], subdivide=False)
    target = vector(ZZ, [2**256, 2**128, 2**224, 2**256, 2**224, 2**256, A])
    R = Babai_CVP(M, target)
    flag = abs(int(R[0]))
    return long_to_bytes(flag)
```

You can find a full working solve script [here](https://github.com/rasti37/CTF-Writeups-and-Notes/blob/main/crypto/BackdoorCTF%202024/Hashing%20Frenzy/solve.py).

# Conclusion

I think this challenge really showcases the power of lattice reduction techniques and what happens when large portions of the secret information, are known. If you find any mistake in this writeup, feel free to reach out in Discord; my handle is `r4sti`.

See ya next time! 😎