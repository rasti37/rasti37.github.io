---
title: "Computing Inverse Ring Homomorphisms (DIY)"
date: 2025-03-07T00:01:27+02:00
slug: 2025-03-07-computing-inverse-ring-homomorphisms-diy
type: posts
draft: false
katex: true
summary: 'In this post, I provide a detailed explanation of how to manually define the inverse ring homomorphism in SageMath, mapping a quotient ring over a finite field to a finite extension field of the same characteristic.'
categories:
  - projects
tags:
  - real-world
  - sage
---

{{< toc >}}

# Introduction

In this post, we will get our hands dirty with applied abstract algebra. Mathematical resources usually lack practical examples which would significantly amplify the learning experience of the readers. This post aims at bridging the gap between programming and mathematics. Thankfully, there is already such a robust bridge, namely [SageMath](https://www.sagemath.org/), but (un)fortunately for me, it didn't include an implementation for what I wanted to achieve. Thereby, I had to do it myself👷.

I'm not a mathematician so there might be loose ends here and there. But hey, as long as we grasp the main idea, that's all that really matters. Notation is for the pros and I'm definitely not claiming to be one :)

# The problem statement

My initial goal was to reimplement WinRAR's signature scheme in SageMath and I thought I was nearly done — until I hit the final boss. There's an entire blog post in the pipeline, entirely dedicated to how WinRAR signs and verifies data, so stay tuned :)

Our current problem can be briefly stated as:

> SageMath doesn't provide a way to compute the inverse ring homomorphism when the domain is a quotient polynomial ring over some finite field and the codomain is a finite field of the same degree.

# Mathematical Notation

We will use the following notation:

- $\mathbb{F}_{p}$. The finite field of prime order $p$.
- $\mathbb{F}_{p^n}$. The composite field over the finite field $\mathbb{F}_p$. Its elements are $(n-1)$-degree polynomials with coefficients $\in \mathbb{F}_p$.
- $\mathbb{K}[X]$. The polynomial ring in $X$ over the field $\mathbb{K}$. It is basically the set of $(n-1)$-degree polynomials $P$ of the form:

$$P(X) = a_0 + a_1X + a_2X^2 + ... + a_nX^n$$

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;where $a_i \in \mathbb{K}$.

- $\mathbb{K}[Y]\ /\ P(Y)$. The quotient polynomial ring, obtained by taking all polynomials in $\mathbb{K}[Y]$ and doing arithmetic polynomial operations (addition, multiplication, division) "modulo" the polynomial $P(Y)$. If $P$ is irreducible, then the quotient polynomial ring forms a *field*.

- $f: A \rightarrow B$. The homomorphism $f$ that maps elements from the domain $A$ to the codomain $B$.

# Translating maths into code

In this post, we'll be cooking with the field $\mathbb{F}_{{(2^2)}^3}$. More specifically, we define:

$$A = F_{2^2}[y]\ /\ (y^3+y+1)$$

In natural language:

> $A$ is the set of degree-$2$ polynomials in $y$ with coefficients in $\mathbb{F}_{2^2}$. But hey, when you do operations with these polynomials, reduce the result modulo the irreducible polynomial $y^3+y+1$.

<!-- Notice that the degree of the polynomials in $A$ should be less than $3$; the degree of the irreducible polynomial. Last but not least, the field $\mathbb{F}_{2^2}$ contains 4 elements which are ***at most*** degree-$1$ polynomials with coefficients in $\mathbb{F}_2$; namely: $\\{0, 1, a, a+1\\}$. -->

It's time for converting the nitty-gritty maths into code.

## Defining the parameters in Sage

First, we define $\mathbb{F}_{2^2}$:

```python
F4.<a> = GF(2^2)
```

Then, the polynomial ring $\mathbb{F}_{2^2}[y]$.

```python
PR.<y> = PolynomialRing(F4)
```

The polynomial ring consists of an infinite set of polynomials with coefficients in $\mathbb{F}_{2^2}$. Some elements are shown below:

```python
sage: for d in range(5, 10): print(PR.random_element(d))
(a + 1)*y^5 + y^4 + a*y^3 + y + a
a*y^6 + y^5 + y^4 + a*y^3 + (a + 1)*y^2 + y
a*y^7 + (a + 1)*y^6 + (a + 1)*y^5 + a*y^3 + a + 1
a*y^8 + a*y^7 + a*y^6 + (a + 1)*y^5 + a*y^4 + (a + 1)*y^2 + a*y + a + 1
y^9 + a*y^7 + y^6 + y^5 + (a + 1)*y^4 + y^2 + y + a + 1
```

Then, we define our irreducible polynomial $P(y) = y^3 + y + 1$ and the quotient polynomial ring $Q = F_{2^2}[y]\ /\ P(y)$:

```python
P = y^3 + y + 1
assert P.is_irreducible()
Q.<w> = PR.quotient(P)
```

Since $P$ is irreducible, $Q$ has maximum order ${(2^2)}^3 = 2^{2 \cdot 3} = 2^6 = 64$. All the elements are listed below:

```python
sage: len(list(Q))
64
sage: str(list(Q))
'[0, a, a + 1, 1, a*w, a*w + a, a*w + a + 1, a*w + 1, (a + 1)*w, (a + 1)*w + a, (a + 1)*w + a + 1, (a + 1)*w + 1, w, w + a, w + a + 1, w + 1, a*w^2, a*w^2 + a, a*w^2 + a + 1, a*w^2 + 1, a*w^2 + a*w, a*w^2 + a*w + a, a*w^2 + a*w + a + 1, a*w^2 + a*w + 1, a*w^2 + (a + 1)*w, a*w^2 + (a + 1)*w + a, a*w^2 + (a + 1)*w + a + 1, a*w^2 + (a + 1)*w + 1, a*w^2 + w, a*w^2 + w + a, a*w^2 + w + a + 1, a*w^2 + w + 1, (a + 1)*w^2, (a + 1)*w^2 + a, (a + 1)*w^2 + a + 1, (a + 1)*w^2 + 1, (a + 1)*w^2 + a*w, (a + 1)*w^2 + a*w + a, (a + 1)*w^2 + a*w + a + 1, (a + 1)*w^2 + a*w + 1, (a + 1)*w^2 + (a + 1)*w, (a + 1)*w^2 + (a + 1)*w + a, (a + 1)*w^2 + (a + 1)*w + a + 1, (a + 1)*w^2 + (a + 1)*w + 1, (a + 1)*w^2 + w, (a + 1)*w^2 + w + a, (a + 1)*w^2 + w + a + 1, (a + 1)*w^2 + w + 1, w^2, w^2 + a, w^2 + a + 1, w^2 + 1, w^2 + a*w, w^2 + a*w + a, w^2 + a*w + a + 1, w^2 + a*w + 1, w^2 + (a + 1)*w, w^2 + (a + 1)*w + a, w^2 + (a + 1)*w + a + 1, w^2 + (a + 1)*w + 1, w^2 + w, w^2 + w + a, w^2 + w + a + 1, w^2 + w + 1]'
```

Each polynomial in the infinite set of $\text{PR}$ eventually reduces to one of these $64$ polynomials.

## Defining the homomorphism $f$

Here comes the fun part.

As aforementioned, $P$ is irreducible which makes $Q$ a ***field***. But is there any other field with the same number of elements as $Q$? One might immediately think of $\mathbb{F}\_{2^6} = \mathbb{F}_{64}$ and they'd be right! In fact, the elements of $\mathbb{F}\_{64}$ are listed below:

```python
sage: F64.<z> = GF(2^6)
sage: len(list(F64))
64
sage: str(list(F64))
'[0, z, z^2, z^3, z^4, z^5, z^4 + z^3 + z + 1, z^5 + z^4 + z^2 + z, z^5 + z^4 + z^2 + z + 1, z^5 + z^4 + z^2 + 1, z^5 + z^4 + 1, z^5 + z^4 + z^3 + 1, z^5 + z^3 + 1, z^3 + 1, z^4 + z, z^5 + z^2, z^4 + z + 1, z^5 + z^2 + z, z^4 + z^2 + z + 1, z^5 + z^3 + z^2 + z, z^2 + z + 1, z^3 + z^2 + z, z^4 + z^3 + z^2, z^5 + z^4 + z^3, z^5 + z^3 + z + 1, z^3 + z^2 + 1, z^4 + z^3 + z, z^5 + z^4 + z^2, z^5 + z^4 + z + 1, z^5 + z^4 + z^3 + z^2 + 1, z^5 + 1, z^4 + z^3 + 1, z^5 + z^4 + z, z^5 + z^4 + z^3 + z^2 + z + 1, z^5 + z^2 + 1, z^4 + 1, z^5 + z, z^4 + z^3 + z^2 + z + 1, z^5 + z^4 + z^3 + z^2 + z, z^5 + z^2 + z + 1, z^4 + z^2 + 1, z^5 + z^3 + z, z^3 + z^2 + z + 1, z^4 + z^3 + z^2 + z, z^5 + z^4 + z^3 + z^2, z^5 + z + 1, z^4 + z^3 + z^2 + 1, z^5 + z^4 + z^3 + z, z^5 + z^3 + z^2 + z + 1, z^2 + 1, z^3 + z, z^4 + z^2, z^5 + z^3, z^3 + z + 1, z^4 + z^2 + z, z^5 + z^3 + z^2, z + 1, z^2 + z, z^3 + z^2, z^4 + z^3, z^5 + z^4, z^5 + z^4 + z^3 + z + 1, z^5 + z^3 + z^2 + 1, 1]'
```

It turns out that there exists a homomorphism (from the Greek «ὅμοιος» + «μορφή», "similar form") that connects the elements of $Q$ and $F_{64}$. In fact, both fields share the same cardinality ($64$ elements) which is a fundamental requirement for the homomorphism to be an isomorphism. However, this alone is merely an indication and does not guarantee isomorphism, as the homomorphism must also be bijective (i.e. injective and surjective).

<!--One of the requirements for two groups to be homomorphic is to have the same cardinality which is true in our case. -->

```python
sage: len(Q) == len(F64)
True
```

Take a random element in $Q$, say $r = w^2 + a \cdot w + 1$. Since these groups are "connected" through the homomorphism, there **might** be an element of $\mathbb{F}_{64}$ that maps to $r$ (*this isn't always the case as the homomorphism must be injective, and we haven't proven that yet*). I might write another blog post in the future trying to break down injective and surjective maps with practical examples. For now, let's move forward and define the homomorphism between $Q$ and $\mathbb{F}\_{64}$.

<div style='text-align: center'><b><u>DISCLAIMER: Huge thanks to @A~Z for assisting me with his algebra and SageMath know-how.</u></b></div>

```python
sage: SF.<z> = P.splitting_field()
sage: r = P.change_ring(SF).any_root()
sage: f = Q.hom([r,], codomain=F64)
sage: f
Ring morphism:
  From: Univariate Quotient Polynomial Ring in z over Finite Field in a of size 2^2 with modulus y^3 + y + 1
  To:   Finite Field in w of size 2^6
  Defn: w |--> z^5 + z^4 + z^2 + 1
```

1. What the heck if `splitting_field`? I don't really know in detail but think of it as an extension field that $P$ is raised to. We will treat it as equivalent to $\mathbb{F}_{64}$.

2. What about $r$? $r$ is the root of $P$ in $\mathbb{F}_{64}$.


```python
sage: P.change_ring(SF)
y^3 + y + 1
sage: P.change_ring(SF).any_root()
z^5 + z
sage: P.change_ring(SF).any_root()
z^5 + z^4 + z^2 + 1
sage: factor(P.change_ring(SF))
(y + z^4 + z^2 + z + 1) * (y + z^5 + z) * (y + z^5 + z^4 + z^2 + 1)
```

From sage [docs](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_element.html#sage.rings.polynomial.polynomial_element.Polynomial.any_root):

> For finite fields, any_root() is non-deterministic when finding linear roots of a polynomial over the base ring.

Essentially, this provides way to determine the images of $Q$'s generator $w$ in the codomain $\mathbb{F}_{64}$. Any of the following mappings would construct a valid homomorphism $f$:

$$
w \rightarrow z^4 + z^2 + z + 1\\\
w \rightarrow z^5 + z\\\
w \rightarrow z^5 + z^4 + z^2 + 1\\\
$$

Each of these images tells the homomorphism how to map elements.

```python
sage: f = Q.hom([z^4+z^2+z+1], codomain=F64) ; f(w^6)
z^5 + z + 1
sage: f = Q.hom([z^5+z], codomain=F64) ; f(w^6)
z^5 + z^4 + z^2
sage: f = Q.hom([z^5+z^4+z^2+1], codomain=F64) ; f(w^6)
z^4 + z^2 + z
```

# Problem demonstration

So far, so good. We found a way to map elements from $Q \rightarrow \mathbb{F}_{64}$ using $f$. What if we want to go in the opposite direction? In other words, given the image $f(w^6) = z^4 + z^2 + z$, can we determine $w^6 = f^{-1}(z^4 + z^2 + z)$?

This boils down to constructing the inverse ring homomorphism $f^{-1}$:

$$f^{-1}: \mathbb{F}_{64} \rightarrow Q$$

$f^{-1}$ exists if and only if $Q$ and $\mathbb{F}_{64}$ are ***isomorphic***. For a homomorphism to be invertible, it must be bijective, which means it needs to be both injective and surjective (see SageMath source [code](https://github.com/sagemath/sage/blob/master/src/sage/rings/morphism.pyx#L1637)). Let's try computing $f^{-1}$:

```python
sage: f.inverse()
# <REDACTED>
NotImplementedError: base rings must be equal
sage: f.is_invertible()
# <REDACTED>
NotImplementedError: base rings must be equal
sage: f.is_injective()
True
sage: f.is_surjective()
# <REDACTED>
NotImplementedError: base rings must be equal
```

<span style='font-size:2em;'>😰</span>

This is where things got serious. While digging into SageMath's source [code](https://github.com/sagemath/sage/blob/master/src/sage/rings/morphism.pyx#L1291), I discovered that the actual error originates from the function `sage.rings.morphism.RingHomomorphism._graph_ideal`. The `NotImplementedError` suggests that nobody has really needed this specific case before, so there's simply no implementation for it. We can confirm that the base rings are indeed different.

```python
sage: f.domain()
Univariate Quotient Polynomial Ring in w over Finite Field in a of size 2^2 with modulus y^3 + y + 1
sage: f.codomain()
Finite Field in z of size 2^6
sage: assert f.domain() == Q
sage: assert f.codomain() == F64
sage: f.domain().base_ring()
Finite Field in a of size 2^2
sage: f.codomain().base_ring()
Finite Field of size 2
```

But I'm too convinced that these two fields are indeed isomorphic.

... until ...

> I assume just defining the inverse yourself?

> but yeah you probably just want to define the inverse yourself

![](discord-interesting-project.png)

<span style='font-size:2em;'>👷🏼‍♂️👷🏼‍♂️</span>

# Defining the inverse ring homomorphism ourselves

## First thoughts

Without any clear plan on HOW to do it, I suspected that the key was to find a polynomial $p(w)$ such that $z \rightarrow p(r)$. If that worked, I could build $f^{-1}$ on top of that mapping. Big kudos to some fellow CryptoHackers for confirming this suspicion!

Additionally, @A~Z shared a couple of functions with me, but they didn't quite work for my case. I ended up having to figure out what to tweak to make them work; which, in the end, wasn't really worth the effort. Consequently, I decided to write my own function to get the job done.

A polynomial $p$ in $w$ has the following form:

$$p(w) = a_0 + a_1w + a_2w^2$$

where $w$ is the generator of $Q$ and $a_i \in F_{2^2}$. Our task is to find the cofficients $\\{a_0, a_1, a_2\\}$.

## Spoiler Alert - Solution Peeking

Before diving into the real thing, we first need to verify whether such polynomial $p$ even exists at all. Since our example field has a relatively small cardinality, I can simply bruteforce all elements of $Q$ and check if $p(r) = z$ held true.

```python
for p in list(Q):
    if p.lift()(r) == z:
        print(p)
```
Output:
```
a*w^2 + w + 1
```

Bingo! The vector $\vec{s} = \\{1, 1, a\\}$ is the coefficient vector we are looking for. This will serve as our sanity check when verifying the solution's correctness.

<p style='text-align: center'><small><i>Since <code>any_root</code> is non-deterministic, the polynomial $p$ might vary but the core idea remains unchanged.</i></small></p>

Now, back to the math...

## Yes. Linear algebra ... again

The only relation we know is:

$$p(r) = z$$

or equivalently

$$a_0 + a_1r + a_2r^2 = z$$

This is where I stumbled upon [this](https://math.stackexchange.com/questions/4069654/finding-inverse-in-a-quotient-ring) thread and it just clicked. This problem can be reframed as a linear algebra problem where, given $M$ and $T$ we need to find the unknown vector:

$$\vec{s} = \begin{pmatrix}a_0 & a_1 & a_2\end{pmatrix}$$

such that:

$$M \cdot \vec{s} = T \Rightarrow \\\ \vec{s} = M^{-1}T$$

The equation can be translated to:

$$\begin{pmatrix}1 & r & r^2\end{pmatrix} \begin{pmatrix}a_0 & a_1 & a_2\end{pmatrix} = z$$

Since both $M$ and $T$ are known, we should be able to recover the unknown vector $\vec{s}$ using SageMath's [`solve_right`](https://doc.sagemath.org/html/en/tutorial/tour_linalg.html#linear-algebra). Right?

Well... not quite. There's a problem.

### PROBLEM: $a_i$ and $z$ are defined over different fields

The issue is that the coefficients $a_i$ are defined over $F_{2^2}$ while $r, z$ are defined over $F_{2^6}$. This field mismatch prevents us from directly calling `solve_right`, as SageMath doesn't inherently know which field to use to solve the equation.

We should agree in a common field to be able to solve the equation:

- What about $F_{2^2}$? Hmm... since $z$ is defined over a larger field, it can't be expressed within a smaller field such as $\mathbb{F}\_{2^2}$. This makes it impossible to define $z$ in $\mathbb{F}\_{2^2}$.

    ```python
    sage: F4(z)
    # <REDACTED>
    ValueError: z is not in the image of (map internal to coercion system -- copy before use)
    Ring morphism:
      From: Finite Field in a of size 2^2
      To:   Finite Field in z of size 2^6
    ```

- What about $F_{2^6}$? Let's try that in Sage:

    ```python
    sage: M = Matrix(F64, [1, r, r**2])
    sage: T = vector([z])
    sage: M.solve_right(T)
    (z, 0, 0)
    ```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;This yields the trivial solution which certainly does not look like a valid solution for $\vec{s} = $

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;$\begin{pmatrix}a_0 & a_1 & a_2\end{pmatrix}$.

## Solving the system over the base field $\mathbb{F}_2$

Luckily, all $a_i, r$ and $z$ share a common base field; namely $\mathbb{F}_2$. This is the lowest level we can perform operations. Once we've solved the system at $\mathbb{F}\_2$, we can lift the elements of $\vec{s}$ to $\mathbb{F}\_{2^2}$.

Lift? How? Well, it's pretty simple:

```python
sage: F4([0,0])
0
sage: F4([1,0])
1
sage: F4([0,1])
a
sage: F4([1,1])
a + 1
sage: F4([0,1,1]) # = a^2 + a -> too large for F4
# <REDACTED>
ValueError: list is too long
```

$\mathbb{F}_4$ contains only $2^2=4$ elements. Trying to lift $a^2$ directly, results in an error.

For example, if we end up with:

$$\vec{s} = \begin{pmatrix}1 & 0 & 0 & 1 & 1 & 1\end{pmatrix}$$

we split $\vec{s}$ into three $2$-bit chunks and we get:

$$a_0 = 1 + 0 \cdot a = 1 \\\ a_1 = 0 + 1 \cdot a = a \\\ a_2 = 1 + 1 \cdot a = a + 1$$

By lifting $a_i$ to $Q$ the following polynomial is formed:

$$p(w) = 1 + a \cdot w + (a+1) \cdot w^2$$

Programmatically, these lifts can be implemented as:
```python
sage: s = [1, 0, 0, 1, 1, 1]
sage: Q([F4(s[i:i+2]) for i in range(0, len(s), 2)])
(a + 1)*w^2 + a*w + 1
```

What remains now is to construct the matrix $M$ and the target vector $T$. Let's begin with the target vector $T$.

### Constructing the target vector $T$

The equation we want to solve is:

$$\begin{align}a_0 + a_1r + a_2r^2 = z\end{align}$$

Our goal is to express $z$ as a binary vector of length $6$ (the degree of the extension field $\mathbb{F}_{2^6}$). Notice above that the binary expansion of $a$, the generator of $\mathbb{F}\_{2^2}$, is:

$$0 + 1 \cdot a$$

which corresponds to the binary vector $\begin{pmatrix}0 & 1\end{pmatrix}$.

Similarly, for $z$, the generator of $\mathbb{F}\_{2^6}$, the binary vector is:

$$\begin{pmatrix}0 & 1 & 0 & 0 & 0 & 0\end{pmatrix}$$

derived from the binary expansion:

$$z = 0 + 1 \cdot z + 0 \cdot z^2 + 0 \cdot z^3 + 0 \cdot z^4 + 0 \cdot z^5$$

Fortunately, in SageMath, the vectorization of $z$ can be done in a single line of code.

```python
sage: vector(z)
(0, 1, 0, 0, 0, 0)
```

### Constructing the matrix $M$
 
What is left is converting the left-hand side into a matrix, after which we can use `solve_right` to find the solution vector.

Remember, our goal is to recover $a_i$. To do this, let's express them as elements of $\mathbb{F}_{2^2}$:

$$
a_0 = b_0 + b_1 \cdot a\\\
a_1 = b_2 + b_3 \cdot a\\\
a_2 = b_4 + b_5 \cdot a\\\
$$

where $b_i \in \mathbb{F}_2$. Substituting into $(1)$, we get:

$$
(b_0 + b_1 \cdot a) + (b_2 + b_3 \cdot a) \cdot r + (b_4 + b_5 \cdot a) \cdot r^2 = z
$$

With some rearrangement, we can express this equation as a vector multiplication. Also, we substitute $z$ with its corresponding binary vector:

$$
\begin{pmatrix}b_0 & b_1 & b_2 & b_3 & b_4 & b_5\end{pmatrix}
\cdot
\begin{pmatrix}
1 & a & r & ar & r^2 & ar^2
\end{pmatrix}
= \\
\begin{pmatrix}
0 & 1 & 0 & 0 & 0 & 0
\end{pmatrix}
$$

Now, all elements of:

$$\begin{pmatrix}1 & a & r & ar & r^2 & ar^2\end{pmatrix}$$

are elements of $\mathbb{F}_{64}$ which can be converted to binary vectors too.

```python
sage: vector(F64(1))
(1, 0, 0, 0, 0, 0)
sage: vector(F64(a))
(0, 1, 1, 1, 0, 0)
sage: vector(F64(r))
(1, 1, 1, 0, 1, 0)
sage: vector(F64(a*r))
(1, 1, 1, 0, 0, 1)
sage: vector(F64(r^2))
(0, 1, 0, 0, 0, 1)
sage: vector(F64(a*r^2))
(0, 1, 1, 0, 0, 0)
```

Then, we use each of these as ***columns*** to construct $M$:

$$
M = \\
\begin{bmatrix}
1 & 0 & 1 & 1 & 0 & 0\\\
0 & 1 & 1 & 1 & 1 & 1\\\
0 & 1 & 1 & 1 & 0 & 1\\\
0 & 1 & 0 & 0 & 0 & 0\\\
0 & 0 & 1 & 0 & 0 & 0\\\
0 & 0 & 0 & 1 & 1 & 0\\\
\end{bmatrix}
$$

Finally, we obtain:

$$
\begin{bmatrix}
1 & 0 & 1 & 1 & 0 & 0\\\
0 & 1 & 1 & 1 & 1 & 1\\\
0 & 1 & 1 & 1 & 0 & 1\\\
0 & 1 & 0 & 0 & 0 & 0\\\
0 & 0 & 1 & 0 & 0 & 0\\\
0 & 0 & 0 & 1 & 1 & 0\\\
\end{bmatrix}
\cdot
\begin{pmatrix}b_0 & b_1 & b_2 & b_3 & b_4 & b_5\end{pmatrix}
= \\
\begin{pmatrix}
0 & 1 & 0 & 0 & 0 & 0
\end{pmatrix}
$$

which is in the form:

$$
M \cdot \vec{s} = T
$$

<center><small><i>WARNING! Keep in mind that $M$ might be different due to the non-deterministic nature of <code>any_root</code>.</i></small></center>

```python
sage: M = Matrix(F64.base_ring(), [ # define M over the base field F_2
....:     [1,0,1,1,0,0],
....:     [0,1,1,1,1,1],
....:     [0,1,1,1,0,1],
....:     [0,1,0,0,0,0],
....:     [0,0,1,0,0,0],
....:     [0,0,0,1,1,0]
....: ])
sage: T = vector(z)
sage: s = M.solve_right(T)
sage: s
(1, 0, 0, 1, 1, 1)
sage: Q([F4(s[i:i+2]) for i in range(0, len(s), 2)])
(a + 1)*w^2 + a*w + 1
```

Words can't describe the satisfaction of finally seeing everything come together and make perfect sense.

All we have to do now is define the inverse homomorphism based on the following mapping:

$$f^{-1}: z \rightarrow (a + 1) \cdot w^2 + a \cdot w + 1$$

```python
sage: p = Q([F4(s[i:i+2]) for i in range(0, len(s), 2)])
sage: finv = F64.hom([p,], Q)
sage: finv
Ring morphism:
  From: Finite Field in z of size 2^6
  To:   Univariate Quotient Polynomial Ring in w over Finite Field in a of size 2^2 with modulus y^3 + y + 1
  Defn: z |--> (a + 1)*w^2 + a*w + 1
```

For be 100% sure that this is the correct homomorphism, we can generate a few random values $l_0, l_1, ..., l_n \in \mathbb{F}_{64}$ and check whether:

$$l_i \stackrel{?}{=} f(f^{-1}(l_i))$$

```python
for i in range(100):
    el = F64.random_element()
    assert el == f(finv(el))
    
print('thanks for reading :-]')
```

Output:

```
thanks for reading :-]
```

Hoped you liked this post. Feel free to reach out on discord for feedback, my handle is `r4sti`.

You can find the source code for this blog post in my public [gist](https://gist.github.com/rasti37/dd27eae9c66bf7d255fe98f59e9c0e7a). I have made some modifications to support any field degree.

Cheers!😎