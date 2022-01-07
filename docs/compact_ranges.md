Compact Ranges
==============

This document introduces **Compact Ranges**, an easy mental model and technique for reasoning about Merkle trees and proofs. We present the definition, the properties, and the applications of this technique.

## Definition

For a range `[L, R)` of leaves in a Merkle tree, a Compact Range is the minimal set of nodes that “cover” these, and only these, leaves. For example, in the picture below, the range `[2, 9)` is covered by nodes `[1.1, 2.1, 8]`, and the range `[12, 16)` is covered by a single node `2.3`.

![compact_ranges](images/compact_ranges.png)

A compact range always consists of nodes that are “final”, i.e. the hashes of these nodes never change as the tree grows. For example, range `[0, 21)` in the picture above is covered by nodes `[4.0, 2.4, 20]`, not just node `5.0`. Nodes `5.0` and `3.2` are “ephemeral” for the tree of this size, and will change when new leaves are appended to the tree until the tree size crosses their corresponding perfect subtree right borders. For simplicity, when we talk about compact ranges, we can assume that the “ephemeral” nodes don’t exist.

Compact ranges have many useful properties, some of which are elaborated in sections below. The basic property is that the number of nodes in a compact range `[L, R)` is `O(log(R-L))`, or `O(log N)` more generally. A compact range is always unique, and its shape is determined using a few bitwise operations on `L` and `R`.

## Merging Compact Ranges

The core property that makes compact ranges widely usable is that they are “mergeable”. Two compact ranges, `[L, M)` and `[M, R)`, can be efficiently merged into an `[L, R)` range. Consider the picture below for an intuitive understanding of how it works.

![compact_ranges_merge](images/compact_ranges_merge.png)

Given 2 compact ranges, `[2, 9)` and `[9, 16)`, each represented by a set of node hashes (3 green and 3 cyan nodes correspondingly), we “merge” 2 sibling nodes by computing their parent’s hash any time they are both present in the set of nodes. This process repeats until there are no siblings in the set. As a result, we get hashes of nodes `[1.1, 2.1, 3.1]` which, as it turns out, represent a compact range of `[2, 16)`.

Note that, when merging 2 compact ranges, the set of “new” nodes (marked in yellow) that are generated as a side effect, forms a partial path towards the root of the tree. It can be proven that this is always the case, which is a convenient property for implementations.

Merging two compact ranges can be implemented in `O(log(R-L))`, or more generally `O(log N)` time. This follows from the observation in the paragraph above, and the fact that the size of the resulting `[L, R)` compact range is limited by the same estimate.

## Merkle Tree Proofs

A compact range `[L, R)`, if represented by the cryptographic hashes of the corresponding nodes, can be considered a commitment to the contents of the leaves in this range. The ability to merge compact ranges is effectively the ability to merge commitments.

### Inclusion Proofs Revisited

A classic way of thinking about Merkle tree proofs is “vertical”, or recursive. For example, see how proofs are [defined](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1) in RFC 6962. In the context of this document we rather look at Merkle trees as horizontal structures (hence *ranges*).

Consider an inclusion proof for leaf `6` in the example tree below. Nodes `[3.1, 2.0, 1.2, 7]` represent a classic CT-style vertical inclusion proof.

![inclusion_proof](images/inclusion_proof.png)

Mind the coloring though. Nodes `[2.0, 1.2]` to the left of the path to leaf `6` are simply the compact range of `[0, 6)`. Similarly, nodes `[7, 3.1]` to the right are the compact range of `[7, 16)`.

One way to verify such a proof is to run a vertical CT-style loop combining hashes, and compare the result with the expected root hash. Another way to combine the hashes and get the same result is to merge 3 compact ranges: `[0, 6)`, `[6, 7)` and `[7, 16)`. The boundary compact ranges are provided by the server as a proof, and the (trivial) middle one is constructed by the client.

### Arbitrary Inclusion Proofs

In the previous section we established that an inclusion proof can be decomposed into 2 compact ranges at both sides from the leaf in question. Note that these compact ranges represent the "complementary" part of the Merkle tree, i.e. the entire range minus the leaf. We can generalize this observation: an inclusion proof for an **arbitrary subset** of leaves is a commitment to its complementary part of the tree.

For example, consider the case when we want to prove the authenticity of values within the range `[6, 13)`, as shown in the picture below.

![inclusion_proof_range](images/inclusion_proof_range.png)

To do so, the server can provide 2 compact ranges: `[0, 6)` and `[13, 16)`. The client will then construct the middle compact range locally (based on the leaf hashes of values between `6` and `12` that they know), and merge it with the two boundary compact ranges. Then they compute the root hash from the resulting compact range, and compare it against the trusted root hash.

This construction is called a **range inclusion proof**.

In a more general case, to prove the inclusion of an arbitrary subset of entries, the server needs to provide a compact range for each of the “gaps” in leaves. The verifier will then construct compact ranges for each contiguous part of the leaves in question, and merge them with all the "gap" compact ranges provided by the prover.

It is easy to see that a range inclusion proof takes `O(log N)` hashes of space. The general case, **multi-entry inclusion proof**, is less straightforward: depending on the number of leaves in question, and how close they are to each other, the proof size varies between `O(log N)` to `O(N)`. The multi-entry proof is always optimal though, and thus more efficient than many individual entry inclusion proofs which could cost `O(N log N)`.

### Consistency Proofs

A consistency proof (or proof of the append-only property) proves to a client who trusts one root hash commitment that another root hash commitment commits to the same entries, plus some new ones appended to the tree from the right.

![consistency_proof](images/consistency_proof.png)

The definition of the consistency proof already contains a hint on how to model it with compact ranges. Suppose a client knows a compact range of the old tree, like `[0, 6)` in the picture above. The server provides compact range of all the appended entries, e.g. `[6, 16)`. The client can then merge `[0, 6)` with `[6, 16)`, and compare the resulting root hash with the advertised one.

If the client does not have the compact range of the old tree, it can be provided by the server too. The classical CT consistency proof [algorithm](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1.2) doesn’t assume that the client has a mergeable commitment. So, instead of just compact range `[6, 16)`, a CT-style proof roughly consists of both the old compact range and the one that commits to the appended entries.
