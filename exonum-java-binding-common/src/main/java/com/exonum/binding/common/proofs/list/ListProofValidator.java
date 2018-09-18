/*
 * Copyright 2018 The Exonum Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.exonum.binding.common.proofs.list;

import static com.exonum.binding.common.hash.Funnels.hashCodeFunnel;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

import com.exonum.binding.common.hash.HashCode;
import com.exonum.binding.common.hash.HashFunction;
import com.exonum.binding.common.hash.Hashing;
import com.exonum.binding.common.hash.PrimitiveSink;
import com.exonum.binding.common.serialization.CheckingSerializerDecorator;
import com.exonum.binding.common.serialization.Serializer;
import com.google.common.annotations.VisibleForTesting;
import java.util.NavigableMap;
import java.util.Optional;
import java.util.TreeMap;

/**
 * A validator of list proofs.
 *
 * @param <E> the type of elements in the corresponding list
 */
public final class ListProofValidator<E> implements ListProofVisitor {

  private final HashCode expectedRootHash;

  private final CheckingSerializerDecorator<E> serializer;

  private final HashFunction hashFunction;

  private final NavigableMap<Long, E> elements;

  private long index;

  private int depth;

  private HashCode hash;

  /**
    * Creates a new ListProofValidator.
   *
   * @param expectedRootHash an expected value of a root hash
   * @param serializer a serializer of list elements
   */
  public ListProofValidator(byte[] expectedRootHash, Serializer<E> serializer) {
    this(HashCode.fromBytes(expectedRootHash), serializer);
  }

  /**
   * Creates a new ListProofValidator.
   *
   * @param expectedRootHash an expected value of a root hash
   * @param serializer a serializer of list elements
   */
  public ListProofValidator(HashCode expectedRootHash, Serializer<E> serializer) {
    this(expectedRootHash,  serializer, Hashing.defaultHashFunction());
  }

  @VisibleForTesting  // to easily inject a mock of a hash function.
  ListProofValidator(HashCode expectedRootHash, Serializer<E> serializer,
                     HashFunction hashFunction) {
    //checkArgument(0 < numElements, "numElements (%s) must be positive", numElements);
    this.expectedRootHash = checkNotNull(expectedRootHash);
    this.serializer = CheckingSerializerDecorator.from(serializer);
    this.hashFunction = checkNotNull(hashFunction);
    elements = new TreeMap<>();
    index = 0;
    depth = 0;
    hash = null;
  }

  private int getExpectedLeafDepth(long numElements) {
      return (int) Math.round(Math.ceil(Math.log(numElements) / Math.log(2.0)));
  }

  @Override
  public void visit(ListProofBranch branch) {
    long branchIndex = index;
    int branchDepth = depth;
    HashCode leftHash = visitLeft(branch, branchIndex, branchDepth);
    Optional<HashCode> rightHash = visitRight(branch, branchIndex, branchDepth);

    hash = hashFunction.newHasher()
        .putObject(leftHash, hashCodeFunnel())
        .putObject(rightHash, (Optional<HashCode> from, PrimitiveSink into) ->
            from.ifPresent((hash) -> hashCodeFunnel().funnel(hash, into)))
        .hash();
  }

  @Override
  public void visit(HashNode hashNode) {
    this.hash = hashNode.getHash();
  }

  @Override
  public void visit(ProofListElement value) {
    assert !elements.containsKey(index) :
        "Error: already an element by such index in the map: i=" + index
            + ", e=" + elements.get(index);

    E element = serializer.fromBytes(value.getElement());
    elements.put(index, element);
    hash = hashFunction.hashObject(value, ProofListElement.funnel());
  }

  private HashCode visitLeft(ListProofBranch branch, long branchIndex, int branchDepth) {
    index = 2 * branchIndex;
    depth = getChildDepth(branchDepth);
    branch.getLeft().accept(this);
    return hash;
  }

  private Optional<HashCode> visitRight(ListProofBranch branch, long branchIndex, int branchDepth) {
    index = 2 * branchIndex + 1;
    depth = getChildDepth(branchDepth);
    hash = null;
    branch.getRight().ifPresent((right) -> right.accept(this));
    return Optional.ofNullable(hash);
  }

  private int getChildDepth(int branchDepth) {
    return branchDepth + 1;
  }

  /**
   * Returns true if this proof is valid.
   */
  public boolean isValid() {
    return !elements.isEmpty() && isBalanced() && doesHashMatchExpected();
  }

  private boolean isBalanced() {
    return getExpectedLeafDepth(elements.size()) >= depth;
  }

  private boolean doesHashMatchExpected() {
    return expectedRootHash.equals(hash);
  }

  /**
   * Returns a non-empty collection of list entries: index-element pairs, ordered by indices.
   *
   * @throws IllegalStateException if proof is not valid
   */
  public NavigableMap<Long, E> getElements() {
    checkState(isValid(), "Proof is not valid: %s", getReason());
    return elements;
  }

  private String getReason() {
    if (elements.isEmpty()) {
      return "the tree does not contain any value nodes";
    } else if (!isBalanced()) {
      return "a value node appears at the wrong level";
    } else if (!doesHashMatchExpected()) {
      return "hash mismatch: expected=" + expectedRootHash
          + ", actual=" + hash;
    } else {
      return "";
    }
  }

  @Override
  public String toString() {
    return "ListProofValidator{"
        + "hash=" + hash
        + ", expectedRootHash=" + expectedRootHash
        + ", isBalanced=" + isBalanced()
        + ", elements=" + elements
        + ", expectedLeafDepth=" + getExpectedLeafDepth(elements.size())
        + ", depth=" + depth
        + ", index=" + index
        + '}';
  }
}
