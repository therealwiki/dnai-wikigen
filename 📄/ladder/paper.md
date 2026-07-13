# The Ladder: A Reliable Leaderboard for Machine Learning Competitions

## Paper Metadata
- **arXiv:** 1502.04585v1
- **Date:** February 16, 2015
- **Authors:** Avrim Blum (Carnegie Mellon University), Moritz Hardt (IBM Almaden Research)
- **Categories:** Machine Learning (cs.LG)

---

## Abstract

The organizer of a machine learning competition faces the problem of maintaining an accurate leaderboard that faithfully represents the quality of the best submission of each competing team. What makes this estimation problem particularly challenging is its **sequential and adaptive** nature: because participants repeatedly evaluate submissions against the leaderboard, they may begin to **overfit to the holdout data** that supports it. The paper introduces a notion of *leaderboard accuracy* and a natural algorithm called the **Ladder** that (1) enjoys strong worst-case guarantees in a fully adaptive model, (2) withstands practical adversarial attacks, and (3) achieves high utility on real submission files from a Kaggle competition. Notably it sidesteps a powerful recent hardness result for adaptive risk estimation, and comes with a completely **parameter-free** variant requiring no tuning.

---

## 1. The Problem: Overfitting to a Reused Holdout

In a competition, the test set's labels are withheld and participants repeatedly submit label predictions, each scored against those hidden labels. The moment a participant incorporates leaderboard feedback into their next submission, the classifier becomes **dependent on the holdout data**, and the holdout no longer gives an unbiased estimate of true performance. Kaggle's standard mitigations — splitting the test set into a public and a private leaderboard, limiting the re-submission rate, and limiting the numerical precision of released scores — are "poorly understood heuristics" and do not fix accuracy on the public leaderboard.

If the `k` submitted classifiers were **fixed in advance**, Hoeffding + a union bound would give error `~√(log k / n)` for a holdout of size `n`. But under **adaptive** choice `f_t = A(f_1, R_1, …, f_{t−1}, R_{t−1})`, this breaks: recent hardness results (Hardt–Ullman; Steinke–Ullman) show no computationally efficient estimator can keep error `o(1)` on more than `n^{2+o(1)}` adaptively chosen functions. So the naive goal ("accurate estimate for *every* submission") is too strong.

---

## 2. Leaderboard Accuracy — a Weaker, Sufficient Target

The key definitional move: you don't need an accurate estimate for *each* `f_t`; you only need the leaderboard to accurately track the **best score so far**. Define the **leaderboard error** of estimates `R_1, …, R_k` as

```
lberr(R_1, …, R_k) = max_{1 ≤ t ≤ k} | min_{1 ≤ i ≤ t} R_D(f_i) − R_t |
```

i.e. the largest gap between the true loss of the best-so-far classifier and the reported best `R_t`. Only reporting improvements, rather than every estimate, is exactly what lets the mechanism circumvent the adaptive-estimation hardness results.

Two ways to extend a single-track mechanism to a full leaderboard: one instance per team (needs a no-multiple-accounts assumption), or one instance per rank (more conservative, no such assumption).

---

## 3. The Ladder Mechanism

The algorithm is strikingly simple. Keep the running best loss `R_{t−1}`. For each new classifier, compute its empirical loss on the holdout; **release a new (rounded) estimate only if it beats the running best by more than a margin `η`** — otherwise re-release the previous best.

```
Input: data set S, step size η > 0
R_0 ← ∞
for each round t = 1, 2, …:
    receive f_t
    if R_S(f_t) < R_{t−1} − η:  R_t ← [R_S(f_t)]_η    # round to nearest multiple of η
    else:                       R_t ← R_{t−1}
    output R_t
```

**Guarantee (Theorem 3.1).** For any adaptively chosen sequence, with `η = O(n^{−1/3} log^{1/3}(kn))`, with high probability

```
lberr(R_1, …, R_k) ≤ O( log^{1/3}(kn) / n^{1/3} )
```

— **only logarithmic in the number of submissions `k`**, versus the `√k`-style degradation of the Kaggle-style "release every score" mechanism. That is an *exponential* improvement in `k`. The proof encodes each node of the analyst's adaptive decision tree in `B = (1/η + 2)·log(4t/η)` bits (there can be at most `⌈1/η⌉` genuine improvement steps, since losses live in `[0,1]`), bounding the effective number of functions to `2^B` and applying Hoeffding + a union bound over that compressed set.

**Lower bound (Theorem 3.3).** No estimator can beat `Ω(√(log k / n))` leaderboard error, even for non-adaptively chosen functions (via a reduction to high-dimensional mean estimation and Fano's inequality). So the Ladder is near-optimal, with a small gap between the `1/3` and `1/2` exponents left open.

---

## 4. Parameter-Free Ladder

Choosing `η` ahead of time is awkward. The parameter-free variant replaces the fixed margin with a **one-sided paired t-test**: it releases a new score only when the new loss vector is *statistically significantly* below the previous best's loss vector. It maintains the previous best classifier's per-example loss vector, computes `s = std(l_t − l_{t−1})`, and releases iff `R_S(f_t) < R_{t−1} − s/√n`, rounding the released value to `1/n`. The paired test has high power because competing submissions are strongly correlated; the significance level works out to ≈0.15. (The authors stress this test is a heuristic guide under adaptivity, since `f_t` need not be independent of `S`.) Releasing to `1/n` precision is fine — it only reveals `log(n)` bits, comparable to `1/√n` accuracy — because **the step size, not the precision, is what controls how often a new estimate leaks**.

---

## 5. The Boosting Attack

A canonical adversarial analyst attack that *quantifies* a mechanism's leakage. Against a hidden label vector `y ∈ {0,1}^n`: submit `k` random vectors `u_1, …, u_k`, keep those with observed loss `≤ 1/2`, and output their coordinate-wise majority `u*`. A standard boosting argument (Theorem 5.1) shows `u*` achieves loss `≤ 1/2 − Ω(√(k/n))` — a bias that **grows with the number of submissions**.

- Against the **Kaggle mechanism** (with rounding `α ≤ 1/√n`), this forces leaderboard error `Ω(√(k/n))` (Corollary 5.2): the public score of `u*` looks far better than its true ≈`1/2` loss on fresh data.
- Against the **Ladder**, each time a vector lowers the best score the probability that a later vector crosses the new threshold drops by a constant factor, so there are at most `O(log k)` improvement steps and the induced bias is only `O(√(log k / n))`.

Experiments (N=12000 labels, n=4000 public) confirm Kaggle's accuracy collapses with submissions while the Ladder stays within expected statistical deviation.

---

## 6. Real Kaggle Data

On 1785 real submissions from Kaggle's "Photo Quality Prediction" challenge, the parameter-free Ladder reproduces both the public and private leaderboards almost exactly — top-10 perturbations are within statistical noise (confirmed by paired t-tests with Bonferroni correction). So the mechanism is safe against adversaries *and* faithful on honest data, with the **same** parameter-free algorithm.

---

## 7. Conclusion

The Ladder makes competitions more reliable and generalizes to any domain where holdout overfitting is a concern (e.g. tracking scientific progress on public benchmarks, guarding against false discovery). It also offers an intuitive explanation for why holdout overfitting is often mild in practice: *if every analyst only checks whether their latest submission is well above their previous best, they are effectively already simulating the Ladder.*

The related work of Dwork, Feldman, Hardt, Pitassi, Reingold & Roth ("Preserving statistical validity in adaptive data analysis") is the more general DP-based approach the authors build on — see the reusable-holdout / Thresholdout line summarized in this repo alongside it.

---

## Relevance to dnai-wikigen

This paper is the theory that makes a **queryable private reward oracle** safe against a third party who can hammer it. In the project's terms, the sealed reward data is the holdout, and a buyer/sponsor/optimizer submitting candidates is the adaptive analyst.

- **The overfitting axis is separate from the leakage axis.** An optimizer can drive a fixed private holdout to a meaningless number *without ever reconstructing a record*. The Ladder is the mechanism that stops it: only release a reward when the candidate significantly beats the running best.
- **Bounded, quantized release is not just for privacy.** Rounding/step-size is what caps how often information leaks and keeps the settlement score honest. This is the same discipline as `denoising_core.band_to_scalar`, given a rigorous adaptive-query guarantee.
- **Practical upshot for the substrate:** with a Ladder-gated (or Thresholdout-gated) release path, a fixed-size sealed holdout supports *effectively unlimited* optimization attempts while the number stays trustworthy — which is exactly what `private_reward_holdout.py` should implement rather than a plain train/val/test split.
- **Parameter-free t-test variant** is directly deployable inside the boundary with no per-deal tuning.

See `📄/attestable-audits/paper.md` for the attestation/commitment side (trusting *which* code and data ran) and `PROJECT.md` (Private Reward Environment) for how these compose into the private verified-reward substrate.
