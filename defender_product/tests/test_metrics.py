"""Tie-aware metrics and the strict-threshold operating point (review 2026-09-21, finding 5)."""
from __future__ import annotations

import importlib.util
import unittest

import numpy as np

from tests.common import ROOT

spec = importlib.util.spec_from_file_location("evaluate_models", ROOT.parent / "dataset" / "tools" / "evaluate_models.py")
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)


class MetricsTest(unittest.TestCase):
    def test_tied_cross_class_scores_give_auc_half_in_both_row_orders(self):
        for labels in ([0, 1], [1, 0]):
            m = em.metrics(np.array([0.5, 0.5]), np.array(labels))
            self.assertAlmostEqual(m["roc_auc"], 0.5)
            self.assertAlmostEqual(m["pr_auc"], 0.5)

    def test_perfectly_separated_two_sample_case(self):
        m = em.metrics(np.array([0.1, 0.9]), np.array([0, 1]))
        self.assertEqual(m["tpr_at_fpr_0.01"], 1.0)
        self.assertEqual(m["threshold_at_fpr_0.01"], 0.1)
        self.assertEqual(m["actual_fpr_0.01"], 0.0)
        self.assertEqual(m["roc_auc"], 1.0)
        self.assertEqual(m["pr_auc"], 1.0)

    def test_strict_threshold_matches_brute_force_and_sklearn_on_grid_scores(self):
        from sklearn.metrics import average_precision_score, roc_auc_score
        rng = np.random.default_rng(11)
        for trial in range(100):
            nb, nm = rng.integers(5, 300), rng.integers(5, 300)
            benign = np.round(rng.beta(2, 6, nb), 2)        # 0.01 grid: many ties, like a 100-tree forest
            malicious = np.round(rng.beta(6, 2, nm), 2)
            scores = np.r_[benign, malicious]; labels = np.r_[np.zeros(nb, int), np.ones(nm, int)]
            m = em.metrics(scores, labels)
            self.assertAlmostEqual(m["roc_auc"], roc_auc_score(labels, scores), places=12)
            self.assertAlmostEqual(m["pr_auc"], average_precision_score(labels, scores), places=12)
            for target in (0.001, 0.01, 0.05):
                cut = em.threshold_for_fpr(benign, target)
                self.assertLessEqual((benign > cut).mean(), target + 1e-12)
                # brute force: the best achievable TPR over every candidate cut with FPR <= target
                best = max(((malicious > c).mean() for c in np.r_[scores, np.nextafter(scores.min(), -np.inf)]
                            if (benign > c).mean() <= target), default=0.0)
                self.assertAlmostEqual(m[f"tpr_at_fpr_{target}"], best, places=12)


if __name__ == "__main__":
    unittest.main()
