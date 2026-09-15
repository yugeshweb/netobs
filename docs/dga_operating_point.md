# DGA detector: operating point

Model: LightGBM, 19 features (13 lexical + 6 dictionary-segmentation).
Evaluation: 25,000 held-out domains (12,500 benign from Tranco,
12,500 synthetic DGA across three families).

## Threshold selection

| threshold | precision | recall | false positives | FPR    | wordlist recall |
|-----------|-----------|--------|-----------------|--------|-----------------|
| 0.50      | 0.9525    | 0.9188 | 573             | 0.0458 | 0.7671          |
| 0.70      | 0.9747    | 0.8764 | 284             | 0.0227 | 0.6467          |
| **0.85**  | **0.9887**| **0.8355** | **119**     | **0.0095** | **0.5323**  |
| 0.90      | 0.9926    | 0.8118 | 76              | 0.0061 | 0.4670          |

Chosen: **0.85 alert / 0.60 observe**.

Between 0.50 and 0.85 the false-positive count falls ~79% for 8 points of
recall. Beyond 0.85 the trade reverses: 0.90 saves 43 further false
positives but drops dictionary-DGA recall below 50%.

Domains scoring 0.60-0.85 are recorded as low-confidence observations
rather than alerts, preserving the signal without the alert load.

## Known limits

- Dictionary-based DGA recall is 0.53 at the chosen threshold. Consistent
  with the difficulty reported for families such as Suppobox and Matsnu.
- The DGA classes are synthetic. Validation against real published families
  is outstanding; figures above should not be read as performance on
  real-world malware.
- ROC AUC on this set: 0.9876.
