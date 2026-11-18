# Samples

## Curated (in git)

| Path | Purpose |
|------|---------|
| `benign/` | Auth-pass / internal / newsletter — FP checks |
| `phishing/*.eml` | Small synthetic/curated cases for demos + CI |

## External corpus (local only, not in git)

`phishing/badsamples/phishing_pot/` is the [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) dataset (~1.5 GB). Used for local calibration tests (`tests/test_pot_*.py`).

Clone it yourself if you need those tests:

```bash
git clone --depth 1 https://github.com/rf-peixoto/phishing_pot.git samples/phishing/badsamples/phishing_pot
```

CI skips pot-dependent tests when the corpus is absent.
