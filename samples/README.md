# Test corpus — DO NOT INSTALL

These 20 small packages (10 PyPI, 10 npm) are **test fixtures for static analysis only**.

- The "malicious" samples are **inert imitations** of real attack patterns (install-time credential theft,
  base64-hidden payloads, environment-variable harvesting, typosquatting, poisoned updates).
- Every network address uses the reserved `.invalid` domain (RFC 2606), which can never resolve.
- Hidden payloads only print a message. Nothing here is real malware and nothing was downloaded.
- Two samples (`mal-evasive`) are deliberately written to evade SupplyShield, so the evaluation is fair.

`labels.json` holds the ground truth. Regenerate everything with:

```
python samples/make_samples.py
```

Even though they are harmless, **never `pip install` or `npm install` these folders**.
