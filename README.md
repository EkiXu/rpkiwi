# rpkiwi

<p align="center">
  <img src="docs/assets/banner.png" alt="rpkiwi logo" width="240">
</p>

rpkiwi is a stateful, grammar-aware differential testing framework for
Cross-Publication-Origin attacks on RPKI validation. It combines Alloy audit
models of seven relying-party (RP) implementations with a fuzzing framework
that preserves validator state across multi-origin publication lifecycles.

# How to cite us?

This framework is based on our research, **"Rethinking Isolation in RPKI:
Cross-Publication-Origin Attacks on RPKI Validation"**, accepted at CCS '26.

If you want to cite us, please use the following (BibTeX) reference:

```bibtex
@inproceedings{10.1145/3830454.3846546,
author = {Wang, Qi and Chen, Jianjun and Guo, TaoFei and Zhang, Minghao and Zhang, Yuheng and Yang, Jingcheng},
title = {Rethinking Isolation in RPKI: Cross-Publication-Origin Attacks on RPKI Validation},
year = {2026},
isbn = {9798400728716},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3830454.3846546},
doi = {10.1145/3830454.3846546},
booktitle = {Proceedings of the 2026 ACM SIGSAC Conference on Computer and Communications Security},
pages = {2104–2117},
numpages = {14},
keywords = {rpki, rpki validators, routing security, protocol security},
location = {The Hague, Netherlands},
series = {CCS '26}
}
```

## Disclaimer

This artifact is intended for security research in an isolated laboratory. Do
not publish crafted RPKI objects to production repositories, and do not use the
framework to disrupt production RPKI validation. The authors are not responsible
for any illegal or damaging use of the provided code or data.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
