# JSONTestSuite

The `test_parsing` cases of [JSONTestSuite](https://github.com/nst/JSONTestSuite), by Nicolas
Seriot, at commit `1ef36fa01286573e846ac449e8683f8833c5b26a` (2024-11-22), copied unchanged from
snaphop-jsonl's copy (`jsonl/src/test/resources/JSONTestSuite`). MIT licensed; see `LICENSE`.

Files starting `y_` are JSON a parser must accept, `n_` JSON it must refuse, and `i_` JSON it
may do either with. The client data reader (`ClientData.Json` in `snaphop-webauthn`) is checked
against them, with the cases where it is stricter by design listed in `JsonTestSuiteTest`.
