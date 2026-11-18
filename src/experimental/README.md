# experimental/

Intentionally empty in this build.

QSC_ALG_EXPERIMENTAL_QS_STREAM is reserved in the identifier table but has no
implementation and is not registered as supported. No original cryptographic
primitive ships in qs_crypt 0.1.0.

Before any original primitive is added here it must document: construction,
assumptions, intended security properties, known limitations, attack surface,
the reason it is experimental, and the evidence required before production use
(at minimum: published specification, reference vectors, and independent
cryptanalysis). Until then it stays labelled EXPERIMENTAL / NOT FOR PRODUCTION.
