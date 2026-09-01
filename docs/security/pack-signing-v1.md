# Pack signing authority v1

This document defines `SangrepPackSignatureV1`, `SangrepPackUnsignedEnvelopeV1`, and
`SangrepPackTrustRootsV1`. The normative schema is
[`schemas/sangrep-pack-signature-v1.json`](../../schemas/sangrep-pack-signature-v1.json).

## Signed bytes

The signature suite is Ed25519 as defined by RFC 8032. The signed message is exactly:

```text
ASCII("SANGREP-PACK-SIGNATURE-V1") || 0x00 || RFC8785(unsignedEnvelope)
```

The envelope contains only closed string-valued identity and digest fields. Its JSON must be UTF-8
RFC 8785 canonical bytes. The signature field is outside the envelope and is never recursively
hashed. Signatures are canonical base64 over exactly 64 bytes.

The key ID is `ed25519-sha256:` followed by 64 lowercase hexadecimal characters derived from
SHA-256 over the exact 32 raw Ed25519 public-key bytes. Alternate algorithms, encodings, and
permissive base64 decoding are not v1.

## Verification order

Consumers fail closed in this order:

1. parse the closed manifest, envelope, signature, and embedded trust registry;
2. rederive the public-key ID and manifest/compatibility/conformance bindings;
3. reject unknown, wrong-publisher, wrong-role, disallowed-channel, not-yet-valid, expired, or
   revoked roots;
4. reject development manifests or roots in release builds;
5. verify Ed25519 over the exact domain-separated canonical bytes; and
6. compare the archive, payload tree, SBOM, license bundle, and receipt digests before activation.

Pack-publisher and catalog keys use different roles. A catalog cannot add trust. Cached reuse and
rollback use the current embedded denylist, so an older artifact does not bypass revocation.

## Development, rotation, and revocation

[`trust/development-pack-roots-v1.json`](../../trust/development-pack-roots-v1.json) contains one
public verification root whose only allowed channel is `development`. Release builds must reject
it. This repository contains no production release root and authorizes no production signing.

Rotation requires a trust-policy version increment, a new reviewed public root, and an explicit
bounded overlap. The old root's `validUntil` closes the overlap. Revocation adds the key ID to the
embedded denylist and cannot be undone by a later catalog or policy successor. A new registry ships
only through a reviewed contracts artifact and consuming application update.

Canonical positive and malicious negative cases are in
[`vectors/v1/pack-signing.json`](../../vectors/v1/pack-signing.json).
