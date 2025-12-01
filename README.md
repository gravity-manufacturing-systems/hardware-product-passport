# Product Passport ID & Secure NFC Binding Specification

Version: 1.1.0   
Owner: @gravity-manufacturing-systems

## 1. Purpose

This document specifies a scheme for uniquely identifying physical products using:

- A **virtual item ID** (`V`), managed in the backend (“product passport”).
- A **secure NFC tag ID** (`T`), provided by the NFC chip.
- A **cryptographic binding** between `V` and `T`, signed by a backend-controlled private key.
- A **mandatory secure NFC challenge–response** using a per-tag secret key stored in the secure NFC chip (e.g. NXP DESFire, NTAG 424 DNA, or equivalent).

The goals are to:

1. Provide a globally unique, hard-to-forge identity for each physical item.
2. Bind the physical NFC tag to the virtual product passport.
3. Make naive cloning (copying UID + NDEF) insufficient to pass verification.
4. Allow online authenticity verification and lifecycle tracking for each item.

The specification is integration-ready: it defines data structures, flows, and API contracts.

---

## 2. Terminology

- **Item**: A single physical finished good.
- **Virtual ID (`V`)**: Backend-generated, globally unique identifier for an item.
- **Tag ID (`T`)**: NFC chip unique identifier (UID) read from the secure NFC tag.
- **Metadata (`M`)**: Fixed, signed attributes such as SKU, batch, plant.
- **Private key (`SK`)**: Backend-only signing key for binding `V` and `T`.
- **Public key (`PK`)**: Public verifier key, distributed to verifiers.
- **Signature (`sig`)**: Digital signature over a canonical payload derived from `V`, `T`, and `M`.
- **Tag secret key (`K_tag`)**: Symmetric key derived from a master key and stored only inside the secure NFC chip.
- **Master key (`K_master`)**: Backend/HSM-held key used to derive `K_tag`.
- **MAC**: Message Authentication Code computed by the secure NFC chip using `K_tag`.
- **Passport**: Backend record for an item, including lifecycle and status.
- **Secure NFC Tag**: Tag supporting hardware-backed cryptographic challenge–response and protected key storage. In this specification, **secure NFC tags are mandatory**, and MUST be NXP DESFire, NTAG 424 DNA, or a functionally equivalent secure NFC platform.

---

## 3. Identifier Model

### 3.1 Virtual Item ID (`V`)

- Type: 128-bit or 256-bit random value (e.g. UUIDv4, ULID, or equivalent).
- Requirements:
  - Globally unique.
  - Non-guessable (high entropy).
- Representation:
  - Canonical string (e.g. `uuid` or `base32` string).
- Example: `e38c0d7b-2815-4c7d-a7f6-7a30e935f91b`.

### 3.2 Tag ID (`T`)

- Type: Secure NFC chip UID (byte sequence).
- Representation:
  - Raw bytes (binary) for storage.
  - Hex-encoded string for APIs and logs.
- Example: `04A2246FB82C80`.

The UID MUST be read from the secure NFC chip and MUST NOT be overridden during personalization.

### 3.3 Metadata (`M`)

Canonical, immutable metadata included in the signed payload:

- `sku`: Product SKU (string).
- `batch_id`: Production batch identifier (string).
- `plant_id`: Identifier for manufacturing plant (string).
- `issued_at`: UTC timestamp of ID issuance (ISO 8601).

Example:

```json
{
  "sku": "SKU-12345",
  "batch_id": "BATCH-2025-03-01-01",
  "plant_id": "PLANT-MTL-01",
  "issued_at": "2025-03-01T12:34:56Z"
}
```

### 3.4 Signing Algorithm (V–T Binding)

Recommended:

- Algorithm: Ed25519 (or equivalent modern curve signature).
- Key pair:
  - `SK`: Stored only in secure backend / HSM.
  - `PK`: Available to all verifiers.

Signature input (canonical payload):

```text
payload = canonical_json({
  "v": V,
  "t": T_hex,
  "m": M,
  "key_version": key_version
})
sig = Sign(SK[key_version], payload)
```

Where:

- `canonical_json` produces deterministic JSON (sorted keys, stable formatting).

### 3.5 Tag Secret Key (`K_tag`) and MAC Algorithm

Secure NFC tag MUST:

- Store a secret key `K_tag` in secure, non-readable memory.
- Support a hardware MAC or “secure unique message” (SUN) style primitive.

Derivation model:

```text
K_tag = KDF(K_master[key_version], T)
```

Where:

- `K_master[key_version]` is a backend/HSM-stored master key for a given key version.
- `KDF` is a standard key-derivation function (e.g. KDF based on AES or HKDF).
- `T` is the UID (or other per-tag identifier supported by the secure NFC).

The NFC programming process MUST load `K_tag` onto the secure NFC chip using the vendor’s secure key loading mechanism (specific to DESFire/NTAG 424 DNA or equivalent).

MAC input (for verification):

```text
mac_payload = C || T || V_optional
MAC_tag = MAC(K_tag, mac_payload)
```

Where:

- `C` is a random challenge (nonce) provided by the verifier.
- `T` is the tag UID.
- `V_optional` may be included for additional binding (implementation choice).

The exact command-level details follow the secure NFC vendor’s specification (e.g. NTAG 424 DNA SUN-based MAC). This document specifies only the logical requirements.

---

## 4. Backend Data Model

### 4.1 Items Table (Product Passport Core)

Logical schema (SQL-ish, adapt to your ORM):

```sql
CREATE TABLE items (
  id              UUID PRIMARY KEY,        -- V
  sku             TEXT NOT NULL,
  batch_id        TEXT NOT NULL,
  plant_id        TEXT NOT NULL,
  issued_at       TIMESTAMPTZ NOT NULL,
  tag_id_hex      TEXT NOT NULL,          -- T_hex
  signature       TEXT NOT NULL,          -- sig (base64)
  key_version     INTEGER NOT NULL,
  status          TEXT NOT NULL,          -- 'manufactured', 'in_market', 'sold', 'revoked', 'recycled', ...
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX items_v_uniq ON items (id);
CREATE UNIQUE INDEX items_tag_id_uniq ON items (tag_id_hex);
```

### 4.2 Events Table (Lifecycle & Scans)

```sql
CREATE TABLE item_events (
  id              UUID PRIMARY KEY,
  item_id         UUID NOT NULL REFERENCES items(id),
  event_type      TEXT NOT NULL,          -- 'manufactured', 'scan', 'sold', 'resold', 'recycled', ...
  source          TEXT NOT NULL,          -- 'factory', 'warehouse', 'retail', 'consumer_app', ...
  payload         JSONB NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX item_events_item_id_idx ON item_events (item_id);
```

The `payload` for scan events MUST include fields for MAC verification results and anomaly classification.

---

## 5. NFC Tag Content Layout

### 5.1 Minimum Data on Tag (NDEF Record)

Recommended NDEF payload (JSON):

```json
{
  "v": "e38c0d7b-2815-4c7d-a7f6-7a30e935f91b",
  "sig": "BASE64_SIGNATURE",
  "kv": 1,
  "algo": "ed25519"
}
```

Where:

- `v`: Virtual item ID (`V`).
- `sig`: Signature of the canonical payload (`payload` defined in §3.4).
- `kv`: Key version for `SK` and `K_master`.
- `algo`: Signature algorithm identifier.

Optionally include:

- `u`: Verification URL, e.g. `https://p.example.com/i/e38c0...`.

### 5.2 Tag UID (`T`)

- The UID MUST be read from the secure NFC tag on every scan.
- The UID MUST NOT be emulated or overridden by personalization scripts.

### 5.3 Secure NFC Requirement

All tags used in this system MUST:

- Be NXP DESFire, NTAG 424 DNA, or a functionally equivalent secure NFC chip that:
  - Supports a hardware-protected secret key store (`K_tag`).
  - Supports a MAC or SUN-style challenge–response protocol.
- Be provisioned so that:
  - `K_tag` is loaded and protected according to vendor security guidelines.
  - Only authenticated command flows can access secure functions.

Plain, non-secure NFC tags (simple UID + NDEF only) MUST NOT be used.

---

## 6. Provisioning Flow (Manufacturing)

### 6.1 Pre-conditions

- Backend has signing keys configured: `SK[key_version]`.
- Backend has master keys configured: `K_master[key_version]`.
- Secure NFC encoder devices are authenticated (API keys, mTLS, or equivalent).
- Secure NFC personalization process for DESFire/NTAG 424 DNA or equivalent is in place.

### 6.2 Steps

1. **Read Tag UID**

   - Secure encoder reads NFC UID: `T`.

2. **Derive Tag Secret Key (`K_tag`)**

   ```text
   K_tag = KDF(K_master[key_version], T)
   ```

   - The derivation MUST be deterministic and unique per `T` and `key_version`.
   - `K_tag` MUST NOT be stored in the encoder or printed/logged; it is written directly into the secure NFC chip as a key.

3. **Generate Virtual ID (`V`)**

   - Either:
     - Encoder requests `V` from backend via an API, or
     - Backend directly generates `V` and returns it to the encoder.
   - Uniqueness enforced by DB constraint.

4. **Assemble Metadata (`M`)**

   - Determine: `sku`, `batch_id`, `plant_id`, `issued_at = now()`.

5. **Build Canonical Payload for Signature**

   ```jsonc
   {
     "v": "V",
     "t": "T_hex",
     "m": {
       "sku": "...",
       "batch_id": "...",
       "plant_id": "...",
       "issued_at": "..."
     },
     "key_version": key_version
   }
   ```

6. **Sign Payload**

   ```text
   payload = canonical_json(above)
   sig_bytes = Sign(SK[key_version], payload)
   sig_b64 = base64(sig_bytes)
   ```

7. **Persist in Backend**

   Insert row into `items`:

   - `id        = V`
   - `tag_id_hex = T_hex`
   - `signature = sig_b64`
   - `key_version = key_version`
   - `status = 'manufactured'`
   - plus metadata.

8. **Encode Tag NDEF**

   Write NDEF record to secure NFC chip:

   ```json
   {
     "v": "V",
     "sig": "sig_b64",
     "kv": key_version,
     "algo": "ed25519"
   }
   ```

   Optionally add:

   - URL record for passport lookup: `https://p.example.com/i/V`.

9. **QA / Read-back and MAC Test**

   - Immediately:
     - Read tag UID `T_read` and NDEF data.
     - Verify `T_read == T`.
     - Call backend QA endpoint to perform:
       - Signature verification (`sig`).
       - A test challenge–response MAC to validate `K_tag` integration.
   - On failure:
     - Mark tag as defective.
     - Mark corresponding `V` as `revoked` (or `invalid`).
     - Repeat with a new tag.

---

## 7. Scan & Verification Flow

### 7.1 Actors

- **Scanner app**: Mobile or edge application that:

  - Reads secure NFC (UID + NDEF).
  - Executes secure challenge–response with tag.
  - Calls backend for verification.

- **Verification backend**: API that:
  - Verifies `(V, T, sig)` using `PK`.
  - Verifies MAC using `K_master`.
  - Returns passport and authenticity status.

### 7.2 NFC Scan Procedure

1. Scanner reads:

   - Tag UID: `T_read`.
   - NDEF JSON: `{ "v": V, "sig": sig_b64, "kv": kv, "algo": "ed25519" }`.

2. Scanner obtains a random challenge `C`:

   - Either generated locally (if protocol allows) or by requesting it from backend:
     - `POST /v1/passport/challenge` → `{ "challenge": "C_base64" }`.

3. Scanner interacts with secure NFC tag:

   - Executes secure challenge–response command sequence defined by the tag family (DESFire/NTAG 424 DNA or equivalent), producing:

     ```text
     MAC_tag = MAC(K_tag, C || T_read || V_optional)
     ```

   - The exact command format is tag-specific; the output MUST be a MAC that the backend can recompute using `K_master` and the same derivation logic.

4. Scanner builds verification request:

   ```json
   {
     "v": "V",
     "t": "T_read_hex",
     "sig": "sig_b64",
     "kv": kv,
     "mac": "BASE64_ENCODED_MAC_TAG",
     "challenge": "BASE64_ENCODED_C",
     "client": {
       "app_id": "consumer_app",
       "version": "1.2.3",
       "platform": "ios"
     },
     "environment": {
       "ts": "2025-03-01T12:45:00Z",
       "ip": "203.0.113.42",
       "geo": {
         "lat": 45.5017,
         "lng": -73.5673,
         "country": "CA"
       }
     }
   }
   ```

5. Scanner calls backend verification endpoint (§7.3).

### 7.3 Verification API

#### 7.3.1 Endpoint

- Method: `POST`
- Path: `/v1/passport/verify`

#### 7.3.2 Request Body

```json
{
  "v": "string", // required: V
  "t": "string", // hex string of tag UID (T), required
  "sig": "string", // base64 signature over payload(V, T, M), required
  "kv": 1, // key version, required
  "mac": "string", // base64 MAC from secure tag, required
  "challenge": "string", // base64 challenge C, required
  "client": {
    // optional, for analytics
    "app_id": "string",
    "version": "string",
    "platform": "string"
  },
  "environment": {
    // optional, for anti-abuse
    "ts": "2025-03-01T12:45:00Z",
    "ip": "string",
    "geo": {
      "lat": 0,
      "lng": 0,
      "country": "string"
    }
  }
}
```

#### 7.3.3 Backend Verification Steps

Backend MUST:

1. Lookup `items` row with `id = V`.

   - If not found → `status = "invalid"`.

2. Check `items.tag_id_hex == t`.

   - If mismatch → set `flags.uid_mismatch = true`.

3. Reconstruct canonical payload:

   ```jsonc
   {
     "v": V,
     "t": t,
     "m": {
       "sku": items.sku,
       "batch_id": items.batch_id,
       "plant_id": items.plant_id,
       "issued_at": items.issued_at
     },
     "key_version": items.key_version
   }
   ```

4. Verify signature:

   ```text
   payload = canonical_json(above)
   valid_sig = Verify(PK[items.key_version], payload, base64_decode(sig))
   ```

   - If invalid → `flags.signature_invalid = true`.

5. Recompute `K_tag` and MAC:

   ```text
   K_tag = KDF(K_master[items.key_version], t)
   C = base64_decode(challenge)
   expected_mac = MAC(K_tag, C || t || V_optional)
   valid_mac = (expected_mac == base64_decode(mac))
   ```

   - If invalid → `flags.mac_invalid = true`.

6. Run anomaly detection:

   - Check scan frequency, geo, status transitions, etc.
   - Set `flags.scan_anomaly` if thresholds exceeded.

7. Determine `status` from combination of:
   - Item status (`items.status`).
   - `flags`.

Example logic:

- If `signature_invalid` or `mac_invalid` → `status = "invalid"`.
- Else if `uid_mismatch` or `scan_anomaly` → `status = "suspicious"`.
- Else if `items.status` in (`revoked`, `recycled`) → `status = items.status`.
- Else → `status = "genuine"`.

#### 7.3.4 Response Body (Success)

```json
{
  "status": "genuine", // 'genuine' | 'suspicious' | 'revoked' | 'recycled' | 'invalid'
  "item": {
    "v": "e38c0d7b-2815-4c7d-a7f6-7a30e935f91b",
    "sku": "SKU-12345",
    "batch_id": "BATCH-2025-03-01-01",
    "plant_id": "PLANT-MTL-01",
    "issued_at": "2025-03-01T12:34:56Z",
    "status": "in_market"
  },
  "flags": {
    "uid_mismatch": false,
    "signature_invalid": false,
    "mac_invalid": false,
    "scan_anomaly": false
  },
  "messages": ["Item appears genuine.", "Secure NFC MAC validated."]
}
```

#### 7.3.5 Error Responses

- `400 Bad Request`: malformed JSON, missing required fields.
- `404 Not Found`: `V` not found.
- `410 Gone`: item revoked or recycled; MAY still return explanatory info.

---

## 8. Security Considerations

### 8.1 Binding V and T (Non-rebinding)

The signature over `V` and `T` ensures:

- Attackers cannot create a new valid `(V, T')` pair without `SK`.
- Modifying either `V` or `T` breaks the signature.
- Backend enforces a single immutable mapping `(V, T)`.

This prevents re-binding attacks (changing which tag UID is claimed to belong to a virtual item).

### 8.2 Mandatory Secure NFC Challenge–Response

To address cloning:

- Secure NFC tags MUST hold `K_tag` derived from `K_master` and `T`.
- Tags MUST support a MAC/SUN computation used in challenge–response.
- On every verification:
  - Backend derives `K_tag` from `K_master` and `T`.
  - Backend validates MAC from tag using `C`, `T`, and optionally `V`.

Result:

- Copying NDEF + UID is insufficient.
- An attacker without `K_master` (or a genuine tag with `K_tag`) cannot produce correct MACs.
- Full emulation of the tag now requires breaking the secure NFC’s hardware or compromising `K_master`.

### 8.3 Key Management

- Maintain `key_version` for:
  - `SK[key_version]` (V–T binding signature).
  - `K_master[key_version]` (secure NFC MAC).
- Implement rotation:
  - New items use new `key_version`.
  - Old items remain verifiable by keeping old keys available in secure storage.
- Keys MUST be stored in HSM or equivalent secure key management infrastructure.

### 8.4 Anti-abuse / Anomaly Detection

Backend SHOULD:

- Log every scan as an `item_events` row.
- Implement heuristics, e.g.:
  - Excessive scan rate per item.
  - Impossible geo/time sequences.
  - Scans in regions where SKU is not distributed.
- Escalate suspicious patterns:
  - Flag items as `suspicious` or `revoked`.
  - Trigger operational workflows (partner alerts, batch investigation).

---

## 9. Item Lifecycle & Status

Suggested `items.status` values:

- `manufactured` – ID issued and tag provisioned.
- `in_market` – Item shipped and available for sale.
- `sold` – First retail/consumer sale recorded.
- `resold` – Secondary market event recorded.
- `revoked` – Marked as counterfeit, compromised, or recalled.
- `recycled` – Item end-of-life processed.

State transitions SHOULD be strictly controlled and logged via `item_events`.

---

## 10. Integration Checklist

To implement this specification:

1. **Cryptography**

   - Implement Ed25519 (or equivalent) for signing/verifying `payload(V, T, M)`.
   - Implement canonical JSON serialization.
   - Implement KDF for deriving `K_tag` from `K_master` and `T`.
   - Implement MAC verification compatible with chosen secure NFC (DESFire/NTAG 424 DNA or equivalent).

2. **Backend**

   - Implement `items` and `item_events` tables.
   - Implement ID generation and uniqueness enforcement.
   - Implement provisioning APIs for encoders (if centralized).
   - Implement `/v1/passport/challenge` and `/v1/passport/verify`.
   - Implement anomaly detection logic and alerts.

3. **Secure NFC Encoding**

   - Choose secure NFC platform: NXP DESFire / NTAG 424 DNA / equivalent.
   - Implement secure onboarding and key loading for `K_tag`.
   - Implement NDEF write of `{ v, sig, kv, algo }`.
   - Implement QA read-back and test MAC.

4. **Scanner Apps**

   - Implement:
     - NFC read (UID + NDEF).
     - Secure NFC challenge–response to compute MAC.
   - Integrate with backend:
     - Request challenge (if not locally generated).
     - Call `/v1/passport/verify` with `V`, `T`, `sig`, `kv`, `mac`, `challenge`.
   - Render authenticity status and passport details.

5. **Operations & Monitoring**
   - Centralize logs for scan events.
   - Build dashboards for:
     - Scan distribution.
     - Anomalies and flagged items.
   - Define operational playbooks for suspicious and revoked items.

---

## 11. Change Management

- This document is versioned. Current version: `1.1.0`.
- Any backwards-incompatible change MUST bump the major version.
- New fields SHOULD be additive and optional whenever possible.
- Verification for previously issued items MUST remain supported.

---

## 12. References

- Ed25519: https://ed25519.cr.yp.to
- NFC Forum NDEF Specification
- NXP DESFire and NTAG 424 DNA documentation (for concrete MAC/SUN command sequences)
- GS1 Digital Link (if interoperable identifiers are required)
