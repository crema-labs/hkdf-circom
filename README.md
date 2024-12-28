# HKDF Circuit Implementation

## Overview

Implementation of HKDF (HMAC-based Key Derivation Function) using SHA-256 in Circom 2.1.8. The circuit follows [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)'s extract-then-expand paradigm.


## Components

### 1. HKDFSha256 Template
Main template that combines Extract and Expand operations.

```circom
template HKDFSha256(s, i, k, m, n)
```

Parameters:
- `s`: Salt length
- `i`: Info length
- `k`: Input key length
- `m`: Number of output keys
- `n`: Output key length

Signals:
- Input: `salt[s]`, `info[i]`, `key[k]`
- Output: `out[m][n]`

### 2. Extract Template
Implements HKDF-Extract using HMAC-SHA256.

```circom
template Extract(s, k)
```

Parameters:
- `s`: Salt length
- `k`: Key length

Signals:
- Input: `salt[s]`, `key[k]`
- Output: `out[32]` (fixed 32-byte SHA-256 output)

### 3. Expand Template
Implements HKDF-Expand using HMAC-SHA256.

```circom
template Expand(i, k, m, n)
```

Parameters:
- `i`: Info length
- `k`: Key length (PRK)
- `m`: Number of output keys
- `n`: Length per output key

Signals:
- Input: `info[i]`, `key[k]`
- Output: `out[m][n]`

## Implementation Details

### Extract Operation
1. Uses HmacSha256 component
2. Sets input key material as message
3. Uses salt as HMAC key
4. Produces 32-byte PRK (Pseudorandom Key)

### Expand Operation
1. Calculates required rounds: `rounds = ceil((m*n)/32)`
2. First round:
   - Message = info || 0x01
   - Key = PRK
3. Subsequent rounds:
   - Message = prev_hash || info || counter
   - Key = PRK
   - Counter increments each round
4. Output mapping:
   - Maps expanded keys to output array
   - Uses byte-wise indexing for proper output arrangement

### Signal Flow
```
Input Key Material → Extract → PRK → Expand → Output Key Material
        ↑              ↑        ↑       ↑
       Salt           HMAC    Info    HMAC[rounds]
```

## Dependencies

- HMAC circuit (`./hmac/circuits/hmac.circom`)
- Circom 2.1.8 or higher