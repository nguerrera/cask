# CASK Secrets
## Standard Backus-Naur Form (BNF)
```
<key> ::= <sensitive-data>      ; A sequence of security-sensitive bytes.
          <cask-signature>      ; A fixed signature (`QJJQ`) that enables high-performance textual identification.
          <sensitive-data-size> ; A count of 16-byte segments encoded as sensitive data ('B' = 1 x 16 bytes = 128 bits, etc).
          <optional-data-size>  ; A count of 3-byte optional data segments, 'A' = 0 = 0 bytes, 'B' = 1 = 3 bytes, etc.
          <timestamp>           ; The year, month, day, hour, and minute of secret allocation.
          <provider-kind>       ; A provider-defined key kind.
          [<optional-fields>]   ; Optional fields comprising provider-defined data.
          <provider-signature>  ; A fixed signature identifying the secret provider.
          <correlating-id>      ; A 20-byte non-sensitive correlating identifier for the secret (see below).

<sensitive-data> ::= <128-bits-padded> | <256-bits-padded>                  ; The sensitive data is a secret generated for a security purpose,
                   | <384-bits> | <512-bits-padded>                         ; such as random data generated by a cryptographically secure random
                                                                            ; number generator (RNG), a Hash Message Authentication Code (HMAC),
                                                                            ; an output of a Key Derivation Function (KDF), etc. CASK specifies
                                                                            ; a storage location and component size for this data but does not
                                                                            ; specify a particular cryptographic algorithm or method for
                                                                            ; generating it. The size of this component must conform to the
                                                                            ; encoded <sensitive-data-size> value.
<128-bits-padded>  ::= 21 * <base64url> <base64-four-zeros-suffix> 'AA'     ; The total sensitive data comprises 128 bits encoded as 21
                                                                            ; characters x 6 bits (126 bits) and 1 character providing
                                                                            ; 2 bits of sensitive data padded with 0000b. The final
                                                                            ; characters `AA` comprise 12 bits of additional padding
                                                                            ; that brings the component to a 3-byte boundary.
<256-bits-padded>  ::= 42 * <base64url> <base64-two-zeros-suffix> 'A'       ; The total sensitive data comprises 256 bits encoded as 42
                                                                            ; characters comprising 6 bits of sensitive data = 252 bits and
                                                                            ; The final characters `A` comprises 6 bits of additional
                                                                            ; padding that brings the component to a 3-byte boundary.
<384-bits>  ::= 64 * <base64url>                                            ; The total sensitive data comprises 384 bits encoded as 64
                                                                            ; 6-bit characters. No reserved padding is required, as
                                                                            ; 384 bits (48 bytes) aligns to a 3-byte boundary.
<512-bits-padded>  ::= 85 * <base64url> <base64-four-zeros-suffix> 'AA'     ; The total sensitive data comprises 512 bits encoded as 85
                                                                            ; characters x 6 bits (510 bits) and 1 character providing
                                                                            ; 2 bits of sensitive data padded with 0000b. The final 
                                                                            ; characters `AA` comprise 12 bits of additional padding
                                                                            ; that brings the component to a 3-byte boundary.
<base64url> ::= 'A'..'Z' | 'a'..'z' | '0'..'9' | '-' | '_'                  ; Base64 URL-safe printable characters. The '=' padding character is excluded.
<base64-two-zeros-suffix> ::= 'A' | 'E' | 'I' | 'M' | 'Q' | 'U' | 'Y' | 'c' 
                            | 'g' | 'k' | 'o' | 's' | 'w' | '0' | '4' | '8' ; Base64 printable characters with two trailing zero bits.
<base64-four-zeros-suffix> ::= 'A' | 'Q' | 'g' | 'w'                        ; Base64 printable characters with four trailing zero bits.
<cask-signature> ::= 'QJJQ'                                                 ; Fixed signature identifying the CASK key.
<sensitive-data-size> ::= 'B'..'E'                                          ; 'B' = 128-bit secret size, 'C' = 256-bit, 'D' = 384-bit, 'E' = 512-bit.
<optional-data-size> ::= 'A'..'E'                                           ; 'A' = zero 3-byte optional data segments, 'B' = one optional 3-byte
                                                                            ; segment, up to a maximum of 'E' = 4 optional 3-byte data segments.
<timestamp> ::= <year> <month> <day> <hour> <minute>                        ; Time-of-allocation timestamp components.
<year> ::= <base64url>                                                      ; Allocation year, 'A' (2025) to '_' (2088).
<month> ::= 'A'..'L'                                                        ; Allocation month, 'A' (January) to 'L' (December).
<day> ::= 'A'..'Z' | 'a'..'e'                                               ; 'A' = day 1, 'B' = day 2, ... 'e' = day 31
<hour> ::= 'A'..'X'                                                         ; Represents hours 0-23. 'A' = hour 0 (midnight), ... 'X' = hour 23.
<minute> ::= 'A'..'7'                                                       ; Represents minutes 0-59.
<provider-kind> ::= <base64url>                                             ; Provider-defined key kind.
<provider-signature> ::= 4 * <base64url>                                    ; Provider identifier (24 bits).
<optional-fields> ::= { <optional-field> }                                  ; Zero or more 4-character (24-bit) sequences of optional data.
<optional-field> ::= 4 * <base64url>                                        ; Each optional field is 4 characters (24 bits). This keeps data
                                                                            ; cleanly aligned along 3-byte/4-encoded character boundaries,
                                                                            ; facilitating readability of encoded form as well as byte-wise use.
<correlating-id> ::= 20 * <base64url>                                       ; 120 bits of unique, non-sensitive data generated by a cryptographically
                                                                            ; secure RNG. This data is not sensitive and is designed to correlate 
                                                                            ; metadata for generated secrets with reports of exposure and other data.
                                                                            ; As a non-security-sensitive component, this data MUST NOT be used
                                                                            ; to drive security-sensitive operations.
```

## Byte-wise Rendering Example for 256-bit Key (no optional data)
|Byte Range|Decimal|Hex|Binary|Description|
|-|-|-|-|-|
|decodedKey[..31]|0...255|0x0...0xFF|00000000b...11111111b|256 bits of sensitive data produced by a cryptographically secure RNG, an HMAC, etc.|
|decodedKey[32]|0|0x00|00000000b| 8 bits of reserved padding.
|decodedKey[33..36]| 37, 4, 9  |0x40, 0x92, 0x50| 00100000b, 10010010b, 01010000b | Decoded 'QJJQ' signature.
|decodedKey[36..39]||||Sensitive data size, optional-data-size, timestamp year and month encoded in 4 six-bit segments.
|decodedKey[39..42]||||Timestamp day, hour, minutes and provider kind data encoded in 4 six-bit segments.
|decodedKey[42..45]|0...255|0x0...0xFF|00000000b...11111111b| Provider signature, e.g. , '0x4c', '0x44', '0x93' (base64-encoded as 'TEST')
|decodedKey[45..60]||||16 byte non-sensitive, unique correlating id.

## URL-Safe Base64-Encoded Rendering Example for 256-bit Key (no optional data)
|String Range|Text Value|Description|
|-|-|-|
|encodedKey[..42] | 'A'...'_' | 252 bits of randomized data generated by cryptographically secure RNG
|encodedKey[42] | <base64-two-zeros-suffix> | 4 bits of randomized data followed by 2 zero bits. See the <base64-two-zeros-suffix> definition for legal values.
|encodedKey[43] | 'A' | The 6-bit encoded sensitive component size.
|encodedKey[44..48]|'QJJQ'| Fixed CASK signature.
|encodedKey[48]|'A'...'D'| Sensitive component key size, 'A' (128-bit), 'B' (256-bit), 'C' (384-bit) or 'D' (512-bit).
|encodedKey[49]|'A'...'?'| Count of optional 3-byte data segments, 'A' == 0 bytes, 'B' == 3 bytes, capped at ?? (maximum permissible would be 189 bytes, 63 * 3)
|encodedKey[50]|'A'...'_'|Represents the year of allocation time, 'A' (2025) to '_' (2088)|
|encodedKey[51|'A'...'L'|Represents the month of allocation time, 'A' (January) to 'L' (December)|
|encodedKey[52]|'A'...'Z'\|'a'..'e'|Represents the day of allocation time, 'A' (0) to 'e' (31)|
|encodedKey[53]|'A'...'X'|Represents the hour of allocation time, 'A' (hour 0 or midnight) to 'X' (hour 23).
|encodedKey[54]|'A'...'7'| Represents the minute of allocation time.
|encodedKey[55]|'A'...'_'| Provider-defined key kind.
|encodedKey[55..75]|'A'...'_'| Correlating id.
```
