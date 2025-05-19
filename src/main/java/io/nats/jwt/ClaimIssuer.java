// Copyright 2021-2024 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package io.nats.jwt;

import io.nats.json.JsonSerializable;
import io.nats.nkey.NKey;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;

import static io.nats.json.Encoding.base64UrlEncodeToString;
import static io.nats.jwt.JwtUtils.ENCODED_CLAIM_HEADER;
import static io.nats.jwt.JwtUtils.currentTimeSeconds;
import static io.nats.nkey.NKeyUtils.base32Encode;

public class ClaimIssuer {
    String aud;
    String jti;
    Long iatInput;
    Long expInput;
    long iatResolved;
    long expResolved;
    String iss;
    String name;
    String nbf;
    String sub;
    JsonSerializable nats;
    Duration expiresInInput;

    public String issueJwt(NKey signingKey) throws GeneralSecurityException, IOException {
        iatResolved = iatInput == null ? currentTimeSeconds() : iatInput;
        if (expInput == null) {
            if (expiresInInput != null) {
                long millis = expiresInInput.toMillis();
                if (millis > 0) {
                    expInput = iatResolved + (millis / 1000);
                }
            }
        }
        expResolved = expInput == null ? 0 : expInput;

        Claim claim = new Claim(this);

        // Issue At time is stored in unix seconds
        String initialJson = claim.toJson();

        // Compute jti, a base32 encoded sha256 hash
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] encoded = sha256.digest(initialJson.getBytes(StandardCharsets.US_ASCII));

        String issueJti = new String(base32Encode(encoded));
        initialJson = Claim.toJson(claim, issueJti);

        // all three components (header/body/signature) are base64url encoded
        String encBody = base64UrlEncodeToString(initialJson);

        // compute the signature off of header + body (. included on purpose)
        byte[] sig = (ENCODED_CLAIM_HEADER + "." + encBody).getBytes(StandardCharsets.UTF_8);
        String encSig = base64UrlEncodeToString(signingKey.sign(sig));

        // append signature to header and body and return it
        return ENCODED_CLAIM_HEADER + "." + encBody + "." + encSig;
    }

    public ClaimIssuer nats(JsonSerializable nats) {
        this.nats = nats;
        return this;
    }

    public ClaimIssuer aud(String aud) {
        this.aud = aud;
        return this;
    }

    public ClaimIssuer iss(String iss) {
        this.iss = iss;
        return this;
    }

    public ClaimIssuer name(String name) {
        this.name = name;
        return this;
    }

    public ClaimIssuer nbf(String nbf) {
        this.nbf = nbf;
        return this;
    }

    public ClaimIssuer sub(String sub) {
        this.sub = sub;
        return this;
    }

    public ClaimIssuer iat(long iat) {
        this.iatInput = iat;
        return this;
    }

    public ClaimIssuer exp(Long exp) {
        this.expInput = exp;
        return this;
    }

    public ClaimIssuer expiresIn(Duration expiresIn) {
        this.expiresInInput = expiresIn;
        return this;
    }
}
