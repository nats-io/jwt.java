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

import io.nats.client.NKey;
import io.nats.client.support.JsonSerializable;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Duration;

import static io.nats.client.support.Encoding.fromBase64Url;
import static io.nats.client.support.Encoding.toBase64Url;

public abstract class JwtUtils {
    public static final String USER_CLAIM_TYPE = "user";
    public static final String AUTH_REQUEST_CLAIM_TYPE = "authorization_request";
    public static final String AUTH_RESPONSE_CLAIM_TYPE = "authorization_response";
    public static final String ENCODED_CLAIM_HEADER = toBase64Url("{\"typ\":\"JWT\", \"alg\":\"ed25519-nkey\"}");
    public static final long NO_LIMIT = -1;

    private JwtUtils() {} /* ensures cannot be constructed */

    /**
     * Format string with `%s` placeholder for the JWT token followed
     * by the user NKey seed. This can be directly used as such:
     * 
     * <pre>
     * NKey userKey = NKey.createUser(new SecureRandom());
     * NKey signingKey = loadFromSecretStore();
     * String jwt = issueUserJWT(signingKey, accountId, new String(userKey.getPublicKey()));
     * String.format(JwtUtils.NATS_USER_JWT_FORMAT, jwt, new String(userKey.getSeed()));
     * </pre>
     */
    public static final String NATS_USER_JWT_FORMAT = "-----BEGIN NATS USER JWT-----\n" +
            "%s\n" +
            "------END NATS USER JWT------\n" +
            "\n" +
            "************************* IMPORTANT *************************\n" +
            "NKEY Seed printed below can be used to sign and prove identity.\n" +
            "NKEYs are sensitive and should be treated as secrets.\n" +
            "\n" +
            "-----BEGIN USER NKEY SEED-----\n" +
            "%s\n" +
            "------END USER NKEY SEED------\n" +
            "\n" +
            "*************************************************************\n";

    /**
     * Get the current time in seconds since epoch. Used for issue time.
     * @return the time
     */
    public static long currentTimeSeconds() {
        return System.currentTimeMillis() / 1000;
    }

    /**
     * Issue a user JWT from a scoped signing key. See <a href="https://docs.nats.io/nats-tools/nsc/signing_keys">Signing Keys</a>
     * @param signingKey a mandatory account nkey pair to sign the generated jwt.
     * @param accountId a mandatory public account nkey. Will throw error when not set or not account nkey.
     * @param publicUserKey a mandatory public user nkey. Will throw error when not set or not user nkey.
     * @throws IllegalArgumentException if the accountId or publicUserKey is not a valid public key of the proper type
     * @throws NullPointerException if signingKey, accountId, or publicUserKey are null.
     * @throws GeneralSecurityException if SHA-256 MessageDigest is missing, or if the signingKey can not be used for signing.
     * @throws IOException if signingKey sign method throws this exception.
     * @return a JWT
     */
    public static String issueUserJWT(NKey signingKey, String accountId, String publicUserKey) throws GeneralSecurityException, IOException {
        return issueUserJWT(signingKey, publicUserKey, null, null, currentTimeSeconds(), null, new UserClaim(accountId));
    }

    /**
     * Issue a user JWT from a scoped signing key. See <a href="https://docs.nats.io/nats-tools/nsc/signing_keys">Signing Keys</a>
     * @param signingKey a mandatory account nkey pair to sign the generated jwt.
     * @param accountId a mandatory public account nkey. Will throw error when not set or not account nkey.
     * @param publicUserKey a mandatory public user nkey. Will throw error when not set or not user nkey.
     * @param name optional human-readable name. When absent, default to publicUserKey.
     * @throws IllegalArgumentException if the accountId or publicUserKey is not a valid public key of the proper type
     * @throws NullPointerException if signingKey, accountId, or publicUserKey are null.
     * @throws GeneralSecurityException if SHA-256 MessageDigest is missing, or if the signingKey can not be used for signing.
     * @throws IOException if signingKey sign method throws this exception.
     * @return a JWT
     */
    public static String issueUserJWT(NKey signingKey, String accountId, String publicUserKey, String name) throws GeneralSecurityException, IOException {
        return issueUserJWT(signingKey, publicUserKey, name, null, currentTimeSeconds(), null, new UserClaim(accountId));
    }

    /**
     * Issue a user JWT from a scoped signing key. See <a href="https://docs.nats.io/nats-tools/nsc/signing_keys">Signing Keys</a>
     * @param signingKey a mandatory account nkey pair to sign the generated jwt.
     * @param accountId a mandatory public account nkey. Will throw error when not set or not account nkey.
     * @param publicUserKey a mandatory public user nkey. Will throw error when not set or not user nkey.
     * @param name optional human-readable name. When absent, default to publicUserKey.
     * @param expiration optional but recommended duration, when the generated jwt needs to expire. If not set, JWT will not expire.
     * @param tags optional list of tags to be included in the JWT.
     * @throws IllegalArgumentException if the accountId or publicUserKey is not a valid public key of the proper type
     * @throws NullPointerException if signingKey, accountId, or publicUserKey are null.
     * @throws GeneralSecurityException if SHA-256 MessageDigest is missing, or if the signingKey can not be used for signing.
     * @throws IOException if signingKey sign method throws this exception.
     * @return a JWT
     */
    public static String issueUserJWT(NKey signingKey, String accountId, String publicUserKey, String name, Duration expiration, String... tags) throws GeneralSecurityException, IOException {
        return issueUserJWT(signingKey, publicUserKey, name, expiration, currentTimeSeconds(), null, new UserClaim(accountId).tags(tags));
    }

    /**
     * Issue a user JWT from a scoped signing key. See <a href="https://docs.nats.io/nats-tools/nsc/signing_keys">Signing Keys</a>
     * @param signingKey a mandatory account nkey pair to sign the generated jwt.
     * @param accountId a mandatory public account nkey. Will throw error when not set or not account nkey.
     * @param publicUserKey a mandatory public user nkey. Will throw error when not set or not user nkey.
     * @param name optional human-readable name. When absent, default to publicUserKey.
     * @param expiration optional but recommended duration, when the generated jwt needs to expire. If not set, JWT will not expire.
     * @param tags optional list of tags to be included in the JWT.
     * @param issuedAt the current epoch seconds.
     * @throws IllegalArgumentException if the accountId or publicUserKey is not a valid public key of the proper type
     * @throws NullPointerException if signingKey, accountId, or publicUserKey are null.
     * @throws GeneralSecurityException if SHA-256 MessageDigest is missing, or if the signingKey can not be used for signing.
     * @throws IOException if signingKey sign method throws this exception.
     * @return a JWT
     */
    public static String issueUserJWT(NKey signingKey, String accountId, String publicUserKey, String name, Duration expiration, String[] tags, Long issuedAt) throws GeneralSecurityException, IOException {
        return issueUserJWT(signingKey, publicUserKey, name, expiration, issuedAt, null, new UserClaim(accountId).tags(tags));
    }

    /**
     * Issue a user JWT from a scoped signing key. See <a href="https://docs.nats.io/nats-tools/nsc/signing_keys">Signing Keys</a>
     * @param signingKey a mandatory account nkey pair to sign the generated jwt.
     * @param accountId a mandatory public account nkey. Will throw error when not set or not account nkey.
     * @param publicUserKey a mandatory public user nkey. Will throw error when not set or not user nkey.
     * @param name optional human-readable name. When absent, default to publicUserKey.
     * @param expiration optional but recommended duration, when the generated jwt needs to expire. If not set, JWT will not expire.
     * @param tags optional list of tags to be included in the JWT.
     * @param issuedAt the current epoch seconds.
     * @param audience the optional audience
     * @throws IllegalArgumentException if the accountId or publicUserKey is not a valid public key of the proper type
     * @throws NullPointerException if signingKey, accountId, or publicUserKey are null.
     * @throws GeneralSecurityException if SHA-256 MessageDigest is missing, or if the signingKey can not be used for signing.
     * @throws IOException if signingKey sign method throws this exception.
     * @return a JWT
     */
    public static String issueUserJWT(NKey signingKey, String accountId, String publicUserKey, String name, Duration expiration, String[] tags, Long issuedAt, String audience) throws GeneralSecurityException, IOException {
        return issueUserJWT(signingKey, publicUserKey, name, expiration, issuedAt, audience, new UserClaim(accountId).tags(tags));
    }

    /**
     * Issue a user JWT from a scoped signing key. See <a href="https://docs.nats.io/nats-tools/nsc/signing_keys">Signing Keys</a>
     * @param signingKey a mandatory account nkey pair to sign the generated jwt.
     * @param publicUserKey a mandatory public user nkey. Will throw error when not set or not user nkey.
     * @param name optional human-readable name. When absent, default to publicUserKey.
     * @param expiration optional but recommended duration, when the generated jwt needs to expire. If not set, JWT will not expire.
     * @param issuedAt the current epoch seconds.
     * @param nats the user claim
     * @throws IllegalArgumentException if the accountId or publicUserKey is not a valid public key of the proper type
     * @throws NullPointerException if signingKey, accountId, or publicUserKey are null.
     * @throws GeneralSecurityException if SHA-256 MessageDigest is missing, or if the signingKey can not be used for signing.
     * @throws IOException if signingKey sign method throws this exception.
     * @return a JWT
     */
    public static String issueUserJWT(NKey signingKey, String publicUserKey, String name, Duration expiration, Long issuedAt, UserClaim nats) throws GeneralSecurityException, IOException {
        return issueUserJWT(signingKey, publicUserKey, name, expiration, issuedAt, null, nats);
    }

    /**
     * Issue a user JWT from a scoped signing key. See <a href="https://docs.nats.io/nats-tools/nsc/signing_keys">Signing Keys</a>
     * @param signingKey a mandatory account nkey pair to sign the generated jwt.
     * @param publicUserKey a mandatory public user nkey. Will throw error when not set or not user nkey.
     * @param name optional human-readable name. When absent, default to publicUserKey.
     * @param expiration optional but recommended duration, when the generated jwt needs to expire. If not set, JWT will not expire.
     * @param issuedAt the current epoch seconds.
     * @param audience the optional audience
     * @param nats the user claim
     * @throws IllegalArgumentException if the accountId or publicUserKey is not a valid public key of the proper type
     * @throws NullPointerException if signingKey, accountId, or publicUserKey are null.
     * @throws GeneralSecurityException if SHA-256 MessageDigest is missing, or if the signingKey can not be used for signing.
     * @throws IOException if signingKey sign method throws this exception.
     * @return a JWT
     */
    public static String issueUserJWT(NKey signingKey, String publicUserKey, String name, Duration expiration, Long issuedAt, String audience, UserClaim nats) throws GeneralSecurityException, IOException {
        // Validate the signingKey:
        if (signingKey.getType() != NKey.Type.ACCOUNT) {
            throw new IllegalArgumentException("issueUserJWT requires an account key for the signingKey parameter, but got " + signingKey.getType());
        }

        // Validate the accountId:
        NKey accountKey = NKey.fromPublicKey(nats.issuerAccount.toCharArray());
        if (accountKey.getType() != NKey.Type.ACCOUNT) {
            throw new IllegalArgumentException("issueUserJWT requires an account key for the accountId parameter, but got " + accountKey.getType());
        }
        // Validate the publicUserKey:
        NKey userKey = NKey.fromPublicKey(publicUserKey.toCharArray());
        if (userKey.getType() != NKey.Type.USER) {
            throw new IllegalArgumentException("issueUserJWT requires a user key for the publicUserKey parameter, but got " + userKey.getType());
        }

        String accSigningKeyPub = new String(signingKey.getPublicKey());

        String claimName = name == null || name.trim().isEmpty() ? publicUserKey : name;

        return issueJWT(signingKey, publicUserKey, claimName, expiration, issuedAt, accSigningKeyPub, audience, nats);
    }

    /**
     * Issue a JWT
     * @param signingKey account nkey pair to sign the generated jwt.
     * @param publicUserKey a mandatory public user nkey.
     * @param name optional human-readable name.
     * @param expiration optional but recommended duration, when the generated jwt needs to expire. If not set, JWT will not expire.
     * @param issuedAt the current epoch seconds.
     * @param accSigningKeyPub the account signing key
     * @param nats the generic nats claim
     * @throws GeneralSecurityException if SHA-256 MessageDigest is missing, or if the signingKey can not be used for signing.
     * @throws IOException if signingKey sign method throws this exception.
     * @return a JWT
     */
    public static String issueJWT(NKey signingKey, String publicUserKey, String name, Duration expiration, Long issuedAt, String accSigningKeyPub, JsonSerializable nats) throws GeneralSecurityException, IOException {
        return issueJWT(signingKey, publicUserKey, name, expiration, issuedAt, accSigningKeyPub, null, nats);
    }

    /**
     * Issue a JWT
     *
     * @param signingKey       account nkey pair to sign the generated jwt.
     * @param publicUserKey    a mandatory public user nkey.
     * @param name             optional human-readable name.
     * @param expiration       optional but recommended duration, when the generated jwt needs to expire. If not set, JWT will not expire.
     * @param issuedAt         the current epoch seconds.
     * @param accSigningKeyPub the account signing key
     * @param audience         the optional audience
     * @param nats             the generic nats claim
     * @return a JWT
     * @throws GeneralSecurityException if SHA-256 MessageDigest is missing, or if the signingKey can not be used for signing.
     * @throws IOException              if signingKey sign method throws this exception.
     */
    public static String issueJWT(NKey signingKey, String publicUserKey, String name, Duration expiration, Long issuedAt, String accSigningKeyPub, String audience, JsonSerializable nats) throws GeneralSecurityException, IOException {
        return new io.nats.jwt.ClaimIssuer()
            .aud(audience)
            .iat(issuedAt == null || issuedAt < 0 ? currentTimeSeconds() : issuedAt)
            .iss(accSigningKeyPub)
            .name(name)
            .sub(publicUserKey)
            .expiresIn(expiration)
            .nats(nats)
            .issueJwt(signingKey);
    }

    /**
     * Get the claim body from a JWT
     * @param jwt the encoded jwt string
     * @return the claim body json
     */
    public static String getClaimBody(String jwt) {
        return fromBase64Url(jwt.split("\\.")[1]);
    }

    /**
     * Get the claim body from a JWT
     * @param jwtBytes the encoded jwt bytes
     * @return the claim body json
     */
    public static String getClaimBody(byte[] jwtBytes) {
        return getClaimBody(new String(jwtBytes));
    }
}
