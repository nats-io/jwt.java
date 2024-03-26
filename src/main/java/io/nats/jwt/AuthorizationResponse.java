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

import io.nats.json.*;

import java.util.Objects;

import static io.nats.json.JsonWriteUtils.beginJson;
import static io.nats.json.JsonWriteUtils.endJson;
import static io.nats.jwt.JwtUtils.AUTH_RESPONSE_CLAIM_TYPE;

public class AuthorizationResponse extends GenericClaimFields<AuthorizationResponse> {
    public String jwt;
    public String error;
    public String issuerAccount;

    public AuthorizationResponse() {
        super(AUTH_RESPONSE_CLAIM_TYPE, 2);
    }

    public AuthorizationResponse(String json) throws JsonParseException {
        this(JsonParser.parse(json));
    }

    public AuthorizationResponse(JsonValue jv) {
        super(jv, AUTH_RESPONSE_CLAIM_TYPE, 2);
        jwt = JsonValueUtils.readString(jv, "jwt");
        error = JsonValueUtils.readString(jv, "error");
        issuerAccount = JsonValueUtils.readString(jv, "issuer_account");
    }

    @Override
    protected AuthorizationResponse getThis() {
        return this;
    }

    @Override
    public String toJson() {
        StringBuilder sb = beginJson();
        JsonWriteUtils.addField(sb, "jwt", jwt);
        JsonWriteUtils.addField(sb, "error", error);
        JsonWriteUtils.addField(sb, "issuer_account", issuerAccount);
        baseJson(sb);
        return endJson(sb).toString();
    }

    public AuthorizationResponse jwt(String jwt) {
        this.jwt = jwt;
        return this;
    }

    public AuthorizationResponse error(String error) {
        this.error = error;
        return this;
    }

    public AuthorizationResponse issuerAccount(String issuerAccount) {
        this.issuerAccount = issuerAccount;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        AuthorizationResponse that = (AuthorizationResponse) o;

        if (!Objects.equals(jwt, that.jwt)) return false;
        if (!Objects.equals(error, that.error)) return false;
        return Objects.equals(issuerAccount, that.issuerAccount);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (jwt != null ? jwt.hashCode() : 0);
        result = 31 * result + (error != null ? error.hashCode() : 0);
        result = 31 * result + (issuerAccount != null ? issuerAccount.hashCode() : 0);
        return result;
    }
}
