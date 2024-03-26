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

import io.nats.json.JsonValue;
import io.nats.json.JsonValueUtils;
import io.nats.json.JsonWriteUtils;

import java.util.Objects;

import static io.nats.json.JsonWriteUtils.beginJson;
import static io.nats.json.JsonWriteUtils.endJson;
import static io.nats.jwt.JwtUtils.AUTH_REQUEST_CLAIM_TYPE;

public class AuthorizationRequest extends GenericClaimFields<AuthorizationRequest> {
    public ServerId serverId;
    public String userNkey;
    public ClientInfo clientInfo;
    public ConnectOpts connectOpts;
    public ClientTls clientTls;
    public String requestNonce;

    public AuthorizationRequest() {
        super(AUTH_REQUEST_CLAIM_TYPE, 2);
    }

    public AuthorizationRequest(JsonValue jv) {
        super(jv, AUTH_REQUEST_CLAIM_TYPE, 2);
        serverId = ServerId.optionalInstance(JsonValueUtils.readValue(jv, "server_id"));
        userNkey = JsonValueUtils.readString(jv, "user_nkey");
        clientInfo = ClientInfo.optionalInstance(JsonValueUtils.readValue(jv, "client_info"));
        connectOpts = ConnectOpts.optionalInstance(JsonValueUtils.readValue(jv, "connect_opts"));
        clientTls = ClientTls.optionalInstance(JsonValueUtils.readValue(jv, "client_tls"));
        requestNonce = JsonValueUtils.readString(jv, "request_nonce");
    }

    @Override
    protected AuthorizationRequest getThis() {
        return this;
    }

    @Override
    public String toJson() {
        StringBuilder sb = beginJson();
        baseJson(sb);
        JsonWriteUtils.addField(sb, "server_id", serverId);
        JsonWriteUtils.addField(sb, "user_nkey", userNkey);
        JsonWriteUtils.addField(sb, "client_info", clientInfo);
        JsonWriteUtils.addField(sb, "connect_opts", connectOpts);
        JsonWriteUtils.addField(sb, "client_tls", clientTls);
        JsonWriteUtils.addField(sb, "request_nonce", requestNonce);
        return endJson(sb).toString();
    }

    public AuthorizationRequest serverId(ServerId serverId) {
        this.serverId = serverId;
        return this;
    }

    public AuthorizationRequest userNkey(String userNkey) {
        this.userNkey = userNkey;
        return this;
    }

    public AuthorizationRequest clientInformation(ClientInfo clientInfo) {
        this.clientInfo = clientInfo;
        return this;
    }

    public AuthorizationRequest connectOptions(ConnectOpts connectOpts) {
        this.connectOpts = connectOpts;
        return this;
    }

    public AuthorizationRequest clientTls(ClientTls clientTls) {
        this.clientTls = clientTls;
        return this;
    }

    public AuthorizationRequest requestNonce(String requestNonce) {
        this.requestNonce = requestNonce;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        AuthorizationRequest that = (AuthorizationRequest) o;

        if (!Objects.equals(serverId, that.serverId)) return false;
        if (!Objects.equals(userNkey, that.userNkey)) return false;
        if (!Objects.equals(clientInfo, that.clientInfo)) return false;
        if (!Objects.equals(connectOpts, that.connectOpts)) return false;
        if (!Objects.equals(clientTls, that.clientTls)) return false;
        return Objects.equals(requestNonce, that.requestNonce);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (serverId != null ? serverId.hashCode() : 0);
        result = 31 * result + (userNkey != null ? userNkey.hashCode() : 0);
        result = 31 * result + (clientInfo != null ? clientInfo.hashCode() : 0);
        result = 31 * result + (connectOpts != null ? connectOpts.hashCode() : 0);
        result = 31 * result + (clientTls != null ? clientTls.hashCode() : 0);
        result = 31 * result + (requestNonce != null ? requestNonce.hashCode() : 0);
        return result;
    }
}
