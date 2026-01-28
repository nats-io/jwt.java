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
import io.nats.json.JsonValue;
import io.nats.json.JsonValueUtils;
import io.nats.json.JsonWriteUtils;
import org.jspecify.annotations.NonNull;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static io.nats.json.JsonWriteUtils.beginJson;
import static io.nats.json.JsonWriteUtils.endJson;

public class ClientTls implements JsonSerializable {
    public final String version;
    public final String cipher;
    public final List<String> certs;
    public final List<List<String>> verifiedChains;

    public static ClientTls optionalInstance(JsonValue jv) {
        return jv == null ? null : new ClientTls(jv);
    }

    public ClientTls(JsonValue jv) {
        version = JsonValueUtils.readString(jv, "version");
        cipher = JsonValueUtils.readString(jv, "cipher");
        certs = JsonValueUtils.readStringListOrNull(jv, "certs");
        verifiedChains = JsonValueUtils.readArrayOrEmpty(jv, "verified_chains").stream()
            .map(jsonObj -> JsonValueUtils.listOfOrEmpty(jsonObj, JsonValue::toJson)).collect(Collectors.toList());
    }

    @Override
    @NonNull
    public String toJson() {
        StringBuilder sb = beginJson();
        JsonWriteUtils.addField(sb, "version", version);
        JsonWriteUtils.addField(sb, "protocol", cipher);
        JsonWriteUtils.addStrings(sb, "tags", certs);
        return endJson(sb).toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ClientTls clientTls = (ClientTls) o;

        if (!Objects.equals(version, clientTls.version)) return false;
        if (!Objects.equals(cipher, clientTls.cipher)) return false;
        if (!Objects.equals(certs, clientTls.certs)) return false;
        return Objects.equals(verifiedChains, clientTls.verifiedChains);
    }

    @Override
    public int hashCode() {
        int result = version != null ? version.hashCode() : 0;
        result = 31 * result + (cipher != null ? cipher.hashCode() : 0);
        result = 31 * result + (certs != null ? certs.hashCode() : 0);
        result = 31 * result + (verifiedChains != null ? verifiedChains.hashCode() : 0);
        return result;
    }
}
