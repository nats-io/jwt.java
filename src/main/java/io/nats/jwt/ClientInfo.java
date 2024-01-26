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

import io.nats.client.support.JsonSerializable;
import io.nats.client.support.JsonUtils;
import io.nats.client.support.JsonValue;
import io.nats.client.support.JsonValueUtils;

import java.util.Arrays;
import java.util.Objects;

import static io.nats.client.support.JsonUtils.beginJson;
import static io.nats.client.support.JsonUtils.endJson;

public class ClientInfo implements JsonSerializable {
    public final String host;
    public final long id;
    public final String user;
    public final String name;
    public final String[] tags;
    public final String nameTag;
    public final String kind;
    public final String type;
    public final String mqttId;
    public final String nonce;

    public static ClientInfo optionalInstance(JsonValue jv) {
        return jv == null ? null : new ClientInfo(jv);
    }

    public ClientInfo(JsonValue jv) {
        host = JsonValueUtils.readString(jv, "host");
        id = JsonValueUtils.readLong(jv, "id");
        user = JsonValueUtils.readString(jv, "user");
        name = JsonValueUtils.readString(jv, "name");
        tags = JsonValueUtils.readStringList(jv, "tags").toArray(new String[0]);
        nameTag = JsonValueUtils.readString(jv, "name_tag");
        kind = JsonValueUtils.readString(jv, "kind");
        type = JsonValueUtils.readString(jv, "type");
        mqttId = JsonValueUtils.readString(jv, "mqtt_id");
        nonce = JsonValueUtils.readString(jv, "nonce");
    }

    @Override
    public String toJson() {
        StringBuilder sb = beginJson();
        JsonUtils.addField(sb, "host", host);
        JsonUtils.addField(sb, "id", id);
        JsonUtils.addField(sb, "user", user);
        JsonUtils.addField(sb, "name", name);
        JsonUtils.addStrings(sb, "tags", tags);
        JsonUtils.addField(sb, "name_tag", nameTag);
        JsonUtils.addField(sb, "kind", kind);
        JsonUtils.addField(sb, "type", type);
        JsonUtils.addField(sb, "mqtt_id", mqttId);
        JsonUtils.addField(sb, "nonce", nonce);
        return endJson(sb).toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ClientInfo that = (ClientInfo) o;

        if (id != that.id) return false;
        if (!Objects.equals(host, that.host)) return false;
        if (!Objects.equals(user, that.user)) return false;
        if (!Objects.equals(name, that.name)) return false;
        // Probably incorrect - comparing Object[] arrays with Arrays.equals
        if (!Arrays.equals(tags, that.tags)) return false;
        if (!Objects.equals(nameTag, that.nameTag)) return false;
        if (!Objects.equals(kind, that.kind)) return false;
        if (!Objects.equals(type, that.type)) return false;
        if (!Objects.equals(mqttId, that.mqttId)) return false;
        return Objects.equals(nonce, that.nonce);
    }

    @Override
    public int hashCode() {
        int result = host != null ? host.hashCode() : 0;
        result = 31 * result + (int) (id ^ (id >>> 32));
        result = 31 * result + (user != null ? user.hashCode() : 0);
        result = 31 * result + (name != null ? name.hashCode() : 0);
        result = 31 * result + Arrays.hashCode(tags);
        result = 31 * result + (nameTag != null ? nameTag.hashCode() : 0);
        result = 31 * result + (kind != null ? kind.hashCode() : 0);
        result = 31 * result + (type != null ? type.hashCode() : 0);
        result = 31 * result + (mqttId != null ? mqttId.hashCode() : 0);
        result = 31 * result + (nonce != null ? nonce.hashCode() : 0);
        return result;
    }
}
