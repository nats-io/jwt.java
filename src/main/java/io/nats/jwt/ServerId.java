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

import static io.nats.json.JsonWriteUtils.beginJson;
import static io.nats.json.JsonWriteUtils.endJson;

public class ServerId implements JsonSerializable {
    public final String name;
    public final String host;
    public final String id;
    public final String version;
    public final String cluster;
    public final List<String> tags;
    public final String xKey;

    public static ServerId optionalInstance(JsonValue jv) {
        return jv == null ? null : new ServerId(jv);
    }

    public ServerId(JsonValue jv) {
        name = JsonValueUtils.readString(jv, "name");
        host = JsonValueUtils.readString(jv, "host");
        id = JsonValueUtils.readString(jv, "id");
        version = JsonValueUtils.readString(jv, "version");
        cluster = JsonValueUtils.readString(jv, "cluster");
        tags = JsonValueUtils.readStringListOrNull(jv, "tags");
        xKey = JsonValueUtils.readString(jv, "xKey");
    }

    @Override
    @NonNull
    public String toJson() {
        StringBuilder sb = beginJson();
        JsonWriteUtils.addField(sb, "name", name);
        JsonWriteUtils.addField(sb, "host", host);
        JsonWriteUtils.addField(sb, "id", id);
        JsonWriteUtils.addField(sb, "version", version);
        JsonWriteUtils.addField(sb, "cluster", cluster);
        JsonWriteUtils.addStrings(sb, "tags", tags);
        JsonWriteUtils.addField(sb, "xKey", xKey);
        return endJson(sb).toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ServerId serverId = (ServerId) o;

        if (!Objects.equals(name, serverId.name)) return false;
        if (!Objects.equals(host, serverId.host)) return false;
        if (!Objects.equals(id, serverId.id)) return false;
        if (!Objects.equals(version, serverId.version)) return false;
        if (!Objects.equals(cluster, serverId.cluster)) return false;
        if (!Objects.equals(tags, serverId.tags)) return false;
        return Objects.equals(xKey, serverId.xKey);
    }

    @Override
    public int hashCode() {
        int result = name != null ? name.hashCode() : 0;
        result = 31 * result + (host != null ? host.hashCode() : 0);
        result = 31 * result + (id != null ? id.hashCode() : 0);
        result = 31 * result + (version != null ? version.hashCode() : 0);
        result = 31 * result + (cluster != null ? cluster.hashCode() : 0);
        result = 31 * result + (tags != null ? tags.hashCode() : 0);
        result = 31 * result + (xKey != null ? xKey.hashCode() : 0);
        return result;
    }
}
