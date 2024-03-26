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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public abstract class GenericClaimFields<B> implements JsonSerializable {
    public List<String> tags;
    public String type;
    public int version;

    protected GenericClaimFields(String type, int version) {
        this.type = type;
        this.version = version;
    }

    protected GenericClaimFields(JsonValue jv, String expectedType, int... validVersions) {
        type = JsonValueUtils.readString(jv, "type");
        if (!type.equals(expectedType)) {
            throw new IllegalArgumentException("Invalid Claim Type '" + type + "', expecting '" + expectedType + "'");
        }

        tags = JsonValueUtils.readOptionalStringList(jv, "tags");

        version = JsonValueUtils.readInteger(jv, "version", -1);
        for (int v : validVersions) {
            if (version == v) {
                return;
            }
        }
        throw new IllegalArgumentException("Invalid Version '" + version + "'");
    }

    public String getType() {
        return type;
    }

    protected void baseJson(StringBuilder sb) {
        JsonWriteUtils.addStrings(sb, "tags", tags);
        JsonWriteUtils.addField(sb, "type", type);
        JsonWriteUtils.addField(sb, "version", version);
    }

    protected abstract B getThis();

    public B tags(String... tags) {
        if (tags == null) {
            this.tags = null;
        }
        else {
            this.tags = new ArrayList<>(Arrays.asList(tags));
        }
        return getThis();
    }

    public B tags(List<String> tags) {
        this.tags = tags;
        return getThis();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GenericClaimFields<?> that = (GenericClaimFields<?>) o;

        if (version != that.version) return false;
        if (!Objects.equals(tags, that.tags)) return false;
        return Objects.equals(type, that.type);
    }

    @Override
    public int hashCode() {
        int result = tags != null ? tags.hashCode() : 0;
        result = 31 * result + (type != null ? type.hashCode() : 0);
        result = 31 * result + version;
        return result;
    }
}