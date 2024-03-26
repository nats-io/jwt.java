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

import java.time.Duration;
import java.util.Objects;

import static io.nats.json.JsonWriteUtils.*;

public class ResponsePermission implements JsonSerializable {
    public int max;
    public Duration expires;

    public static ResponsePermission optionalInstance(JsonValue jv) {
        return jv == null ? null : new ResponsePermission(jv);
    }

    public ResponsePermission() {}

    public ResponsePermission(JsonValue jv) {
        max = JsonValueUtils.readInteger(jv, "max", 0);
        expires = JsonValueUtils.readNanos(jv, "ttl");
    }

    public ResponsePermission max(int max) {
        this.max = max;
        return this;
    }

    public ResponsePermission expires(Duration expires) {
        this.expires = expires;
        return this;
    }

    public ResponsePermission expires(long expiresMillis) {
        this.expires = Duration.ofMillis(expiresMillis);
        return this;
    }

    @Override
    public String toJson() {
        StringBuilder sb = beginJson();
        addField(sb, "max", max);
        addFieldAsNanos(sb, "ttl", expires);
        return endJson(sb).toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ResponsePermission that = (ResponsePermission) o;

        if (max != that.max) return false;
        return Objects.equals(expires, that.expires);
    }

    @Override
    public int hashCode() {
        int result = max;
        result = 31 * result + (expires != null ? expires.hashCode() : 0);
        return result;
    }
}