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

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static io.nats.json.JsonWriteUtils.beginJson;
import static io.nats.json.JsonWriteUtils.endJson;

public class Permission implements JsonSerializable {
    public List<String> allow;
    public List<String> deny;

    public static Permission optionalInstance(JsonValue jv) {
        return jv == null ? null : new Permission(jv);
    }

    public Permission() {}

    public Permission(JsonValue jv) {
        allow = JsonValueUtils.readStringList(jv, "allow");
        deny = JsonValueUtils.readStringList(jv, "deny");
    }

    public Permission allow(String... allow) {
        this.allow = Arrays.asList(allow);
        return this;
    }

    public Permission allow(List<String> allow) {
        this.allow = allow;
        return this;
    }

    public Permission deny(String... deny) {
        this.deny = Arrays.asList(deny);
        return this;
    }

    public Permission deny(List<String> deny) {
        this.deny = deny;
        return this;
    }

    @Override
    public String toJson() {
        StringBuilder sb = beginJson();
        JsonWriteUtils.addStrings(sb, "allow", allow);
        JsonWriteUtils.addStrings(sb, "deny", deny);
        return endJson(sb).toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Permission that = (Permission) o;

        if (!Objects.equals(allow, that.allow)) return false;
        return Objects.equals(deny, that.deny);
    }

    @Override
    public int hashCode() {
        int result = allow != null ? allow.hashCode() : 0;
        result = 31 * result + (deny != null ? deny.hashCode() : 0);
        return result;
    }
}