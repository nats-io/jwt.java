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
import io.nats.client.support.JsonValue;
import io.nats.client.support.JsonValueUtils;
import io.nats.client.support.JsonWriteUtils;

import java.util.List;
import java.util.Objects;

import static io.nats.client.support.JsonWriteUtils.beginJson;
import static io.nats.client.support.JsonWriteUtils.endJson;

public class TimeRange implements JsonSerializable {
    public String start;
    public String end;

    public static List<TimeRange> optionalListOf(JsonValue jv) {
        return JsonValueUtils.optionalListOf(jv, TimeRange::new);
    }

    public TimeRange(String start, String end) {
        this.start = start;
        this.end = end;
    }

    public TimeRange(JsonValue jv) {
        this.start = JsonValueUtils.readString(jv, "start");
        this.end = JsonValueUtils.readString(jv, "end");
    }

    @Override
    public String toJson() {
        StringBuilder sb = beginJson();
        JsonWriteUtils.addField(sb, "start", start);
        JsonWriteUtils.addField(sb, "end", end);
        return endJson(sb).toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TimeRange timeRange = (TimeRange) o;

        if (!Objects.equals(start, timeRange.start)) return false;
        return Objects.equals(end, timeRange.end);
    }

    @Override
    public int hashCode() {
        int result = start != null ? start.hashCode() : 0;
        result = 31 * result + (end != null ? end.hashCode() : 0);
        return result;
    }
}