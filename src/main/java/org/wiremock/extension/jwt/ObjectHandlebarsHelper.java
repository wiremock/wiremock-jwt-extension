package org.wiremock.extension.jwt;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import com.github.jknack.handlebars.Options;
import com.github.tomakehurst.wiremock.extension.responsetemplating.helpers.HandlebarsHelper;

public class ObjectHandlebarsHelper extends HandlebarsHelper<Object> {

    @Override
    public Object apply(Object context, Options options) {
        Map<String, Object> result = new HashMap<>();

        // Process each key-value pair from the options hash
        options.hash.forEach((key, value) -> {
            // Convert each key-value pair to a nested structure if the key contains dots
            Map<String, Object> map = new HashMap<>();
            map.put(key, value);
            result.putAll(map);
        });

        return result;
    }

    private static Map<String, Object> convertToNestedStructure(String key, Object value) {
        Map<String, Object> result = new HashMap<>();
        Map<String, Object> current = result;

        // Put the actual value at the deepest level
        current.put(key, value);
        return result;
    }
}
