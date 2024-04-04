package org.wiremock.extension.jwt;

import com.github.jknack.handlebars.Options;
import com.github.tomakehurst.wiremock.extension.responsetemplating.helpers.HandlebarsHelper;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ClaimListHandlebarsHelper extends HandlebarsHelper<Object> {

    @Override
    public Object apply(Object context, Options options) {
        return Stream
                .concat(Stream.of(context), Stream.of(options.params))
                .collect(Collectors.toList());
    }
}
