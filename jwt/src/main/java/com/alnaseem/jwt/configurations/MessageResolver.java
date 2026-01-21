package com.alnaseem.jwt.configurations;

import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * Helper component to resolve localized messages from application's MessageSource.
 * Provides convenience methods for default, English and Arabic lookups.
 */
@Component
@RequiredArgsConstructor
public class MessageResolver {
    private final MessageSource messageSource;

    public String get(String code, Object[] args, Locale locale) {
        return messageSource.getMessage(code, args, code, locale);
    }

    public String get(String code) {
        return get(code, null, LocaleContextHolder.getLocale());
    }

    public String getEn(String code, Object... args) {
        return get(code, args, Locale.ENGLISH);
    }

    public String getAr(String code, Object... args) {
        return get(code, args, new Locale("ar"));
    }
}
