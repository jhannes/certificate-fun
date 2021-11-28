package com.johannesbrodwall.pki.util;

import java.util.function.Function;

public class ExceptionUtil {
    @FunctionalInterface
    interface FunctionThrowing<T,R,EX extends Throwable> {
        R apply(T a) throws EX;
    }

    public static <T,R, EX extends Throwable> Function<T,R> softenFunction(FunctionThrowing<T, R, EX> f) {
        return a -> {
            try {
                return f.apply(a);
            } catch (Throwable e) {
                throw softenException(e);
            }
        };
    }

    private static RuntimeException softenException(Throwable e) {
        return helper(e);
    }

    @SuppressWarnings("RedundantThrows")
    private static <EX extends Throwable> EX helper(Throwable e) throws EX {
        return (EX)e;
    }
}
