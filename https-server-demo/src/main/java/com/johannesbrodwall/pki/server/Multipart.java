package com.johannesbrodwall.pki.server;

import com.johannesbrodwall.pki.util.ExceptionUtil;
import org.actioncontroller.ApiControllerContext;
import org.actioncontroller.ApiHttpExchange;
import org.actioncontroller.meta.HttpParameterMapper;
import org.actioncontroller.meta.HttpParameterMapperFactory;
import org.actioncontroller.meta.HttpParameterMapping;
import org.actioncontroller.servlet.ServletHttpExchange;

import javax.servlet.ServletException;
import javax.servlet.http.Part;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Parameter;

@Retention(RetentionPolicy.RUNTIME)
@HttpParameterMapping(Multipart.MapperFactory.class)
public @interface Multipart {
    String value();

    class MapperFactory implements HttpParameterMapperFactory<Multipart> {
        @Override
        public HttpParameterMapper create(Multipart annotation, Parameter parameter, ApiControllerContext context) {
            return exchange -> mapExchange(exchange, annotation.value());
        }

        private Object mapExchange(ApiHttpExchange exchange, String name) throws IOException {
            try {
                Part part = ((ServletHttpExchange) exchange).getRequest().getPart(name);
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                part.getInputStream().transferTo(buffer);
                return buffer.toString();
            } catch (ServletException e) {
                throw ExceptionUtil.softenException(e);
            }
        }
    }

}
