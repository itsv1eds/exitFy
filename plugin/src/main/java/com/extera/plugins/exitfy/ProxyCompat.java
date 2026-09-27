package com.extera.plugins.exitfy;

import org.telegram.messenger.SharedConfig;
import org.telegram.tgnet.ConnectionsManager;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

final class ProxyCompat {
    private ProxyCompat() {}

    static ProxySnapshotModel.ProxyValue read(Object proxy) {
        if (proxy == null) return null;
        try {
            Field settings = settingsField(proxy.getClass());
            if (settings == null) {
                Class<?> type = proxy.getClass();
                return new ProxySnapshotModel.ProxyValue(
                        (String) type.getField("address").get(proxy),
                        type.getField("port").getInt(proxy),
                        (String) type.getField("username").get(proxy),
                        (String) type.getField("password").get(proxy),
                        (String) type.getField("secret").get(proxy));
            }
            Object value = settings.get(proxy);
            String kind = String.valueOf(call(value, "getType"));
            return new ProxySnapshotModel.ProxyValue(
                    (String) call(value, "getAddress"),
                    ((Number) call(value, "getPort")).intValue(),
                    (String) call(value, "getUser"),
                    (String) call(value, "getPassword"),
                    (String) call(value, "getSecret"),
                    "WEB".equals(kind) ? 2 : "MTPROTO".equals(kind) ? 1 : 0);
        } catch (ReflectiveOperationException error) {
            throw failure(error);
        }
    }

    static SharedConfig.ProxyInfo create(ProxySnapshotModel.ProxyValue value) {
        return value == null ? null : (SharedConfig.ProxyInfo) create(SharedConfig.ProxyInfo.class, value);
    }

    static Object create(Class<?> proxyClass, ProxySnapshotModel.ProxyValue value) {
        try {
            Field settings = settingsField(proxyClass);
            if (settings == null) {
                if (value.type == 2) throw new IllegalStateException("Web proxy requires a newer client");
                return proxyClass.getConstructor(String.class, int.class, String.class,
                        String.class, String.class).newInstance(value.address, value.port,
                        value.username, value.password, value.secret);
            }
            Class<?> settingsClass = settings.getType();
            Object builder = settingsClass.getMethod("builder").invoke(null);
            Class<?> builderClass = builder.getClass();
            Method setType = null;
            for (Method method : builderClass.getMethods()) {
                if (method.getName().equals("setType") && method.getParameterTypes().length == 1) {
                    setType = method;
                    break;
                }
            }
            if (setType == null) throw new NoSuchMethodException("ProxySettings.Builder.setType");
            String kind = value.type == 2 ? "WEB" : value.type == 1 ? "MTPROTO" : "SOCKS5";
            Object enumValue = null;
            for (Object candidate : setType.getParameterTypes()[0].getEnumConstants()) {
                if (((Enum<?>) candidate).name().equals(kind)) enumValue = candidate;
            }
            if (enumValue == null) throw new IllegalStateException("Unsupported Telegram proxy type");
            setType.invoke(builder, enumValue);
            builderClass.getMethod("setAddress", String.class).invoke(builder, value.address);
            builderClass.getMethod("setPort", int.class).invoke(builder, value.port);
            builderClass.getMethod("setUser", String.class).invoke(builder, value.username);
            builderClass.getMethod("setPassword", String.class).invoke(builder, value.password);
            builderClass.getMethod("setSecret", String.class).invoke(builder, value.secret);
            Object built = call(builder, "build");
            return proxyClass.getConstructor(settingsClass).newInstance(built);
        } catch (ReflectiveOperationException error) {
            throw failure(error);
        }
    }

    static String link(Object proxy) {
        if (proxy == null) return "";
        try {
            Field field = settingsField(proxy.getClass());
            return (String) call(field == null ? proxy : field.get(proxy), "getLink");
        } catch (ReflectiveOperationException error) {
            throw failure(error);
        }
    }

    static boolean structured() {
        return settingsField(SharedConfig.ProxyInfo.class) != null;
    }

    static void configure(boolean enabled, SharedConfig.ProxyInfo proxy) {
        configure(ConnectionsManager.class, SharedConfig.ProxyInfo.class, enabled, proxy);
    }

    static void configure(Class<?> managerClass, Class<?> proxyClass, boolean enabled, Object proxy) {
        try {
            Field field = settingsField(proxyClass);
            if (field != null) {
                managerClass.getMethod("setProxySettings", boolean.class, field.getType())
                        .invoke(null, enabled, proxy == null ? null : field.get(proxy));
            } else {
                ProxySnapshotModel.ProxyValue value = read(proxy);
                managerClass.getMethod("setProxySettings", boolean.class, String.class, int.class,
                        String.class, String.class, String.class).invoke(null, enabled,
                        value == null ? "" : value.address, value == null ? 0 : value.port,
                        value == null ? "" : value.username, value == null ? "" : value.password,
                        value == null ? "" : value.secret);
            }
        } catch (ReflectiveOperationException error) {
            throw failure(error);
        }
    }

    private static Field settingsField(Class<?> type) {
        try {
            return type.getField("settings");
        } catch (NoSuchFieldException oldClient) {
            return null;
        }
    }

    private static Object call(Object receiver, String name) throws ReflectiveOperationException {
        return receiver.getClass().getMethod(name).invoke(receiver);
    }

    private static IllegalStateException failure(ReflectiveOperationException error) {
        Throwable cause = error instanceof InvocationTargetException
                && error.getCause() != null ? error.getCause() : error;
        return new IllegalStateException("Telegram proxy API is unavailable", cause);
    }
}
