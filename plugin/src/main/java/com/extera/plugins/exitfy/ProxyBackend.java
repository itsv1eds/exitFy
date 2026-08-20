package com.extera.plugins.exitfy;

import org.telegram.messenger.SharedConfig;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;

/** Keeps the DEX linkable on 12.5.1 while preserving newer proxy metadata. */
interface ProxyBackend {
    SharedConfig.ProxyInfo current();

    void setCurrent(SharedConfig.ProxyInfo value);

    ArrayList<SharedConfig.ProxyInfo> list();

    SharedConfig.ProxyInfo add(SharedConfig.ProxyInfo value);

    void delete(SharedConfig.ProxyInfo value);

    String name(SharedConfig.ProxyInfo value);

    void setName(SharedConfig.ProxyInfo value, String name);

    String kind();

    static ProxyBackend create() {
        try {
            return new ControllerBackend();
        } catch (ClassNotFoundException | NoSuchMethodException | LinkageError
                 | SecurityException | IllegalStateException unavailable) {
            return new SharedConfigBackend();
        }
    }

    final class ControllerBackend implements ProxyBackend {
        private static final String CLASS_NAME =
                "com.exteragram.messenger.proxy.ProxyController";

        private final Object controller;
        private final Method getCurrent;
        private final Method setCurrent;
        private final Method getList;
        private final Method add;
        private final Method delete;
        private final Method getName;
        private final Method setName;

        ControllerBackend() throws ClassNotFoundException, NoSuchMethodException {
            Class<?> type = Class.forName(CLASS_NAME, false,
                    SharedConfig.class.getClassLoader());
            Method getInstance = type.getMethod("getInstance");
            try {
                controller = getInstance.invoke(null);
            } catch (IllegalAccessException | InvocationTargetException error) {
                throw new IllegalStateException("ProxyController is unavailable", unwrap(error));
            }
            getCurrent = type.getMethod("getCurrentProxy");
            setCurrent = type.getMethod("setCurrentProxy", SharedConfig.ProxyInfo.class);
            getList = type.getMethod("getProxyList");
            add = type.getMethod("addProxy", SharedConfig.ProxyInfo.class);
            delete = type.getMethod("deleteProxy", SharedConfig.ProxyInfo.class);
            getName = type.getMethod("getName", SharedConfig.ProxyInfo.class);
            setName = type.getMethod("setName", SharedConfig.ProxyInfo.class, String.class);
        }

        @Override
        public SharedConfig.ProxyInfo current() {
            return (SharedConfig.ProxyInfo) invoke(getCurrent);
        }

        @Override
        public void setCurrent(SharedConfig.ProxyInfo value) {
            invoke(setCurrent, value);
        }

        @SuppressWarnings("unchecked")
        @Override
        public ArrayList<SharedConfig.ProxyInfo> list() {
            Object value = invoke(getList);
            return value instanceof ArrayList
                    ? new ArrayList<>((ArrayList<SharedConfig.ProxyInfo>) value)
                    : new ArrayList<>();
        }

        @Override
        public SharedConfig.ProxyInfo add(SharedConfig.ProxyInfo value) {
            return (SharedConfig.ProxyInfo) invoke(add, value);
        }

        @Override
        public void delete(SharedConfig.ProxyInfo value) {
            invoke(delete, value);
        }

        @Override
        public String name(SharedConfig.ProxyInfo value) {
            Object result = invoke(getName, value);
            return result == null ? "" : String.valueOf(result);
        }

        @Override
        public void setName(SharedConfig.ProxyInfo value, String name) {
            invoke(setName, value, name == null ? "" : name);
        }

        @Override
        public String kind() {
            return "controller";
        }

        private Object invoke(Method method, Object... args) {
            try {
                return method.invoke(controller, args);
            } catch (IllegalAccessException | InvocationTargetException error) {
                throw new IllegalStateException("ProxyController call failed", unwrap(error));
            }
        }

        private static Throwable unwrap(Exception error) {
            return error instanceof InvocationTargetException
                    && ((InvocationTargetException) error).getCause() != null
                    ? ((InvocationTargetException) error).getCause() : error;
        }
    }

    final class SharedConfigBackend implements ProxyBackend {
        SharedConfigBackend() {
            synchronized (SharedConfig.class) {
                SharedConfig.loadProxyList();
            }
        }

        @Override
        public SharedConfig.ProxyInfo current() {
            synchronized (SharedConfig.class) {
                SharedConfig.loadProxyList();
                return SharedConfig.currentProxy;
            }
        }

        @Override
        public void setCurrent(SharedConfig.ProxyInfo value) {
            synchronized (SharedConfig.class) {
                SharedConfig.currentProxy = value;
            }
        }

        @Override
        public ArrayList<SharedConfig.ProxyInfo> list() {
            synchronized (SharedConfig.class) {
                SharedConfig.loadProxyList();
                return new ArrayList<>(SharedConfig.proxyList);
            }
        }

        @Override
        public SharedConfig.ProxyInfo add(SharedConfig.ProxyInfo value) {
            synchronized (SharedConfig.class) {
                return SharedConfig.addProxy(value);
            }
        }

        @Override
        public void delete(SharedConfig.ProxyInfo value) {
            synchronized (SharedConfig.class) {
                SharedConfig.deleteProxy(value);
            }
        }

        @Override
        public String name(SharedConfig.ProxyInfo value) {
            return "";
        }

        @Override
        public void setName(SharedConfig.ProxyInfo value, String name) {
            // Names were introduced together with ProxyController.
        }

        @Override
        public String kind() {
            return "shared_config";
        }
    }
}
