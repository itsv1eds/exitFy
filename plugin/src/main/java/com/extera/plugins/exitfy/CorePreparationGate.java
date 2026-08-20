package com.extera.plugins.exitfy;

final class CorePreparationGate {
    private long generation;
    private Request current;

    synchronized Request request(CoreFamily family, String nodeKey) {
        if (family == null || nodeKey == null || nodeKey.isEmpty()) {
            throw new IllegalArgumentException("invalid core preparation request");
        }
        if (current != null && current.family == family
                && current.nodeKey.equals(nodeKey)) {
            return current;
        }
        current = new Request(++generation, family, nodeKey);
        return current;
    }

    synchronized Request current() {
        return current;
    }

    synchronized boolean isCurrent(Request request) {
        return request != null && current != null
                && request.generation == current.generation;
    }

    synchronized void cancel() {
        generation++;
        current = null;
    }

    static final class Request {
        final long generation;
        final CoreFamily family;
        final String nodeKey;

        private Request(long generation, CoreFamily family, String nodeKey) {
            this.generation = generation;
            this.family = family;
            this.nodeKey = nodeKey;
        }
    }
}
