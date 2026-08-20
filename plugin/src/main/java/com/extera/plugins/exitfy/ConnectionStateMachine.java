package com.extera.plugins.exitfy;

final class ConnectionStateMachine {
    private RuntimeState state = RuntimeState.STOPPED;

    synchronized RuntimeState get() {
        return state;
    }

    synchronized void transition(RuntimeState next) {
        if (next == null || next == state) return;
        boolean allowed;
        switch (state) {
            case STOPPED:
                allowed = next == RuntimeState.STARTING || next == RuntimeState.ERROR;
                break;
            case STARTING:
                allowed = next == RuntimeState.RUNNING || next == RuntimeState.STOPPING
                        || next == RuntimeState.ERROR || next == RuntimeState.STOPPED;
                break;
            case RUNNING:
                allowed = next == RuntimeState.STOPPING || next == RuntimeState.ERROR;
                break;
            case STOPPING:
                allowed = next == RuntimeState.STOPPED || next == RuntimeState.ERROR;
                break;
            case ERROR:
                allowed = next == RuntimeState.STARTING || next == RuntimeState.STOPPING
                        || next == RuntimeState.STOPPED;
                break;
            default:
                allowed = false;
        }
        if (!allowed) throw new IllegalStateException("invalid runtime transition " + state + " -> " + next);
        state = next;
    }
}
