package com.extera.plugins.exitfy;

/**
 * Process-local projection of an explicit two-family installation.
 *
 * <p>The session never exposes family names or versions. Its generation lets a
 * recreated dashboard attach to current work while rejecting callbacks from a
 * cancelled plugin instance.</p>
 */
final class CoreInstallSession {
    enum State {
        IDLE("idle"),
        QUEUED("queued"),
        RUNNING("running"),
        SUCCESS("success"),
        ERROR("error");

        final String id;

        State(String id) {
            this.id = id;
        }
    }

    enum Stage {
        IDLE("idle"),
        PREPARING("preparing"),
        DOWNLOADING("downloading"),
        VERIFYING("verifying"),
        DONE("done"),
        PARTIAL("partial"),
        FAILED("failed");

        final String id;

        Stage(String id) {
            this.id = id;
        }
    }

    private long generation;
    private State state = State.IDLE;
    private Stage stage = Stage.IDLE;
    private int progress;

    synchronized Request request() {
        if (active(state)) return new Request(generation, false);
        generation++;
        state = State.QUEUED;
        stage = Stage.PREPARING;
        progress = 0;
        return new Request(generation, true);
    }

    synchronized boolean begin(long expectedGeneration) {
        if (generation != expectedGeneration || state != State.QUEUED) return false;
        state = State.RUNNING;
        stage = Stage.PREPARING;
        return true;
    }

    synchronized boolean publish(long expectedGeneration, int nextProgress, Stage nextStage) {
        if (generation != expectedGeneration || !active(state)) return false;
        int boundedProgress = Math.max(progress, Math.max(0, Math.min(99, nextProgress)));
        Stage boundedStage = nextStage == null ? stage : nextStage;
        if (progress == boundedProgress && stage == boundedStage) return false;
        progress = boundedProgress;
        stage = boundedStage;
        return true;
    }

    synchronized boolean finish(long expectedGeneration, int readyCount) {
        if (generation != expectedGeneration || !active(state)) return false;
        int boundedReady = Math.max(0, Math.min(2, readyCount));
        if (boundedReady == 2) {
            state = State.SUCCESS;
            stage = Stage.DONE;
            progress = 100;
        } else {
            state = State.ERROR;
            stage = boundedReady == 0 ? Stage.FAILED : Stage.PARTIAL;
            progress = Math.min(progress, 99);
        }
        return true;
    }

    synchronized void cancel() {
        generation++;
        state = State.IDLE;
        stage = Stage.IDLE;
        progress = 0;
    }

    synchronized boolean isActive() {
        return active(state);
    }

    synchronized boolean isActive(long expectedGeneration) {
        return generation == expectedGeneration && active(state);
    }

    synchronized Snapshot snapshot() {
        return new Snapshot(generation, state, stage, progress);
    }

    private static boolean active(State value) {
        return value == State.QUEUED || value == State.RUNNING;
    }

    static final class Request {
        final long generation;
        final boolean created;

        Request(long generation, boolean created) {
            this.generation = generation;
            this.created = created;
        }
    }

    static final class Snapshot {
        final long generation;
        final State state;
        final Stage stage;
        final int progress;

        Snapshot(long generation, State state, Stage stage, int progress) {
            this.generation = generation;
            this.state = state;
            this.stage = stage;
            this.progress = progress;
        }

        boolean active() {
            return CoreInstallSession.active(state);
        }
    }
}
