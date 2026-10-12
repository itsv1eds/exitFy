package com.extera.plugins.exitfy;

/** Saved progress is informational: only an explicit request creates a tour. */
final class TutorialFlow {
    enum Step { INSTALL, SOURCE, PROVIDER, REFRESH, SELECT, PING, CONNECT, ADVANCED, DONE }
    private Step step;
    TutorialFlow(boolean replay) { step = replay ? Step.SOURCE : Step.INSTALL; }
    static int count() { return Step.values().length - 1; }
    Step step() { return step; }
    int position() { return step.ordinal(); }
    boolean advance(Step completed, boolean succeeded) {
        if (!succeeded || step != completed || step == Step.DONE) return false;
        step = Step.values()[step.ordinal() + 1];
        return true;
    }
    void finish() { step = Step.DONE; }
}
