package com.extera.plugins.exitfy;

/** Saved progress is informational: only an explicit request creates a tour. */
final class TutorialFlow {
    enum Step { INSTALL, SOURCE, PROVIDER, SUBSCRIPTION, REFRESH, SELECT, PING, CONNECT, ADVANCED, DONE }
    private Step step;
    private boolean customSource;
    TutorialFlow(boolean replay) { step = replay ? Step.SOURCE : Step.INSTALL; }
    static int count() { return Step.values().length - 1; }
    Step step() { return step; }
    int position() { return step.ordinal(); }
    int displayPosition() {
        return step.ordinal() - (!customSource && step.ordinal() > Step.SUBSCRIPTION.ordinal() ? 1 : 0);
    }
    int totalSteps() { return count() - (customSource ? 0 : 1); }
    boolean chooseProvider(boolean needsSubscription) {
        if (step != Step.PROVIDER) return false;
        customSource = needsSubscription;
        return advance(Step.PROVIDER, true);
    }
    boolean advance(Step completed, boolean succeeded) {
        if (!succeeded || step != completed || step == Step.DONE) return false;
        step = Step.values()[step.ordinal() + 1];
        if (step == Step.SUBSCRIPTION && !customSource) step = Step.REFRESH;
        return true;
    }
    void finish() { step = Step.DONE; }
}
