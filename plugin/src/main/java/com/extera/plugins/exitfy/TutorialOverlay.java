package com.extera.plugins.exitfy;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;

/** Rounded spotlight and animated tap indicator made entirely from native Views. */
final class TutorialOverlay implements AutoCloseable {
    private static final int DIM = 0xAA000000;
    private final FrameLayout layer;
    private final View[] shades = new View[4];
    private final View[] corners = new View[4];
    private final FrameLayout focus;
    private final View cursor;
    private final View wave;
    private final LinearLayout card;
    private final LinearLayout description;
    private final LinearLayout controls;
    private final ScrollView descriptionScroll;
    private final TextView progress, title, body, press, stop;
    private final ViewTreeObserver.OnPreDrawListener layoutListener = () -> { layout(); return true; };
    private final int[] origin = new int[2];
    private final Rect destination = new Rect(), displayed = new Rect(), visibleWindow = new Rect();
    private final boolean motion = ValueAnimator.areAnimatorsEnabled();
    private ValueAnimator travel;
    private AnimatorSet tapLoop;
    private final Runnable repeatTap = this::startTapLoop;
    private View target;
    private Runnable action, end;
    private String shownTitle = "", shownBody = "", shownCounter = "", shownButton = "";
    private int accent = Integer.MIN_VALUE, surface = Integer.MIN_VALUE;
    private int foreground = Integer.MIN_VALUE, muted = Integer.MIN_VALUE;
    private int cornerRadius = -1;
    private boolean allowed, closed, leaving, moving, enterPending, started;

    TutorialOverlay(BaseFragment owner) {
        Context context = owner.getParentActivity();
        ViewGroup root = (ViewGroup) owner.getParentActivity().getWindow().getDecorView();
        layer = new FrameLayout(context);
        layer.setClickable(true);
        layer.setFocusableInTouchMode(true);
        layer.setAlpha(motion ? 0f : 1f);
        root.addView(layer, new ViewGroup.LayoutParams(-1, -1));
        for (int i = 0; i < 4; i++) {
            shades[i] = new View(context);
            shades[i].setBackgroundColor(DIM);
            layer.addView(shades[i], new FrameLayout.LayoutParams(0, 0));
            corners[i] = new View(context);
            layer.addView(corners[i], new FrameLayout.LayoutParams(0, 0));
        }
        focus = new FrameLayout(context);
        focus.setContentDescription(I18n.t("Нажать выделенную кнопку", "Tap the highlighted button"));
        layer.addView(focus, new FrameLayout.LayoutParams(0, 0));
        wave = new View(context);
        cursor = new View(context);
        wave.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        cursor.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        focus.addView(wave, new FrameLayout.LayoutParams(dp(24), dp(24), Gravity.CENTER));
        focus.addView(cursor, new FrameLayout.LayoutParams(dp(20), dp(20), Gravity.CENTER));

        card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(12), dp(14), dp(10));
        card.setElevation(dp(6));
        layer.addView(card, new FrameLayout.LayoutParams(0, 0));
        descriptionScroll = new ScrollView(context);
        description = new LinearLayout(context);
        description.setOrientation(LinearLayout.VERTICAL);
        descriptionScroll.addView(description);
        progress = text(context, 12, false);
        title = text(context, 17, true);
        body = text(context, 14, false);
        description.addView(progress, new LinearLayout.LayoutParams(-1, -2));
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(-1, -2);
        titleParams.topMargin = dp(5);
        description.addView(title, titleParams);
        LinearLayout.LayoutParams bodyParams = new LinearLayout.LayoutParams(-1, -2);
        bodyParams.topMargin = dp(6);
        description.addView(body, bodyParams);
        card.addView(descriptionScroll, new LinearLayout.LayoutParams(-1, -2));
        controls = new LinearLayout(context);
        controls.setGravity(Gravity.CENTER_VERTICAL);
        stop = text(context, 13, false);
        stop.setText(I18n.t("Завершить", "End tutorial"));
        press = text(context, 14, true);
        for (TextView button : new TextView[]{stop, press}) {
            button.setGravity(Gravity.CENTER);
            button.setMinHeight(dp(44));
            button.setPadding(dp(4), dp(6), dp(4), dp(6));
            controls.addView(button, new LinearLayout.LayoutParams(0, -2, 1f));
        }
        LinearLayout.LayoutParams controlParams = new LinearLayout.LayoutParams(-1, -2);
        controlParams.topMargin = dp(6);
        card.addView(controls, controlParams);
        focus.setOnClickListener(view -> pressTarget());
        press.setOnClickListener(view -> pressTarget());
        stop.setOnClickListener(view -> dismiss(end));
        layer.setOnKeyListener((view, key, event) -> {
            if (key != KeyEvent.KEYCODE_BACK) return false;
            if (event.getAction() == KeyEvent.ACTION_UP) dismiss(end);
            return true;
        });
        layer.getViewTreeObserver().addOnPreDrawListener(layoutListener);
        layer.requestFocus();
    }

    void present(View next, String heading, String explanation, String counter,
                 String button, Runnable customAction, Runnable finish, boolean clickAllowed) {
        if (closed || leaving) return;
        boolean newTarget = target != next;
        boolean changed = newTarget || !heading.equals(shownTitle) || !explanation.equals(shownBody)
                || !counter.equals(shownCounter) || !button.equals(shownButton);
        if (newTarget) {
            target = next;
            moving = !displayed.isEmpty();
            target.requestRectangleOnScreen(new Rect(0, -dp(24), Math.max(1, target.getWidth()),
                    target.getHeight() + dp(200)), true);
        }
        action = customAction;
        end = finish;
        allowed = clickAllowed;
        if (changed) {
            shownTitle = heading; shownBody = explanation; shownCounter = counter; shownButton = button;
            card.animate().cancel();
            if (started && motion) {
                card.animate().alpha(0f).translationY(dp(8)).setDuration(100L).withEndAction(() -> {
                    if (closed || leaving) return;
                    updateText(); enterPending = true; layout();
                }).start();
            } else { updateText(); enterPending = true; }
        }
        applyTheme();
        layout();
    }

    private void updateText() {
        title.setText(shownTitle); body.setText(shownBody);
        progress.setText(shownCounter); press.setText(shownButton);
        descriptionScroll.scrollTo(0, 0);
    }

    private void applyTheme() {
        int nextAccent = Theme.getColor(Theme.key_windowBackgroundWhiteBlueText);
        int nextSurface = Theme.getColor(Theme.key_windowBackgroundWhite);
        int nextForeground = Theme.getColor(Theme.key_windowBackgroundWhiteBlackText);
        int nextMuted = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText);
        if (nextAccent == accent && nextSurface == surface && nextForeground == foreground && nextMuted == muted) return;
        accent = nextAccent; surface = nextSurface;
        foreground = nextForeground; muted = nextMuted;
        card.setBackground(rounded(surface, 0, 0, dp(18)));
        cursor.setBackground(circle(accent, surface, dp(2)));
        wave.setBackground(circle(0, accent, dp(2)));
        cornerRadius = -1;
        title.setTextColor(foreground); body.setTextColor(foreground);
        progress.setTextColor(accent); press.setTextColor(accent);
        stop.setTextColor(muted);
    }

    boolean isClosed() { return closed; }

    private void pressTarget() {
        View clicked = target;
        if (closed || leaving || !allowed || clicked == null || !clicked.isShown()
                || (action == null && !clicked.isEnabled())) return;
        Runnable custom = action;
        clicked.setPressed(true);
        clicked.postDelayed(() -> clicked.setPressed(false), 150L);
        dismiss(() -> {
            if (!clicked.isAttachedToWindow()) return;
            if (custom != null) custom.run();
            else clicked.performClick();
        });
    }

    private void dismiss(Runnable after) {
        if (closed || leaving) return;
        leaving = true;
        stop.setEnabled(false); press.setEnabled(false); focus.setEnabled(false);
        cancelMotion();
        Runnable remove = () -> { if (closed) return; close(); if (after != null) after.run(); };
        if (!motion) remove.run();
        else layer.animate().alpha(0f).setDuration(140L).withEndAction(remove).start();
    }

    private void layout() {
        if (closed || leaving || target == null || layer.getWidth() == 0 || layer.getHeight() == 0) return;
        boolean enabled = allowed && (action != null || target.isEnabled());
        press.setEnabled(enabled); focus.setEnabled(enabled);
        press.setAlpha(enabled ? 1f : 0.45f);
        cursor.setAlpha(enabled ? 1f : 0.45f);
        Rect area = new Rect();
        if (!target.getGlobalVisibleRect(area)) { close(); return; }
        layer.getLocationOnScreen(origin);
        area.offset(-origin[0], -origin[1]);
        if (!area.intersect(0, 0, layer.getWidth(), layer.getHeight())) { close(); return; }
        destination.set(area);
        if (moving && motion) {
            moving = false;
            Rect from = new Rect(displayed);
            if (travel != null) travel.cancel();
            travel = ValueAnimator.ofFloat(0f, 1f);
            travel.setDuration(300L);
            travel.setInterpolator(new DecelerateInterpolator());
            travel.addUpdateListener(animation -> {
                if (closed || leaving) return;
                float part = (float) animation.getAnimatedValue();
                displayed.set(mix(from.left, destination.left, part), mix(from.top, destination.top, part),
                        mix(from.right, destination.right, part), mix(from.bottom, destination.bottom, part));
                renderGeometry();
            });
            travel.start();
        } else if (travel == null || !travel.isRunning()) {
            displayed.set(destination); renderGeometry();
        }
    }

    private void renderGeometry() {
        Rect area = displayed;
        int width = layer.getWidth(), height = layer.getHeight();
        place(shades[0], 0, 0, width, area.top);
        place(shades[1], 0, area.bottom, width, height - area.bottom);
        place(shades[2], 0, area.top, area.left, area.height());
        place(shades[3], area.right, area.top, width - area.right, area.height());
        int radius = Math.min(targetRadius(), Math.min(area.width(), area.height()) / 2);
        if (radius != cornerRadius) {
            cornerRadius = radius;
            focus.setBackground(rounded(0, accent, dp(2), radius));
            for (int i = 0; i < 4; i++) {
                GradientDrawable mask = new GradientDrawable();
                mask.setGradientType(GradientDrawable.RADIAL_GRADIENT);
                mask.setColors(new int[]{0, 0, DIM}, new float[]{0f, 0.995f, 1f});
                mask.setGradientRadius(Math.max(1, radius));
                mask.setGradientCenter((i % 2 == 0) ? 1f : 0f, i < 2 ? 1f : 0f);
                corners[i].setBackground(mask);
            }
        }
        place(corners[0], area.left, area.top, radius, radius);
        place(corners[1], area.right - radius, area.top, radius, radius);
        place(corners[2], area.left, area.bottom - radius, radius, radius);
        place(corners[3], area.right - radius, area.bottom - radius, radius, radius);
        place(focus, area.left, area.top, area.width(), area.height());
        layer.getWindowVisibleDisplayFrame(visibleWindow);
        int safeTop = Math.max(0, visibleWindow.top - origin[1]);
        int safeBottom = Math.min(height, visibleWindow.bottom - origin[1]);
        if (safeBottom <= safeTop) { safeTop = 0; safeBottom = height; }
        int budget = TutorialPlacement.availableHeight(area.top, area.bottom, safeTop, safeBottom, dp(10), dp(12));
        int cardWidth = Math.max(1, Math.min(dp(320), width - dp(28)));
        int textWidth = Math.max(1, cardWidth - dp(28));
        controls.measure(View.MeasureSpec.makeMeasureSpec(textWidth, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED));
        description.measure(View.MeasureSpec.makeMeasureSpec(textWidth, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED));
        int textHeight = Math.min(description.getMeasuredHeight(), Math.max(0, budget - dp(28) - controls.getMeasuredHeight()));
        LinearLayout.LayoutParams textParams = (LinearLayout.LayoutParams) descriptionScroll.getLayoutParams();
        if (textParams.height != textHeight) { textParams.height = textHeight; descriptionScroll.setLayoutParams(textParams); }
        card.measure(View.MeasureSpec.makeMeasureSpec(cardWidth, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(Math.max(1, budget), View.MeasureSpec.AT_MOST));
        int cardHeight = card.getMeasuredHeight();
        int top = TutorialPlacement.cardTop(area.top, area.bottom, safeTop, safeBottom, cardHeight, dp(10), dp(12));
        place(card, (width - cardWidth) / 2, top, cardWidth, cardHeight);
        if (!started) {
            started = true;
            if (motion) layer.animate().alpha(1f).setDuration(220L).start();
            startTapLoop();
        }
        if (enterPending) {
            enterPending = false;
            card.setAlpha(motion ? 0f : 1f);
            card.setTranslationY(motion ? dp(8) : 0f);
            card.setScaleX(motion ? 0.97f : 1f); card.setScaleY(motion ? 0.97f : 1f);
            if (motion) card.animate().alpha(1f).translationY(0f).scaleX(1f).scaleY(1f)
                    .setInterpolator(new DecelerateInterpolator()).setDuration(230L).start();
        }
    }

    private int targetRadius() {
        Drawable drawable = target.getBackground();
        if (drawable instanceof RippleDrawable && ((RippleDrawable) drawable).getNumberOfLayers() > 0)
            drawable = ((RippleDrawable) drawable).getDrawable(0);
        if (drawable != null) drawable = drawable.getCurrent();
        return drawable instanceof GradientDrawable ? Math.round(((GradientDrawable) drawable).getCornerRadius()) : dp(14);
    }

    private void startTapLoop() {
        if (closed || leaving || !motion || !ValueAnimator.areAnimatorsEnabled()) { wave.setAlpha(0f); return; }
        tapLoop = new AnimatorSet();
        ObjectAnimator x = ObjectAnimator.ofFloat(cursor, "translationX", dp(28), 0f);
        ObjectAnimator y = ObjectAnimator.ofFloat(cursor, "translationY", -dp(22), 0f);
        x.setDuration(400L); y.setDuration(400L);
        ObjectAnimator sx = ObjectAnimator.ofFloat(cursor, "scaleX", 1f, 0.65f, 1f);
        ObjectAnimator sy = ObjectAnimator.ofFloat(cursor, "scaleY", 1f, 0.65f, 1f);
        sx.setStartDelay(400L); sy.setStartDelay(400L);
        sx.setDuration(280L); sy.setDuration(280L);
        ObjectAnimator wx = ObjectAnimator.ofFloat(wave, "scaleX", 1f, 2.8f);
        ObjectAnimator wy = ObjectAnimator.ofFloat(wave, "scaleY", 1f, 2.8f);
        ObjectAnimator wa = ObjectAnimator.ofFloat(wave, "alpha", 0.8f, 0f);
        for (ObjectAnimator animation : new ObjectAnimator[]{wx, wy, wa}) {
            animation.setStartDelay(420L); animation.setDuration(700L);
        }
        ValueAnimator pause = ValueAnimator.ofFloat(0f, 1f);
        pause.setDuration(1800L);
        tapLoop.playTogether(x, y, sx, sy, wx, wy, wa, pause);
        tapLoop.addListener(new AnimatorListenerAdapter() {
            @Override public void onAnimationEnd(Animator animation) {
                if (!closed && !leaving && ValueAnimator.areAnimatorsEnabled()) layer.postDelayed(repeatTap, 100L);
            }
        });
        tapLoop.start();
    }

    private void cancelMotion() {
        layer.removeCallbacks(repeatTap);
        card.animate().cancel();
        if (travel != null) travel.cancel();
        if (tapLoop != null) tapLoop.cancel();
    }

    @Override public void close() {
        if (closed) return;
        closed = true;
        layer.animate().cancel(); cancelMotion();
        if (layer.getViewTreeObserver().isAlive()) layer.getViewTreeObserver().removeOnPreDrawListener(layoutListener);
        if (layer.getParent() instanceof ViewGroup) ((ViewGroup) layer.getParent()).removeView(layer);
        target = null; action = null; end = null;
    }

    private static void place(View view, int x, int y, int width, int height) {
        FrameLayout.LayoutParams old = (FrameLayout.LayoutParams) view.getLayoutParams();
        width = Math.max(0, width); height = Math.max(0, height);
        if (old.leftMargin == x && old.topMargin == y && old.width == width && old.height == height) return;
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(width, height, Gravity.TOP | Gravity.LEFT);
        params.leftMargin = x; params.topMargin = y; view.setLayoutParams(params);
    }
    private static int mix(int from, int to, float part) { return Math.round(from + (to - from) * part); }
    private static TextView text(Context context, int size, boolean bold) {
        TextView text = new TextView(context); text.setTextSize(size);
        text.setTypeface(Typeface.DEFAULT, bold ? Typeface.BOLD : Typeface.NORMAL); return text;
    }
    private static GradientDrawable circle(int fill, int border, int width) {
        GradientDrawable drawable = new GradientDrawable(); drawable.setShape(GradientDrawable.OVAL);
        drawable.setColor(fill); if (width > 0) drawable.setStroke(width, border); return drawable;
    }
    private static GradientDrawable rounded(int fill, int border, int width, int radius) {
        GradientDrawable drawable = new GradientDrawable(); drawable.setColor(fill); drawable.setCornerRadius(radius);
        if (width > 0) drawable.setStroke(width, border); return drawable;
    }
    private static int dp(float value) { return AndroidUtilities.dp(value); }
}
