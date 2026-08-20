package com.extera.plugins.exitfy;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.LocaleController;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.Components.AnimatedFloat;
import org.telegram.ui.Components.AnimatedTextView;
import org.telegram.ui.Components.CubicBezierInterpolator;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.StickerImageView;

/**
 * Aggregate core-installation progress. Deliberately contains no core family
 * names or versions: the dashboard treats both required binaries as one task.
 */
@SuppressLint("ViewConstructor") // Programmatic dialog view needs account/theme inputs.
final class CoreInstallProgressView extends FrameLayout {
    private final Theme.ResourcesProvider resourcesProvider;
    private final AnimatedTextView percentView;
    private final InstallProgressBar progressBar;
    private final TextView titleView;
    private final TextView subtitleView;
    private int lastProgress = -1;

    CoreInstallProgressView(Context context, int currentAccount,
                            Theme.ResourcesProvider resourcesProvider) {
        super(context);
        this.resourcesProvider = resourcesProvider;

        StickerImageView imageView = new StickerImageView(context, currentAccount);
        imageView.getImageReceiver().setAutoRepeat(1);
        imageView.setStickerPackName("UtyaDuck");
        imageView.setStickerNum(16);
        imageView.setImportantForAccessibility(
                View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        addView(imageView, LayoutHelper.createFrame(
                150, 150, Gravity.CENTER_HORIZONTAL | Gravity.TOP,
                0, 16, 0, 0));

        percentView = new AnimatedTextView(context, false, true, true);
        percentView.setAnimationProperties(
                .35f, 0, 120, CubicBezierInterpolator.EASE_OUT);
        percentView.setGravity(Gravity.CENTER_HORIZONTAL);
        percentView.setTextSize(AndroidUtilities.dp(24));
        percentView.setTypeface(AndroidUtilities.bold());
        addView(percentView, LayoutHelper.createFrame(
                LayoutHelper.MATCH_PARENT, 32,
                Gravity.CENTER_HORIZONTAL | Gravity.TOP,
                0, 176, 0, 0));

        progressBar = new InstallProgressBar(context, resourcesProvider);
        addView(progressBar, LayoutHelper.createFrame(
                240, 5, Gravity.CENTER_HORIZONTAL | Gravity.TOP,
                0, 236, 0, 0));

        titleView = new TextView(context);
        titleView.setGravity(Gravity.CENTER_HORIZONTAL);
        titleView.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 16);
        titleView.setTypeface(AndroidUtilities.bold());
        titleView.setText(I18n.t("Установка компонентов", "Installing components"));
        titleView.setIncludeFontPadding(false);
        addView(titleView, LayoutHelper.createFrame(
                LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT,
                Gravity.CENTER_HORIZONTAL | Gravity.TOP,
                20, 271, 20, 0));

        subtitleView = new TextView(context);
        subtitleView.setGravity(Gravity.CENTER_HORIZONTAL);
        subtitleView.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 14);
        subtitleView.setIncludeFontPadding(false);
        subtitleView.setMaxLines(2);
        addView(subtitleView, LayoutHelper.createFrame(
                240, LayoutHelper.WRAP_CONTENT,
                Gravity.CENTER_HORIZONTAL | Gravity.TOP,
                0, 302, 0, 0));

        applyTheme();
    }

    void setState(ExitFyDashboardState.CoreInstallState state) {
        if (state == null) return;
        int progress = Math.max(0, Math.min(100, state.progress));
        boolean animate = lastProgress >= 0 && progress != lastProgress;
        lastProgress = progress;
        percentView.cancelAnimation();
        percentView.setText(progress + "%", animate && !LocaleController.isRTL);
        progressBar.setProgress(progress / 100f);
        subtitleView.setText(state.stageLabel());
        setContentDescription(I18n.format(
                "Установка компонентов. Прогресс: %d%%. %s",
                "Installing components. Progress: %d%%. %s",
                progress, state.stageLabel()));
    }

    void applyTheme() {
        percentView.setTextColor(Theme.getColor(
                Theme.key_dialogTextBlack, resourcesProvider));
        titleView.setTextColor(Theme.getColor(
                Theme.key_dialogTextBlack, resourcesProvider));
        subtitleView.setTextColor(Theme.getColor(
                Theme.key_dialogTextGray2, resourcesProvider));
        progressBar.applyTheme();
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(
                MeasureSpec.makeMeasureSpec(
                        MeasureSpec.getSize(widthMeasureSpec), MeasureSpec.EXACTLY),
                MeasureSpec.makeMeasureSpec(
                        AndroidUtilities.dp(350), MeasureSpec.EXACTLY));
    }

    private static final class InstallProgressBar extends View {
        private final Theme.ResourcesProvider resourcesProvider;
        private final Paint fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final RectF bounds = new RectF();
        private final AnimatedFloat animatedProgress =
                new AnimatedFloat(this, 350, CubicBezierInterpolator.EASE_OUT);
        private float progress;

        InstallProgressBar(Context context,
                           Theme.ResourcesProvider resourcesProvider) {
            super(context);
            this.resourcesProvider = resourcesProvider;
            applyTheme();
        }

        void setProgress(float value) {
            progress = Math.max(0f, Math.min(1f, value));
            invalidate();
        }

        void applyTheme() {
            int accent = Theme.getColor(
                    Theme.key_switchTrackChecked, resourcesProvider);
            fillPaint.setColor(accent);
            trackPaint.setColor(Theme.multAlpha(accent, .2f));
            invalidate();
        }

        @Override
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            float radius = AndroidUtilities.dp(3);
            bounds.set(0, 0, getMeasuredWidth(), getMeasuredHeight());
            canvas.drawRoundRect(bounds, radius, radius, trackPaint);
            bounds.right = getMeasuredWidth() * animatedProgress.set(progress);
            canvas.drawRoundRect(bounds, radius, radius, fillPaint);
        }
    }
}
