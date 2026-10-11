package com.extera.plugins.exitfy;

import android.content.Context;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;
import org.telegram.messenger.R;
import org.telegram.ui.ActionBar.Theme;

/** Steps are data: progress and the final saved position use their actual count. */
final class ExitFyTutorial extends ExitFySubscreenFragment<ExitFyDashboardState> {
    private final String[][] steps = steps();
    private int index;
    private TextView progress;
    private TextView title;
    private TextView explanation;
    private SettingRow action;
    private SettingRow next;
    private SettingRow back;

    static int count() { return steps().length; }

    private static String[][] steps() {
        return new String[][]{
            {I18n.t("Добро пожаловать в exitFy", "Welcome to exitFy"),
             I18n.t("Плагин направляет трафик Telegram через выбранный вами сервер. Системный VPN включать не нужно. Обучение ничего не подключает автоматически.", "The plugin routes Telegram through a server you choose. No system VPN is required. This tutorial does not connect automatically.")},
            {I18n.t("Выберите источник", "Choose a source"),
             I18n.t("На главном экране нажмите «Источник серверов». Выберите Shrimp, Elix, Sworkle или «Пользовательский» для своей подписки.", "Tap Server source on the main screen. Choose Shrimp, Elix, Sworkle, or Custom for your own subscription.")},
            {I18n.t("Добавьте свою подписку или конфиг", "Add a subscription or config"),
             I18n.t("В пользовательском источнике можно добавить ссылку подписки, ссылку отдельного сервера или конфиг AmneziaWG. Ключи остаются на вашем устройстве. Ссылку и конфиг не публикуйте.", "In Custom you can add a subscription link, a server link, or an AmneziaWG config. Keys stay on your device. Keep links and configs private.")},
            {I18n.t("Обновите серверы", "Refresh servers"),
             I18n.t("Нажмите «Обновить подписки». У каждого источника показано число серверов. При ошибке прежний список сохраняется, а причина появляется на экране.", "Tap Refresh subscriptions. Each source shows its server count. A failed refresh keeps the previous list and displays the reason.")},
            {I18n.t("Проверьте задержку", "Check latency"),
             I18n.t("«Проверить пинг» есть на главном экране и в выборе серверов. По умолчанию используется TCP. В списке можно включить сортировку по пингу: быстрые серверы окажутся первыми.", "Check ping is on the dashboard and in the server picker. TCP is the default. Sort by ping to put the fastest servers first.")},
            {I18n.t("Выберите сервер и подключитесь", "Choose a server and connect"),
             I18n.t("Нажатие на карточку активного сервера открывает выбор. После выбора нажмите «Подключить». При первом подключении exitFy загрузит нужные компоненты; дождитесь завершения.", "Tap the active server card to choose a server, then tap Connect. The first connection downloads the required components; wait until installation finishes.")},
            {I18n.t("Балансировщик и подписки", "Balancer and subscriptions"),
             I18n.t("Если серверов несколько, в «Дополнительно» доступен балансировщик: Round Robin распределяет новые соединения, Sticky Session выбирает самый быстрый сервер. Удержание подписки позволяет переместить, скрыть или удалить её.", "With multiple servers, Advanced offers a balancer: Round Robin distributes new connections; Sticky Session chooses the fastest server. Hold a subscription to move, hide, or remove it.")},
            {I18n.t("Готово", "Ready"),
             I18n.t("Два ядра включены по умолчанию. Звонки через exitFy и автоматические обновления настраиваются в «Дополнительно». Там же можно снова запустить обучение. После обновления с просьбой о перезапуске полностью закройте клиент и откройте его снова.", "Both cores are enabled by default. Calls and automatic refresh are configured in Advanced. You can also replay this tutorial there. If an update requests a restart, fully close and reopen the client.")}
        };
    }

    @Override protected CharSequence screenTitle() { return I18n.t("Обучение exitFy", "exitFy tutorial"); }
    @Override protected ExitFyDashboardState parseUiState(String json) { return ExitFyDashboardState.parse(json); }

    @Override protected void buildContent(Context context, LinearLayout content) {
        progress = text(context, 16, Theme.key_windowBackgroundWhiteGrayText, false);
        title = text(context, 24, Theme.key_windowBackgroundWhiteBlackText, true);
        explanation = text(context, 17, Theme.key_windowBackgroundWhiteBlackText, false);
        content.addView(progress, sectionParams());
        content.addView(title, sectionParams());
        content.addView(explanation, sectionParams());
        action = settingRow(context, R.drawable.msg_folders, I18n.t("Открыть серверы", "Open servers"), "");
        setSafeClick(action.view, () -> {
            ExitFyServersFragment fragment = new ExitFyServersFragment();
            fragment.setCurrentAccount(currentAccount);
            presentFragment(fragment);
        });
        content.addView(action.view, sectionParams());
        next = settingRow(context, R.drawable.msg_arrowright, I18n.t("Далее", "Next"), "");
        setSafeClick(next.view, () -> saveStep(index + 1));
        content.addView(next.view, sectionParams());
        back = settingRow(context, R.drawable.msg_reset, I18n.t("Назад", "Back"), "");
        setSafeClick(back.view, () -> saveStep(Math.max(0, index - 1)));
        content.addView(back.view, sectionParams());
        SettingRow skip = settingRow(context, R.drawable.msg_close, I18n.t("Пропустить обучение", "Skip tutorial"), "");
        setSafeClick(skip.view, () -> saveStep(steps.length));
        content.addView(skip.view, sectionParams());
    }

    @Override protected void renderUiState(ExitFyDashboardState state) {
        index = Math.min(state.tutorialStep, steps.length - 1);
        progress.setText(I18n.format("Шаг %s из %s", "Step %s of %s", index + 1, steps.length));
        title.setText(steps[index][0]);
        explanation.setText(steps[index][1]);
        action.view.setVisibility(index > 0 && index < 6 ? View.VISIBLE : View.GONE);
        back.view.setVisibility(index == 0 ? View.GONE : View.VISIBLE);
        next.setValue(index == steps.length - 1 ? I18n.t("Завершить", "Finish") : I18n.t("Продолжить", "Continue"));
    }

    private void saveStep(int step) {
        executeCommand(() -> new JSONObject().put("command", "set_setting")
                .put("key", "tutorial_step").put("value", step), false,
                result -> { if (result.ok && step >= steps.length) finishFragment(); });
    }
}
