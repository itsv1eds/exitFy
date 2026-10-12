package com.extera.plugins.exitfy;

import android.app.Activity;
import android.view.View;
import org.json.JSONObject;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import java.lang.ref.WeakReference;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/** A highlight follows actual user actions between the existing plugin screens. */
final class ExitFyTutorial {
    private final TutorialFlow flow;
    private final ExecutorService progressWriter = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "exitfy-tutorial-progress");
        thread.setDaemon(true);
        return thread;
    });
    private WeakReference<BaseFragment> visible = new WeakReference<>(null);
    private Runnable refresh;
    private View pollView;
    private TutorialOverlay overlay;
    private boolean active = true;
    private boolean needsCustomSource;
    private boolean pauseAction;
    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (!active || pollView == null || refresh == null) return;
            refresh.run();
            if (pollView != null) pollView.postDelayed(this, 350L);
        }
    };

    private ExitFyTutorial(boolean replay) { flow = new TutorialFlow(replay); }
    static int count() { return TutorialFlow.count(); }

    static boolean offerWelcome(BaseFragment owner) {
        Activity activity = owner == null ? null : owner.getParentActivity();
        if (activity == null || activity.isFinishing()
                || (owner.getVisibleDialog() != null && owner.getVisibleDialog().isShowing())) return false;
        AlertDialog dialog = new AlertDialog.Builder(activity, owner.getResourceProvider())
                .setTitle(I18n.t("Добро пожаловать в exitFy", "Welcome to exitFy"))
                .setMessage(I18n.t("Показать, как установить компоненты и пользоваться плагином? Подсказки выделят нужные кнопки. Все действия выполняются только после вашего нажатия.",
                        "Would you like a walkthrough of component installation and the plugin? Hints highlight the buttons. Actions only run when you tap."))
                .setNegativeButton(I18n.t("Не сейчас", "Not now"), null)
                .setPositiveButton(I18n.t("Начать обучение", "Start tutorial"),
                        (ignored, which) -> start(owner, false)).create();
        return owner.showDialog(dialog) != null;
    }

    static void start(BaseFragment owner, boolean replay) {
        if (owner == null || owner.getParentActivity() == null) return;
        ExitFyTutorial tour = new ExitFyTutorial(replay);
        ExitFyDashboardFragment dashboard = new ExitFyDashboardFragment(tour);
        dashboard.setCurrentAccount(owner.getCurrentAccount());
        if (owner.presentFragment(dashboard)) tour.saveProgress();
        else tour.close();
    }

    void attach(BaseFragment owner, Runnable render) {
        if (!active || owner == null || owner.getFragmentView() == null) return;
        detach(visible.get());
        visible = new WeakReference<>(owner);
        refresh = render;
        pollView = owner.getFragmentView();
        pollView.postDelayed(poll, 350L);
    }

    void detach(BaseFragment owner) {
        if (owner != visible.get()) return;
        if (pollView != null) pollView.removeCallbacks(poll);
        pollView = null;
        refresh = null;
        visible.clear();
        hide();
    }

    void close() {
        active = false;
        detach(visible.get());
        progressWriter.shutdown();
    }

    private void finish() {
        flow.finish();
        saveProgress();
        close();
    }

    private void saveProgress() {
        int position = flow.position();
        try {
            progressWriter.execute(() -> {
                try {
                    ExitFyBridge.execute(new JSONObject().put("command", "set_setting")
                            .put("key", "tutorial_step").put("value", position).toString());
                } catch (Exception ignored) { }
            });
        } catch (RejectedExecutionException ignored) { }
    }

    private void advance(TutorialFlow.Step step) {
        if (active && flow.advance(step, true)) { hide(); saveProgress(); }
    }

    void sourceOpened() { advance(TutorialFlow.Step.SOURCE); }
    void providerChosen(int provider, boolean configured) {
        if (flow.step() != TutorialFlow.Step.PROVIDER) return;
        needsCustomSource = provider == SettingsModel.CUSTOM_PROVIDER_ID && !configured;
        if (!needsCustomSource) advance(TutorialFlow.Step.PROVIDER);
        else hide();
    }
    void serverCommand(String command) {
        if (needsCustomSource && ("add_subscription".equals(command)
                || "add_node".equals(command) || "import_text".equals(command))) {
            needsCustomSource = false;
            advance(TutorialFlow.Step.PROVIDER);
        }
        if ("refresh_subscriptions".equals(command)) advance(TutorialFlow.Step.REFRESH);
        if ("select_node".equals(command)) advance(TutorialFlow.Step.SELECT);
    }
    void serverSelected() { advance(TutorialFlow.Step.SELECT); }
    void pingRequested() { advance(TutorialFlow.Step.PING); }
    boolean selectingServer() { return active && flow.step() == TutorialFlow.Step.SELECT; }
    boolean returningToDashboard() {
        return active && flow.step().ordinal() >= TutorialFlow.Step.PING.ordinal();
    }

    void dashboard(BaseFragment owner, ExitFyDashboardState state,
                   View install, View source, View server, View ping, View advanced) {
        if (!active) return;
        if (flow.step() == TutorialFlow.Step.INSTALL && state.runtimeAvailable
                && !state.coreInstall.required) advance(TutorialFlow.Step.INSTALL);
        TutorialFlow.Step step = flow.step();
        pauseAction = state.coreInstall.active() || (step == TutorialFlow.Step.PING && state.pingRunning)
                || (step == TutorialFlow.Step.CONNECT && state.pingRunning);
        if (step == TutorialFlow.Step.PROVIDER || step == TutorialFlow.Step.REFRESH) {
            show(owner, source, I18n.t("Продолжите в списке серверов", "Continue in the server list"),
                    I18n.t("Откройте источник, чтобы выбрать провайдера и обновить подписки.",
                            "Open the source to choose a provider and refresh subscriptions."), null);
            return;
        }
        View target;
        String title;
        String body;
        Runnable action = null;
        switch (step) {
            case INSTALL:
                target = install; title = I18n.t("Установите компоненты", "Install components");
                body = I18n.t("Нажмите выделенную кнопку и дождитесь завершения загрузки. Подсказка продолжится, когда компоненты будут готовы.",
                        "Tap the highlighted button and wait for the download. The tutorial continues when the components are ready."); break;
            case SOURCE:
                target = source; title = I18n.t("Откройте источник серверов", "Open the server source");
                body = I18n.t("Нажмите на выделенную карточку. Там можно выбрать провайдера или добавить свою подписку.",
                        "Tap the highlighted card to choose a provider or add your own subscription."); break;
            case SELECT:
                target = server; title = I18n.t("Выберите сервер", "Choose a server");
                body = state.serverCount == 0
                        ? I18n.t("Серверов пока нет. Откройте список, проверьте источник и повторите обновление.",
                                "There are no servers yet. Open the list, check the source and retry the refresh.")
                        : I18n.t("Нажмите на карточку активного сервера, затем выберите сервер в открывшемся списке.",
                                "Tap the active server card, then select a server in the list."); break;
            case PING:
                target = ping; title = I18n.t("Проверьте задержку", "Check latency");
                body = I18n.t("Нажмите «Проверить пинг». Результаты видны в списке серверов; TCP не прерывает подключение.",
                        "Tap Check ping. Results appear in the server list; TCP does not interrupt the connection."); break;
            case CONNECT:
                target = install; title = I18n.t("Подключитесь", "Connect");
                body = "RUNNING".equals(state.runtimeState)
                        ? I18n.t("Вы уже подключены. Эта кнопка включает и отключает exitFy. Нажмите «Продолжить», чтобы сохранить подключение.",
                                "You are already connected. This button connects and disconnects exitFy. Tap Continue to keep the connection.")
                        : I18n.t("Нажмите «Подключить». После успешного подключения нажмите «Продолжить». Если нужны компоненты, сначала установите их этой же кнопкой.",
                                "Tap Connect. After a successful connection, tap Continue. If components are required, install them using this button first.");
                if ("RUNNING".equals(state.runtimeState)) action = () -> advance(TutorialFlow.Step.CONNECT);
                break;
            case ADVANCED:
                target = advanced; title = I18n.t("Откройте дополнительные настройки", "Open Advanced");
                body = I18n.t("Здесь находятся автоматизация, подписки, проверка задержки, звонки и компоненты. Нажмите на карточку.",
                        "Automation, subscriptions, latency checks, calls and components are here. Tap the card."); break;
            default: return;
        }
        show(owner, target, title, body, action);
    }

    void servers(BaseFragment owner, ExitFyDashboardState state,
                 View provider, View add, View refreshTarget, View firstServer) {
        if (!active) return;
        pauseAction = state.refreshRunning || state.importRunning;
        if (needsCustomSource && state.providerId == SettingsModel.CUSTOM_PROVIDER_ID
                && (state.customUrlCount > 0 || state.serverCount > 0)) {
            needsCustomSource = false;
            advance(TutorialFlow.Step.PROVIDER);
        }
        TutorialFlow.Step step = flow.step();
        if (step == TutorialFlow.Step.PROVIDER) {
            show(owner, needsCustomSource ? add : provider,
                    needsCustomSource ? I18n.t("Добавьте свою подписку", "Add your subscription")
                            : I18n.t("Выберите провайдера", "Choose a provider"),
                    needsCustomSource ? I18n.t("Нажмите «Добавить подписку» и вставьте ссылку. Добавление выполняется только после подтверждения.",
                            "Tap Add subscription and paste the link. It is added only after you confirm.")
                            : I18n.t("Нажмите на провайдера и выберите Shrimp, Elix, Sworkle или «Пользовательский». Можно подтвердить уже выбранный источник.",
                            "Tap Provider and choose Shrimp, Elix, Sworkle or Custom. You can confirm the current source."), null);
        } else if (step == TutorialFlow.Step.REFRESH || step == TutorialFlow.Step.SELECT) {
            boolean choose = step == TutorialFlow.Step.SELECT && firstServer != null && !state.refreshRunning;
            show(owner, choose ? firstServer : refreshTarget,
                    choose ? I18n.t("Выберите сервер", "Choose a server")
                            : I18n.t("Обновите подписки", "Refresh subscriptions"),
                    choose ? I18n.t("Нажмите на сервер в списке, затем «Выбрать» в его окне. После выбора вернёмся на главный экран и проверим задержку.",
                            "Tap a server in the list, then Select in its dialog. We will return to the dashboard and check latency.")
                            : I18n.t("Нажмите выделенную кнопку и дождитесь появления серверов. При ошибке проверьте ссылку или источник и повторите обновление.",
                            "Tap the highlighted button and wait for servers. On an error, check the URL or source and retry."), null);
        }
    }

    void preferences(BaseFragment owner, View target) {
        if (!active || flow.step() != TutorialFlow.Step.ADVANCED) return;
        pauseAction = false;
        show(owner, target, I18n.t("Обучение завершено", "Tutorial complete"),
                I18n.t("Настройки разделены по группам. Обучение можно снова запустить в «Помощь» — установка компонентов при повторе пропускается.",
                        "Settings are grouped. Replay the tutorial from Help; component installation is skipped on replay."), this::finish);
    }

    private void show(BaseFragment owner, View target, String title, String body, Runnable action) {
        if (owner != visible.get() || target == null || !target.isShown()) { hide(); return; }
        if (owner.getVisibleDialog() != null && owner.getVisibleDialog().isShowing()) { hide(); return; }
        if (overlay == null || overlay.isClosed()) overlay = new TutorialOverlay(owner);
        overlay.present(target, title, body,
                I18n.format("Шаг %s из %s", "Step %s of %s", flow.position() + 1, count()),
                action == null ? I18n.t("Нажать выделенную кнопку", "Tap the highlighted button")
                        : flow.step() == TutorialFlow.Step.ADVANCED ? I18n.t("Готово", "Done")
                        : I18n.t("Продолжить", "Continue"), action, this::finish, !pauseAction);
    }

    private void hide() { if (overlay != null) { overlay.close(); overlay = null; } }
}
