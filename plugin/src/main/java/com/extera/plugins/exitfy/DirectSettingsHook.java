package com.extera.plugins.exitfy;

import android.os.Looper;

import com.exteragram.messenger.plugins.Plugin;
import com.exteragram.messenger.plugins.PythonPluginsEngine;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.FileLog;
import org.telegram.ui.ActionBar.BaseFragment;

import java.util.concurrent.atomic.AtomicBoolean;

/** Routes the host's canonical plugin-settings overload directly to exitFy. */
final class DirectSettingsHook implements AutoCloseable {
    private static final String TAG = "exitFy";
    private static final String PLUGIN_ID = "exitFy_v2";

    private final AtomicBoolean active = new AtomicBoolean();
    private XC_MethodHook.Unhook hook;

    synchronized void install() {
        if (!active.compareAndSet(false, true)) return;
        try {
            hook = XposedBridge.hookMethod(
                    PythonPluginsEngine.class.getDeclaredMethod(
                            "openPluginSettings", Plugin.class, BaseFragment.class),
                    new XC_MethodHook(10_000) {
                        @Override
                        public void beforeHookedMethod(MethodHookParam param) {
                            interceptSettingsOpen(param);
                        }
                    });
            if (hook == null) {
                active.set(false);
                FileLog.e(TAG + ": settings hook target was not found");
            }
        } catch (Throwable error) {
            active.set(false);
            removeHook();
            FileLog.e(TAG + ": settings hook installation failed", error);
        }
    }

    private void interceptSettingsOpen(XC_MethodHook.MethodHookParam param) {
        try {
            Object[] args = param == null ? null : param.args;
            if (!active.get() || args == null || args.length != 2
                    || !(args[0] instanceof Plugin)
                    || !(args[1] instanceof BaseFragment)
                    || !PLUGIN_ID.equals(((Plugin) args[0]).getId())) {
                return;
            }
            BaseFragment host = (BaseFragment) args[1];
            if (Looper.myLooper() == Looper.getMainLooper()) {
                if (presentDashboard(host)) param.setResult(null);
            } else {
                AndroidUtilities.runOnUIThread(() -> presentDashboard(host));
                param.setResult(null);
            }
        } catch (Throwable error) {
            FileLog.e(TAG + ": direct settings open failed", error);
        }
    }

    private boolean presentDashboard(BaseFragment host) {
        if (!active.get() || host == null || host.isFinished) return false;
        try {
            ExitFyDashboardFragment dashboard = new ExitFyDashboardFragment();
            dashboard.setCurrentAccount(host.getCurrentAccount());
            if (host.presentFragment(dashboard)) return true;
            FileLog.e(TAG + ": host rejected dashboard fragment");
        } catch (Throwable error) {
            FileLog.e(TAG + ": could not open dashboard", error);
        }
        return false;
    }

    @Override
    public synchronized void close() {
        active.set(false);
        removeHook();
    }

    private void removeHook() {
        XC_MethodHook.Unhook installed = hook;
        hook = null;
        if (installed == null) return;
        try {
            installed.unhook();
        } catch (Throwable error) {
            FileLog.e(TAG + ": settings hook removal failed", error);
        }
    }
}
