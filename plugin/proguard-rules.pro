-keep class com.extera.plugins.exitfy.ExitFyBridge {
    public static void configure(java.lang.String);
    public static void load();
    public static void unload();
    public static void updateSettings(java.lang.String);
    public static java.lang.String execute(java.lang.String);
    public static java.lang.String getUiState();
    public static void onAppResume();
}

# Python opens this factory by declared-method reflection. It remains
# package-private so the seven-method public bridge ABI does not expand.
-keepclassmembers class com.extera.plugins.exitfy.ExitFyBridge {
    static org.telegram.ui.ActionBar.BaseFragment createDashboardFragment();
}

-keepclassmembers class * extends de.robv.android.xposed.XC_MethodHook {
    void beforeHookedMethod(de.robv.android.xposed.XC_MethodHook$MethodHookParam);
    void afterHookedMethod(de.robv.android.xposed.XC_MethodHook$MethodHookParam);
}

-keep class com.extera.plugins.exitfy.NativeBridge {
    <methods>;
}

-repackageclasses 'com.extera.plugins.exitfy.o'
-adaptclassstrings
-renamesourcefileattribute SourceFile
# Keep R8 shrinking and name obfuscation, but disable optimizer-wide access
# relaxation/class merging so the reflected bridge ABI stays exact.
-dontoptimize
-keepattributes AnnotationDefault,EnclosingMethod,InnerClasses,RuntimeVisibleAnnotations,RuntimeVisibleParameterAnnotations,RuntimeVisibleTypeAnnotations,Signature

# These are host-only transitive types referenced by the compileOnly
# exteraGram classes jar. The embedded plugin neither defines nor calls them.
-dontwarn com.chaquo.python.**
-dontwarn com.google.firebase.analytics.**
-dontwarn com.google.firebase.crashlytics.**
-dontwarn com.google.gson.**
-dontwarn de.robv.android.xposed.**
-dontwarn org.simplifiles.archive.ArchiveExtractionOptions
-dontwarn org.simplifiles.archive.security.SecurityPolicy
-dontwarn androidx.collection.LongSparseArray
-dontwarn androidx.core.util.Consumer
-dontwarn androidx.core.view.NestedScrollingChild2
-dontwarn androidx.core.view.NestedScrollingChild3
-dontwarn androidx.core.view.NestedScrollingChildHelper
-dontwarn androidx.core.view.ScrollingView
-dontwarn androidx.core.view.WindowInsetsCompat
-dontwarn androidx.dynamicanimation.animation.DynamicAnimation
-dontwarn androidx.dynamicanimation.animation.SpringAnimation
-dontwarn androidx.exifinterface.media.ExifInterface
-dontwarn androidx.viewpager.widget.ViewPager
