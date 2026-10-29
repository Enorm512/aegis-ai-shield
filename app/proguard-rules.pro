# Aegis release shrinking rules.
# The app itself uses no reflection, serialization frameworks or dynamic class loading; apart from the Tesseract rules below,
# no keep rules are required beyond the Android defaults and the manifest-referenced components (kept automatically).
# Keep readable stack traces for crash reports the user chooses to share:
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Tesseract OCR (screenshot check): its native libraries look up Java fields and callbacks by name over JNI,
# and the AAR ships no consumer rules, so its classes must not be renamed or removed.
-keep class com.googlecode.tesseract.android.** { *; }
-keep class com.googlecode.leptonica.android.** { *; }
-keepclasseswithmembernames class * { native <methods>; }
