# Aegis release shrinking rules.
# Nothing in the app uses reflection, serialization frameworks or dynamic class loading, so no keep rules are
# required beyond the Android defaults and the manifest-referenced components (kept automatically).
# Keep readable stack traces for crash reports the user chooses to share:
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
