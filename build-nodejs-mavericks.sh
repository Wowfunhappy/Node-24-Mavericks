#!/bin/bash
set -e

# Before running this, you must modify the macports-libcxx port to use llvm 18 instead of llvm 11, then install it.

# Configuration
NODE_VERSION="24.6.0"
SOURCE_DIR="node-v${NODE_VERSION}"
BUILD_DIR="${SOURCE_DIR}-build"
INSTALL_PREFIX="/usr/local"
JOBS=$(sysctl -n hw.ncpu)

# Clean and prepare build directory
#rm -rf "$BUILD_DIR"
if [ ! -d "$SOURCE_DIR" ]; then
    if [ ! -f "node-v${NODE_VERSION}.tar.gz" ]; then
        echo "Downloading Node.js ${NODE_VERSION}..."
        curl -LO "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}.tar.gz"
    fi
    echo "Extracting source..."
    tar -xzf "node-v${NODE_VERSION}.tar.gz"
fi

cp -R "$SOURCE_DIR" "$BUILD_DIR"
cd "$BUILD_DIR"

echo "Patching common.gypi for macOS 10.9..."
if [ -f "common.gypi" ]; then
    sed -i '' "s|'MACOSX_DEPLOYMENT_TARGET': '[0-9.]*'|'MACOSX_DEPLOYMENT_TARGET': '10.9'|g" common.gypi
    sed -i '' 's|-mmacosx-version-min=[0-9.]*|-mmacosx-version-min=10.9|g' common.gypi
fi


mkdir -p deps/mavericks-compat

cat > deps/mavericks-compat/polyfills.h << 'EOF'
#ifndef MAVERICKS_POLYFILLS_H
#define MAVERICKS_POLYFILLS_H

#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __CLANG_MAX_ALIGN_T_DEFINED
#define __CLANG_MAX_ALIGN_T_DEFINED
typedef struct {
  long long __max_align_ll __attribute__((__aligned__(__alignof__(long long))));
  long double __max_align_ld __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
#endif

#ifndef QOS_CLASS_USER_INTERACTIVE
#define QOS_CLASS_USER_INTERACTIVE  0x21
#endif
#ifndef QOS_CLASS_USER_INITIATED
#define QOS_CLASS_USER_INITIATED    0x19
#endif
#ifndef QOS_CLASS_DEFAULT
#define QOS_CLASS_DEFAULT           0x15
#endif
#ifndef QOS_CLASS_UTILITY
#define QOS_CLASS_UTILITY           0x11
#endif
#ifndef QOS_CLASS_BACKGROUND
#define QOS_CLASS_BACKGROUND        0x09
#endif
#ifndef QOS_CLASS_UNSPECIFIED
#define QOS_CLASS_UNSPECIFIED       0x00
#endif

#ifdef __APPLE__
#if !__has_include(<os/signpost.h>)
typedef struct os_log_s *os_log_t;
typedef struct os_signpost_id_s {
    uint64_t _id;
} os_signpost_id_t;
#define OS_LOG_DISABLED ((os_log_t)0)
#define OS_SIGNPOST_ID_INVALID ((os_signpost_id_t){0})
#define OS_SIGNPOST_ID_EXCLUSIVE ((os_signpost_id_t){0xEEEEB0B5B2B2EEEE})
#define os_signpost_enabled(log) (0)
#define os_signpost_interval_begin(log, id, name, ...) do {} while(0)
#define os_signpost_interval_end(log, id, name, ...) do {} while(0)

os_signpost_id_t os_signpost_id_generate(os_log_t log);
os_signpost_id_t os_signpost_id_make_with_pointer(os_log_t log, const void *ptr);
#endif
#endif

int pthread_set_qos_class_self_np(int qos_class, int relative_priority);

#ifndef MMSGHDR_DEFINED
#define MMSGHDR_DEFINED
struct mmsghdr {
    struct msghdr msg_hdr;
    size_t msg_len;
};
#endif

ssize_t recvmsg_x(int s, const struct mmsghdr* msgp, u_int cnt, int flags);
ssize_t sendmsg_x(int s, const struct mmsghdr* msgp, u_int cnt, int flags);

#ifdef __APPLE__
#include <stdbool.h>
// Only declare if not already defined by Security framework
#ifndef _SECURITY_SECTRUST_H_
typedef struct __SecTrust *SecTrustRef;
#endif
#ifndef __COREFOUNDATION_CFERROR__
typedef struct __CFError *CFErrorRef;  
#endif
bool SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error);
#endif

#ifdef __cplusplus
}
#endif

#endif // MAVERICKS_POLYFILLS_H
EOF

cat > deps/mavericks-compat/polyfills.c << 'EOF'
#include "polyfills.h"
#include <sys/socket.h>
#include <errno.h>

#ifdef __APPLE__
int pthread_set_qos_class_self_np(int qos_class, int relative_priority) {
  (void)qos_class;
  (void)relative_priority;
  return 0;
}

ssize_t recvmsg_x(int s, const struct mmsghdr* msgp, u_int cnt, int flags) {
  ssize_t total = 0;
  u_int i;
  
  for (i = 0; i < cnt; i++) {
    ssize_t ret = recvmsg(s, (struct msghdr*)&msgp[i].msg_hdr, flags | MSG_DONTWAIT);
    if (ret < 0) {
      if (i == 0) return ret;
      break;
    }
    ((struct mmsghdr*)msgp)[i].msg_len = ret;
    total++;
    if (ret == 0) break;
  }
  
  return total > 0 ? total : -1;
}

ssize_t sendmsg_x(int s, const struct mmsghdr* msgp, u_int cnt, int flags) {
  ssize_t total = 0;
  u_int i;
  
  for (i = 0; i < cnt; i++) {
    ssize_t ret = sendmsg(s, (struct msghdr*)&msgp[i].msg_hdr, flags | MSG_DONTWAIT);
    if (ret < 0) {
      if (i == 0) return ret;
      break;
    }
    ((struct mmsghdr*)msgp)[i].msg_len = ret;
    total++;
  }
  
  return total > 0 ? total : -1;
}

os_signpost_id_t os_signpost_id_generate(os_log_t log) {
    (void)log;
    return OS_SIGNPOST_ID_INVALID;
}

os_signpost_id_t os_signpost_id_make_with_pointer(os_log_t log, const void *ptr) {
    (void)log;
    (void)ptr;
    return OS_SIGNPOST_ID_INVALID;
}

//https://trac.macports.org/ticket/66749#comment:2
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

CFStringRef getStringForResultType(SecTrustResultType resultType) {
    switch (resultType) {
        case kSecTrustResultInvalid: return CFSTR("Error evaluating certificate");
        case kSecTrustResultDeny: return CFSTR("User specified to deny trust");
        case kSecTrustResultUnspecified: return CFSTR("Rejected Certificate");
        case kSecTrustResultRecoverableTrustFailure: return CFSTR("Rejected Certificate");
        case kSecTrustResultFatalTrustFailure: return CFSTR("Bad Certificate");
        case kSecTrustResultOtherError: return CFSTR("Error evaluating certificate");
        case kSecTrustResultProceed: return CFSTR("Proceed");
        default: return CFSTR("Unknown");
    }
}

bool SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    SecTrustResultType trustResult = kSecTrustResultInvalid;
    OSStatus status = SecTrustEvaluate(trust, &trustResult);
    if (status == errSecSuccess && (trustResult == kSecTrustResultProceed || trustResult == kSecTrustResultUnspecified)) {
        if (error) {
            *error = NULL;
        }
        return true;
    }
    if (error)
        *error = CFErrorCreate(kCFAllocatorDefault, getStringForResultType(trustResult), 0, NULL);
    return false;
}

#endif // __APPLE__
EOF

cat > mavericks.patch << 'EOF'
--- a/deps/v8/src/base/platform/platform-posix.cc
+++ b/deps/v8/src/base/platform/platform-posix.cc
@@ -10,6 +10,9 @@
 #include <limits.h>
 #include <pthread.h>
 
+#ifdef __APPLE__
+#include <AvailabilityMacros.h>
+#endif
 #include "src/base/logging.h"
 #if defined(__DragonFly__) || defined(__FreeBSD__) || defined(__OpenBSD__)
 #include <pthread_np.h>  // for pthread_set_name_np
--- a/deps/uv/src/unix/darwin.c
+++ b/deps/uv/src/unix/darwin.c
@@ -20,6 +20,7 @@
 
 #include "uv.h"
 #include "internal.h"
+#include <AvailabilityMacros.h>
 
 #include <dlfcn.h>
 #include <mach/mach.h>
--- a/deps/uv/src/unix/fs.c
+++ b/deps/uv/src/unix/fs.c
@@ -71,6 +71,10 @@
 # include <sys/statfs.h>
 #endif
 
+#if defined(__APPLE__)
+#include <AvailabilityMacros.h>
+#endif
+
 #if defined(_AIX) && _XOPEN_SOURCE <= 600
 extern char *mkdtemp(char *template);
 #endif
EOF

patch -p1 < mavericks.patch 2>/dev/null

cat > v8-signpost.patch << 'EOF'
--- a/deps/v8/src/libplatform/tracing/recorder.h
+++ b/deps/v8/src/libplatform/tracing/recorder.h
@@ -10,7 +10,7 @@
 #include "include/libplatform/v8-tracing.h"
 
 #if V8_OS_DARWIN
-#include <os/signpost.h>
+// #include <os/signpost.h> // Not available on macOS 10.9
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wunguarded-availability"
 #endif
--- a/tools/v8_gypfiles/features.gypi
+++ b/tools/v8_gypfiles/features.gypi
@@ -65,7 +65,7 @@
     
       ['OS == "win" or OS == "mac"', {
         # Sets -DENABLE_SYSTEM_INSTRUMENTATION. Enables OS-dependent event tracing
-        'v8_enable_system_instrumentation': 1,
+        'v8_enable_system_instrumentation': 0,
       }, {
         'v8_enable_system_instrumentation': 0,
       }],
EOF

patch -p1 < v8-signpost.patch 2>/dev/null

# Fix safepoint.h - replace pthread_override_t with void*
sed -i '' 's/pthread_override_t qos_override;/void* qos_override; \/\/ pthread_override not available on 10.9/' deps/v8/src/heap/safepoint.h

# Fix safepoint.cc - replace pthread_override_t with void*
sed -i '' 's/pthread_override_t qos_override = nullptr;/void* qos_override = nullptr;/' deps/v8/src/heap/safepoint.cc

# Delete the qos_override assignment and CHECK_NOT_NULL lines
sed -i '' '/qos_override = pthread_override_qos_class_start_np/,/CHECK_NOT_NULL(qos_override);/d' deps/v8/src/heap/safepoint.cc

# Remove the CHECK_EQ line that calls pthread_override_qos_class_end_np (multi-line)
# This is a 3-line statement starting with CHECK_EQ and containing pthread_override_qos_class_end_np
sed -i '' '/CHECK_EQ($/{N;N;/pthread_override_qos_class_end_np/d;}' deps/v8/src/heap/safepoint.cc

# Set up environment for macports-libcxx with clang-18
export CXX="/opt/local/bin/clang++-mp-18"
export CC="/opt/local/bin/clang-mp-18"

COMPAT_HEADER_PATH="${PWD}/deps/mavericks-compat/polyfills.h"

# C++ flags - using macports-libcxx for C++20
# Use -nostdinc++ to exclude system C++ headers
# Include LegacySupport first for missing POSIX functions, then libc++ headers
# Let C headers resolve normally after this
export CXXFLAGS="\
-std=c++20 \
-include ${COMPAT_HEADER_PATH} \
-isystem /opt/local/include/LegacySupport \
-nostdinc++ \
-isystem /opt/local/libexec/llvm-18/include/c++/v1 \
-mmacosx-version-min=10.9 \
-DMAC_OS_X_VERSION_MIN_REQUIRED=1090 \
-D_LIBCPP_DISABLE_AVAILABILITY \
-faligned-allocation \
-fno-aligned-new"

# C flags - include legacy-support
export CFLAGS="\
-I/opt/local/include/LegacySupport \
-mmacosx-version-min=10.9 \
-DMAC_OS_X_VERSION_MIN_REQUIRED=1090"

# Linker flags - static link with MacPorts libc++ and legacy-support
export LDFLAGS="\
-nostdlib++ \
-mmacosx-version-min=10.9 \
-L/opt/local/lib \
/opt/local/libexec/llvm-18/lib/libc++/libc++.a \
/opt/local/libexec/llvm-18/lib/libc++/libc++abi.a \
/opt/local/lib/libMacportsLegacySupport.a \
-lSystem"

# CPPFLAGS should not include LegacySupport path to avoid it being added to C++ compilation
export CPPFLAGS="\
-mmacosx-version-min=10.9 \
-DMAC_OS_X_VERSION_MIN_REQUIRED=1090"

# Compile the polyfills.c file to an object file
echo "Compiling Mavericks compatibility polyfills..."
POLYFILLS_OBJ="${PWD}/deps/mavericks-compat/polyfills.o"
${CC} ${CFLAGS} -c deps/mavericks-compat/polyfills.c -o ${POLYFILLS_OBJ}

# Update LDFLAGS to include the polyfills object and Security/CoreFoundation frameworks
export LDFLAGS="${LDFLAGS} ${POLYFILLS_OBJ} -framework Security -framework CoreFoundation"
 
echo "Configuring Node.js..."

CC="${CC}" \
CXX="${CXX}" \
CFLAGS="${CFLAGS}" \
CXXFLAGS="${CXXFLAGS}" \
LDFLAGS="${LDFLAGS}" \
CPPFLAGS="${CPPFLAGS}" \
MACOSX_DEPLOYMENT_TARGET=10.9 \
    /opt/local/bin/python3 ./configure \
    --prefix="${INSTALL_PREFIX}" \
    --with-intl=full-icu \
    --download=all \
    --fully-static \
    --enable-static

echo "Building Node.js with ${JOBS} parallel jobs..."

CC="${CC}" \
CXX="${CXX}" \
CFLAGS="${CFLAGS}" \
CXXFLAGS="${CXXFLAGS}" \
LDFLAGS="${LDFLAGS}" \
CPPFLAGS="${CPPFLAGS}" \
MACOSX_DEPLOYMENT_TARGET=10.9 \
    make -j${JOBS} V=1

echo "Build complete!"

echo "Testing binary..."
./out/Release/node --version
./out/Release/node -e "console.log('Hello from Node.js ' + process.version + ' on Mavericks!');"





# Create a package, following the same process as the original `make pkg` command.
# As of this writing, this part of the script is technically untested, because I don't want to do another full rebuild of Node.
# The same commands worked individually, I just haven't run the full process.

echo "Creating package..."

FULLVERSION="${NODE_VERSION}"  # or dynamically get from built node
TARNAME="node-v${NODE_VERSION}-darwin-x64"
NPM_VERSION="v$(cat deps/npm/package.json | grep '^  "version"' | sed 's/^[^:]*: "\([^"]*\)",.*/\1/')"
PKG="${TARNAME}.pkg"
MACOSOUTDIR="out/macos"
NODE="./out/Release/node"
PYTHON="/opt/local/bin/python3"
V=0  # Verbosity level

# Step 1: Clean and prepare output directory
rm -rf "${MACOSOUTDIR}"
mkdir -p "${MACOSOUTDIR}/installer/productbuild"

# Step 2: Process distribution.xml template (exact from Makefile)
cat tools/macos-installer/productbuild/distribution.xml.tmpl  \
    | sed -E "s/\\{nodeversion\\}/${FULLVERSION}/g" \
    | sed -E "s/\\{npmversion\\}/${NPM_VERSION}/g" \
    >"${MACOSOUTDIR}/installer/productbuild/distribution.xml"

# Step 3: Process HTML templates for each language (exact from Makefile)
for dirname in tools/macos-installer/productbuild/Resources/*/; do
    lang=$(basename "$dirname")
    mkdir -p "${MACOSOUTDIR}/installer/productbuild/Resources/${lang}"
    printf "Found localization directory %s\n" "$dirname"

    cat "${dirname}/welcome.html.tmpl" \
        | sed -E "s/\\{nodeversion\\}/${FULLVERSION}/g" \
        | sed -E "s/\\{npmversion\\}/${NPM_VERSION}/g" \
        >"${MACOSOUTDIR}/installer/productbuild/Resources/${lang}/welcome.html"

    cat "${dirname}/conclusion.html.tmpl" \
        | sed -E "s/\\{nodeversion\\}/${FULLVERSION}/g" \
        | sed -E "s/\\{npmversion\\}/${NPM_VERSION}/g" \
        >"${MACOSOUTDIR}/installer/productbuild/Resources/${lang}/conclusion.html"
done

# Step 4: Install to staging directory (replaces the rebuild in original)
# Create the installation directory structure
DESTDIR="${MACOSOUTDIR}/dist/node"
mkdir -p "${DESTDIR}/usr/local/bin"
mkdir -p "${DESTDIR}/usr/local/lib/node_modules"
mkdir -p "${DESTDIR}/usr/local/share/man/man1"
mkdir -p "${DESTDIR}/usr/local/include/node"
# Copy the node binary
echo "  Copying node binary..."
cp out/Release/node "${DESTDIR}/usr/local/bin/node"
chmod 755 "${DESTDIR}/usr/local/bin/node"
# Copy npm
echo "  Copying npm..."
cp -R deps/npm "${DESTDIR}/usr/local/lib/node_modules/npm"
# Create npm and npx symlinks
echo "  Creating npm/npx symlinks..."
ln -sf ../lib/node_modules/npm/bin/npm-cli.js "${DESTDIR}/usr/local/bin/npm"
ln -sf ../lib/node_modules/npm/bin/npx-cli.js "${DESTDIR}/usr/local/bin/npx"
# Copy man page if it exists
if [ -f "doc/node.1" ]; then
    echo "  Copying man page..."
    cp doc/node.1 "${DESTDIR}/usr/local/share/man/man1/"
fi
# Copy headers for native addons
if [ -d "src" ]; then
    echo "  Copying headers..."
    # Copy Node.js headers
    find src -name "*.h" | while read -r file; do
        dest="${DESTDIR}/usr/local/include/node/$file"
        mkdir -p "$(dirname "$dest")"
        cp "$file" "$dest"
    done
    # Copy V8 headers
    if [ -d "deps/v8/include" ]; then
        cp -R deps/v8/include/* "${DESTDIR}/usr/local/include/node/" 2>/dev/null || true
    fi
    # Copy libuv headers
    if [ -d "deps/uv/include" ]; then
        cp -R deps/uv/include/* "${DESTDIR}/usr/local/include/node/" 2>/dev/null || true
    fi
fi

# Step 5: Prepare npm package structure
mkdir -p "${MACOSOUTDIR}/dist/npm/usr/local/lib/node_modules"
mkdir -p "${MACOSOUTDIR}/pkgs"
# Move npm to separate package root
mv "${MACOSOUTDIR}/dist/node/usr/local/lib/node_modules/npm" \
   "${MACOSOUTDIR}/dist/npm/usr/local/lib/node_modules"
# Remove npm/npx symlinks from node package
unlink "${MACOSOUTDIR}/dist/node/usr/local/bin/npm" 2>/dev/null || true
unlink "${MACOSOUTDIR}/dist/node/usr/local/bin/npx" 2>/dev/null || true

# Step 6: Generate license RTF
"${NODE}" tools/license2rtf.mjs < LICENSE > \
    "${MACOSOUTDIR}/installer/productbuild/Resources/license.rtf"

# Step 7: Copy logo
cp doc/osx_installer_logo.png "${MACOSOUTDIR}/installer/productbuild/Resources"

# Step 8: Build node package (exact from Makefile)
pkgbuild --version "${FULLVERSION}" \
    --identifier org.nodejs.node.pkg \
    --root "${MACOSOUTDIR}/dist/node" \
    "${MACOSOUTDIR}/pkgs/node-${FULLVERSION}.pkg"

# Step 9: Build npm package (exact from Makefile)
pkgbuild --version "${NPM_VERSION}" \
    --identifier org.nodejs.npm.pkg \
    --root "${MACOSOUTDIR}/dist/npm" \
    --scripts ./tools/macos-installer/pkgbuild/npm/scripts \
    "${MACOSOUTDIR}/pkgs/npm-${NPM_VERSION}.pkg"

# Step 10: Build final product (exact from Makefile)
productbuild --distribution "${MACOSOUTDIR}/installer/productbuild/distribution.xml" \
    --resources "${MACOSOUTDIR}/installer/productbuild/Resources" \
    --package-path "${MACOSOUTDIR}/pkgs" \
    "./${PKG}"
