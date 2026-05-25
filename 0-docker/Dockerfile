ARG LIBOQS_TAG=0.12.0
ARG MSQUIC_TAG=nibanks/openss3.3-test
ARG OQSPROVIDER_TAG=0.8.0
#ARG OPENSSL_TAG=openssl-3.3.1
ARG OPENSSL_TAG=openssl-3.4.2
ARG MAKE_DEFINES="-j 4"     
ARG MSQUIC_DEBUG=off        
ARG LIBOQS_BUILD_DEFINES="-DOQS_DIST_BUILD=ON"
ARG TARGETARCH=amd64
ARG BASEDIR=/opt
ARG INSTALLDIR=${BASEDIR}/oqssa
ARG LIBOQSDIR=${BASEDIR}/liboqs
ARG MSQUICDIR=${BASEDIR}/msquic-pq
ARG OPENSSLDIR=${BASEDIR}/openssl
ARG OQSPROVIDERDIR=${BASEDIR}/oqs-provider
ARG LIBDIR

# --------------------------------------
# Stage 1: Install all necessary tools
# --------------------------------------
FROM ubuntu:24.10 AS base
ENV DEBIAN_FRONTEND=noninteractive

# 1) Escribe sources.list apuntando a old-releases
RUN set -eux; \
  mv /etc/apt/sources.list /etc/apt/sources.list.bak || true; \
  cat > /etc/apt/sources.list <<'EOF'
deb http://old-releases.ubuntu.com/ubuntu oracular main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu oracular-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu oracular-backports main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu oracular-security main restricted universe multiverse
EOF

# 2) Sustituye cualquier entrada residual (.list y .sources), desactiva Valid-Until e instala
RUN set -eux; \
  find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) -print -exec sed -i \
    -e 's|https\?://archive\.ubuntu\.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' \
    -e 's|https\?://security\.ubuntu\.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' \
    -e 's|https\?://ports\.ubuntu\.com/ubuntu-ports|http://old-releases.ubuntu.com/ubuntu|g' {} \; || true; \
  printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid; \
  apt-get update; \
  apt-get install -y --no-install-recommends \
    cmake gcc ninja-build libunwind-dev \
    pkg-config build-essential \
    cargo git wget ca-certificates \
    openssl libssl-dev \
    zlib1g-dev libzstd-dev libbrotli-dev; \
  rm -rf /var/lib/apt/lists/*


# --------------------------------------
# Stage 2: Download all necessary sources
# --------------------------------------
FROM base AS download
ARG BASEDIR
ARG LIBOQS_TAG
ARG MSQUIC_TAG
ARG OPENSSL_TAG
ARG OQSPROVIDER_TAG
ARG OPENSSLDIR

# Download and prepare source files needed for the build process.
WORKDIR $BASEDIR
RUN [ ! -d "${LIBOQSDIR}" ] && \ 
    mkdir liboqs && \  
    git clone --recursive --depth 1 --branch ${LIBOQS_TAG} https://github.com/open-quantum-safe/liboqs.git 
RUN [ ! -d "${MSQUICDIR}" ] && \ 
    mkdir msquic-pq && \
    #git clone --recursive --depth 1 --branch ${MSQUIC_TAG} https://github.com/javibc3/msquic-pq.git
    git clone --recursive --depth 1 --branch ${MSQUIC_TAG} https://github.com/montenegro-montes/msquic-pq.git
RUN [ ! -d "${OPENSSLDIR}" ] && \ 
    mkdir openssl && \
    git clone --depth 1 --branch ${OPENSSL_TAG} https://github.com/openssl/openssl.git

# Modificar límites en speed.c
WORKDIR ${OPENSSLDIR}
RUN sed -i 's/#define MAX_SIG_NUM .*/#define MAX_SIG_NUM 512/' ./apps/speed.c && \
    sed -i 's/#define MAX_KEM_NUM .*/#define MAX_KEM_NUM 512/' ./apps/speed.c

# Patch: add -compress_cert flag to s_server for RFC 8879 certificate compression
WORKDIR ${OPENSSLDIR}
RUN sed -i '/OPT_NO_TX_CERT_COMP,/a\    OPT_COMPRESS_CERT,' apps/s_server.c && \
    sed -i '/{"no_tx_cert_comp", OPT_NO_TX_CERT_COMP, NULL, "Disable sending TLSv1.3 compressed certificates"},/a\    {"compress_cert", OPT_COMPRESS_CERT, NULL, "Enable TLSv1.3 certificate compression (RFC 8879)"},' apps/s_server.c && \
    sed -i '/case OPT_NO_RX_CERT_COMP:/i\        case OPT_COMPRESS_CERT:\n            ctx_options |= SSL_OP_ENABLE_CERT_COMPRESSION;\n            break;' apps/s_server.c


WORKDIR $BASEDIR    
RUN [ ! -d "${OQSPROVIDERDIR}" ] && \ 
    mkdir oqs-provider && \
    git clone --depth 1 --branch ${OQSPROVIDER_TAG} https://github.com/open-quantum-safe/oqs-provider.git 


# --------------------------------------
# Stage 3: Build the tools
# --------------------------------------
FROM download AS build
ARG MAKE_DEFINES     
ARG MSQUIC_DEBUG
ARG LIBOQS_BUILD_DEFINES
ARG INSTALLDIR
ARG LIBOQSDIR
ARG MSQUICDIR
ARG OPENSSLDIR
ARG OQSPROVIDERDIR
ARG LIBDIR

# Build and install liboqs (multi-arch aware)
WORKDIR ${LIBOQSDIR}/build
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      echo "[BUILD] ARM64 detected — disabling x86-specific optimizations"; \
      cmake -G"Ninja" .. ${LIBOQS_BUILD_DEFINES} \
        -DOQS_USE_AVX2_INSTRUCTIONS=OFF \
        -DOQS_USE_AES_INSTRUCTIONS=OFF \
        -DOQS_USE_SHA3_INSTRUCTIONS=OFF; \
    else \
      echo "[BUILD] x86_64 detected — enabling optimizations"; \
      cmake -G"Ninja" .. ${LIBOQS_BUILD_DEFINES}; \
    fi && \
    ninja -j"$(nproc)" && \
    ninja install

FROM build AS build_1
ARG MAKE_DEFINES     
ARG MSQUIC_DEBUG
ARG LIBOQS_BUILD_DEFINES
ARG INSTALLDIR
ARG LIBOQSDIR
ARG MSQUICDIR
ARG OPENSSLDIR
ARG OQSPROVIDERDIR
ARG LIBDIR

# Force cache invalidation for compression rebuild
RUN echo "CACHE_BUST_COMPRESSION_v2" > /tmp/.compression_build

# Install required build tools and system dependencies.
# NOTE: zlib1g-dev, libzstd-dev, libbrotli-dev are REQUIRED for OpenSSL certificate compression (RFC 8879)
# These MUST be installed BEFORE OpenSSL is configured for compression auto-detection to work
RUN apt update && apt install -y --no-install-recommends python3 golang-go python3-pip \
    zlib1g-dev libzstd-dev libbrotli-dev && \ 
    pip install jinja2 tabulate pyyaml --break-system-packages && \
    rm -rf /var/lib/apt/lists/* && \
    ls /usr/include/zlib.h /usr/include/zstd.h /usr/include/brotli/encode.h 


# Build and install MsQuic. We dupplicate the cmake command to ensure the OQS provider is enabled.
WORKDIR ${MSQUICDIR}
RUN mkdir build && cd build && \ 
    cmake -G 'Unix Makefiles' -DQUIC_ENABLE_LOGGING=${MSQUIC_DEBUG} -DQUIC_LOGGING_TYPE=stdout \ 
    -DQUIC_ENABLE_OQS_PROVIDER=on -DQUIC_TLS=openssl3 -DQUIC_BUILD_TOOLS=on .. && \ 
    cmake -G 'Unix Makefiles' -DQUIC_ENABLE_LOGGING=${MSQUIC_DEBUG} -DQUIC_LOGGING_TYPE=stdout \ 
    -DQUIC_ENABLE_OQS_PROVIDER=on -DQUIC_TLS=openssl3 -DQUIC_BUILD_TOOLS=on .. && \
    cmake --build .


# Build OpenSSL3 (multi-arch aware)
WORKDIR ${OPENSSLDIR}
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      echo "[BUILD] ARM64 — using linux-aarch64 target"; \
      LIBDIR=lib; \
      LDFLAGS="-Wl,-rpath -Wl,${INSTALLDIR}/${LIBDIR}" ./Configure shared --prefix=${INSTALLDIR} -I/usr/include linux-aarch64 enable-zlib enable-brotli enable-zstd; \
    else \
      echo "[BUILD] x86_64 — using linux-x86_64 target"; \
      LIBDIR=lib64; \
      LDFLAGS="-Wl,-rpath -Wl,${INSTALLDIR}/${LIBDIR}" ./Configure shared --prefix=${INSTALLDIR} -I/usr/include linux-x86_64 enable-zlib enable-brotli enable-zstd; \
    fi && \
    echo "=== Checking compression detection ===" && \
    grep -i "compress\|zlib\|brotli\|zstd" Makefile 2>/dev/null | head -10 || true && \
    make ${MAKE_DEFINES} && make install_sw install_ssldirs;



# --------------------------------------
# Stage 4: Configure the tools
# --------------------------------------
FROM build_1 AS configure
ARG INSTALLDIR
ARG OQSPROVIDERDIR
ARG LIBOQSDIR

# set path to use 'new' openssl. Dyn libs have been properly linked in to match
ENV PATH="${INSTALLDIR}/bin:${PATH}"

# Configure oqs-provider to activate all algorithms
WORKDIR ${OQSPROVIDERDIR}
RUN sed -i "s/false/true/g" oqs-template/generate.yml && \ 
    LIBOQS_SRC_DIR=${LIBOQSDIR} python3 oqs-template/generate.py

# Build OQS provider and copy it in the right location
WORKDIR ${OQSPROVIDERDIR}
RUN ln -s ../openssl . && \
    cmake -DOPENSSL_ROOT_DIR=${INSTALLDIR} -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=${INSTALLDIR} -S . -B _build && \
    cmake --build _build 

RUN LIBDIR=$(uname -m | grep -q x86_64 && echo "lib64" || echo "lib") && \ 
    cp _build/lib/oqsprovider.so ${INSTALLDIR}/${LIBDIR}/ossl-modules/


# Modify the openssl configuration file to use the OQS provider
RUN sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g" ${INSTALLDIR}/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g" ${INSTALLDIR}/ssl/openssl.cnf && \
    sed -i "s/providers = provider_sect/providers = provider_sect\nssl_conf = ssl_sect\n\n\[ssl_sect\]\nsystem_default = system_default_sect\n\n\[system_default_sect\]\nGroups = \$ENV\:\:DEFAULT_GROUPS\n/g" ${INSTALLDIR}/ssl/openssl.cnf && \ 
    sed -i "s/\# Use this in order to automatically load providers/\# Set default KEM groups if not set via environment variable\nKDEFAULT_GROUPS = $DEFAULT_GROUPS\n\n# Use this in order to automatically load providers/g" ${INSTALLDIR}/ssl/openssl.cnf && \
    sed -i "s/HOME\t\t\t= ./HOME\t\t= .\nDEFAULT_GROUPS\t= ${DEFAULT_GROUPS}/g" ${INSTALLDIR}/ssl/openssl.cnf

# --------------------------------------
# Stage 2: Runtime - Create a lightweight image with essential binaries and configurations.
# --------------------------------------
FROM ubuntu:24.10 AS runtime
ARG INSTALLDIR
ARG MSQUICDIR
ARG OQSPROVIDERDIR

# set path to use 'new' openssl and link it with the OQS provider
ENV PATH="${INSTALLDIR}/bin:${PATH}"
ENV OPENSSL=${INSTALLDIR}/bin/openssl
ENV OPENSSL_CNF=${INSTALLDIR}/ssl/openssl.cnf

# 1) Escribe sources.list apuntando a old-releases
RUN set -eux; \
  mv /etc/apt/sources.list /etc/apt/sources.list.bak || true; \
  cat > /etc/apt/sources.list <<'EOF'
deb http://old-releases.ubuntu.com/ubuntu oracular main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu oracular-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu oracular-backports main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu oracular-security main restricted universe multiverse
EOF

# 2) Sustituye cualquier entrada residual (.list y .sources), desactiva Valid-Until e instala
RUN set -eux; \
  find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) -print -exec sed -i \
    -e 's|https\?://archive\.ubuntu\.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' \
    -e 's|https\?://security\.ubuntu\.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' \
    -e 's|https\?://ports\.ubuntu\.com/ubuntu-ports|http://old-releases.ubuntu.com/ubuntu|g' {} \; || true; \
  printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid; \
  apt-get update; \
  apt-get install -y --no-install-recommends \
    ca-certificates iproute2 tcpdump \
    zlib1g libbrotli1 libzstd1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy necessary files from the build stage
COPY --from=configure ${INSTALLDIR} ${INSTALLDIR}
COPY --from=configure ${MSQUICDIR}/build/bin/Release/ ${INSTALLDIR}/bin/
COPY --from=configure ${OQSPROVIDERDIR}/_build/lib/oqsprovider.so /tmp

# Copy openssl and oqs files in default location just in case
RUN cp $INSTALLDIR/ssl/openssl.cnf $(openssl version -m | cut -d '"' -f2) && \
    LIBDIR=$(uname -m | grep -q x86_64 && echo "lib64" || echo "lib") && \ 
    cp ${INSTALLDIR}/${LIBDIR}/ossl-modules/* $(openssl version -d | cut -d '"' -f2)


# Copy local files into the machine
COPY scripts/*.sh ${INSTALLDIR}/bin/
RUN chmod 755 ${INSTALLDIR}/bin/*.sh

WORKDIR ${INSTALLDIR}/bin

CMD ["/bin/bash"]
