FROM node:22-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
    PATH=/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/build-tools/36.1.0:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Docker CLI is needed by the trusted worker to launch isolated build containers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates curl docker.io git \
       openjdk-17-jdk-headless unzip zip \
    && rm -rf /var/lib/apt/lists/*

# Install Android SDK command-line tools and required Android 36 packages.
RUN mkdir -p "${ANDROID_HOME}/cmdline-tools" /tmp/android-cmdline-tools \
    && curl -fsSL \
       https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip \
       -o /tmp/android-commandline-tools.zip \
    && unzip -q /tmp/android-commandline-tools.zip -d /tmp/android-cmdline-tools \
    && mv /tmp/android-cmdline-tools/cmdline-tools "${ANDROID_HOME}/cmdline-tools/latest" \
    && rm -rf /tmp/android-commandline-tools /tmp/android-commandline-tools.zip \
    && yes | sdkmanager --sdk_root="${ANDROID_HOME}" --licenses >/dev/null \
    && sdkmanager --sdk_root="${ANDROID_HOME}" \
       "platform-tools" \
       "platforms;android-36" \
       "build-tools;36.1.0" \
    && chmod -R a+rX "${ANDROID_HOME}"

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src
RUN npm run build \
    && npm prune --omit=dev

# The trusted worker needs Docker socket access. Run it only on a dedicated,
# controlled Linux host; access to the host Docker socket is highly privileged.
CMD ["node", "dist/worker.js"]
