# Android Build Instructions

Since this is a Go project, building the Android app requires generating the Go bindings (`.aar`) first.

## Prerequisites

1.  **Go Mobile**:
    ```bash
    go install golang.org/x/mobile/cmd/gomobile@latest
    gomobile init
    ```
2.  **Android Studio & NDK**: Ensure you have Android SDK and NDK installed.

## Build Steps

### 1. Generate Go Bindings (`.aar`)

Run the following command in the project root (`w33d-tunnel/`):

```bash
# Create libs directory
mkdir -p android/app/libs

# Generate .aar
# This compiles the 'mobile' package and its dependencies into a native library
gomobile bind -o android/app/libs/mobile.aar -target=android ./mobile
```

### 2. Build APK

Open the `android/` directory in **Android Studio**.

*   Sync Gradle.
*   Build > Build Bundle(s) / APK(s) > Build APK(s).
*   Run on Emulator or Device.

## How it works

*   The Go code in `mobile/mobile.go` exports a `MobileClient` class.
*   `gomobile bind` generates Java bindings for this class.
*   The Android App (`MainActivity.kt`) calls `Mobile.newMobileClient()` and `client.start(jsonConfig)`.
*   The Go runtime starts a SOCKS5 server on `127.0.0.1:1080` inside the app process.
*   **Note**: This version only starts a local SOCKS5 proxy. To intercept all traffic, you would need to implement `VpnService` and route traffic to this SOCKS5 port (e.g., using `tun2socks` logic).
