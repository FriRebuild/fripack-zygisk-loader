#include "zygisk.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android/dlext.h>

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define LOGD(...)                                                              \
  __android_log_print(ANDROID_LOG_DEBUG, "FriPackInject", __VA_ARGS__)

class FripackInject : public zygisk::ModuleBase {
public:
  void onLoad(Api *api, JNIEnv *env) override {
    this->api = api;
    this->env = env;
  }

  void preAppSpecialize(AppSpecializeArgs *args) override {
    // Use JNI to fetch our process name
    const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
    preSpecialize(process);
    env->ReleaseStringUTFChars(args->nice_name, process);
  }

  void preServerSpecialize(ServerSpecializeArgs *args) override {
    preSpecialize("system_server");
  }

private:
  Api *api;
  JNIEnv *env;
  void *so_data = nullptr;
  size_t so_size = 0;
  bool should_inject = false;

  bool isInScope(const char *process, int modfd) {
    char scope_path[PATH_MAX];
    snprintf(scope_path, sizeof(scope_path), "/proc/self/fd/%d/fripack/scope",
             modfd);
    FILE *fp = fopen(scope_path, "r");
    if (!fp)
      return false;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
      size_t len = strlen(line);
      if (len > 0 && line[len - 1] == '\n')
        line[len - 1] = '\0';
      if (strcmp(line, process) == 0) {
        fclose(fp);
        return true;
      }
    }
    fclose(fp);
    return false;
  }

  void loadSoToMemory(int modfd) {
    char so_path[PATH_MAX];
    snprintf(so_path, sizeof(so_path), "/proc/self/fd/%d/fripack/inject.so",
             modfd);
    LOGD("Loading so from: %s", so_path);
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) {
      LOGD("Failed to open inject.so");
      return;
    }
    struct stat st;
    fstat(fd, &st);
    so_size = st.st_size;
    LOGD("inject.so size: %zu", so_size);
    so_data = malloc(so_size);
    if (!so_data) {
      LOGD("Failed to malloc buffer");
      close(fd);
      return;
    }
    read(fd, so_data, so_size);
    close(fd);
  }

  void injectSo() {
    if (!so_data || so_size == 0) {
      LOGD("No SO data to inject");
      return;
    }

    int memfd = memfd_create("inject", MFD_CLOEXEC);
    if (memfd < 0) {
      LOGD("Failed to create memfd: %s", strerror(errno));
      return;
    }
    if (ftruncate(memfd, so_size) == -1) {
      LOGD("Failed to ftruncate memfd: %s", strerror(errno));
      close(memfd);
      return;
    }
    void *mem = mmap(nullptr, so_size, PROT_WRITE, MAP_SHARED, memfd, 0);
    if (mem == MAP_FAILED) {
      LOGD("Failed to mmap memfd: %s", strerror(errno));
      close(memfd);
      return;
    }
    memcpy(mem, so_data, so_size);
    munmap(mem, so_size);
    void *handle = nullptr;

    // LOGD("Trying android_dlopen_ext with ANDROID_DLEXT_USE_LIBRARY_FD");

    android_dlextinfo extinfo = {};
    extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_FORCE_LOAD;
    extinfo.library_fd = memfd;

    dlerror();
    handle = android_dlopen_ext("libsystemservz.so", RTLD_NOW | RTLD_LOCAL, &extinfo);
    if (handle) {
      LOGD("android_dlopen_ext success");
    } else {
      char *error = dlerror();
      LOGD("android_dlopen_ext failed: %s", error ? error : "unknown error");
    }

    close(memfd);
    free(so_data);
    so_data = nullptr;
    so_size = 0;
  }

  void preSpecialize(const char *process) {
    int modfd = api->getModuleDir();
    if (modfd < 0) {
      LOGD("Failed to get module dir");
      api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
      return;
    }
    if (isInScope(process, modfd)) {
      LOGD("Process %s is in scope, loading so to memory", process);
      should_inject = true;
      loadSoToMemory(modfd);
    } else {
      // LOGD("Process %s not in scope", process);
    }
  }

  void postAppSpecialize(const AppSpecializeArgs *args) override {
    if (should_inject) {
      LOGD("postAppSpecialize: injecting SO");
      injectSo();
    }

    api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
  }
};

// Register our module class
REGISTER_ZYGISK_MODULE(FripackInject)