LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    src/bt_hidladapter.cpp

# If you add android.hardware.bluetooth@1.0 to LOCAL_SHARED_LIBRARIES,
# revelent header file will be added to LOCAL_C_INCLUDES automatically.

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libutils \
    libhidlbase \
    android.hardware.bluetooth@1.0

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/include

LOCAL_CFLAGS += -Wall -Wextra -Wno-unused-parameter -Werror

LOCAL_MODULE := libsuntecbt_hidladapter
LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)

