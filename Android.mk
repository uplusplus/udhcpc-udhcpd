LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE = udhcpd

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_SRC_FILES := \
    options.c socket.c packet.c pidfile.c \
    dhcpd.c arpping.c files.c leases.c serverpacket.c

LOCAL_CFLAGS := -DVERSION=\"0.9.8\"
    
include $(BUILD_EXECUTABLE)
