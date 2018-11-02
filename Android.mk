LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE = udhcpd

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_SRC_FILES := \
    options.c \
    socket.c \
    packet.c \
    pidfile.c \
    dhcpd.c \
    arpping.c \
    files.c \
    leases.c \
    serverpacket.c \
    stb_3des.c \
    hs_digest.c

LOCAL_CFLAGS := -DVERSION=\"0.9.8\" -D_BSD_SOURCE -std=c99

LOCAL_LDLIBS := -llog

include $(BUILD_EXECUTABLE)
