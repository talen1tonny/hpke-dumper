TARGET := iphone:clang:latest:14.0
ARCHS  := arm64 arm64e

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libhpkedumper
libhpkedumper_FILES      = Tweak.m
libhpkedumper_CFLAGS     = -fobjc-arc -Wno-unused-variable -Wno-unused-function
libhpkedumper_FRAMEWORKS = Foundation
libhpkedumper_LIBRARIES  = objc

include $(THEOS_MAKE_PATH)/library.mk
