TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        chacha20-c/chacha20.c \
        serveur.c

LIBS += -lnatpmp -lminiupnpc

HEADERS += \
	chacha20-c/chacha20.h
