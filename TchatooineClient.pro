TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        chacha20-c/chacha20.c \
        client.c

DISTFILES += \
    cle.crypt \
    nonce.crypt
