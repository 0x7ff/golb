.PHONY: all aes_ap key_dumper clean

all: aes_ap key_dumper

aes_ap:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb.c aes_ap.c -o aes_ap -framework CoreFoundation -lcompression -O2

key_dumper:
	xcrun -sdk iphoneos clang -arch arm64 -arch arm64e -mios-version-min=10.0 -Weverything key_dumper.c -o key_dumper -framework IOKit -framework CoreFoundation -lcompression -O2

clean:
	$(RM) aes_ap key_dumper
