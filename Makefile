.PHONY: all aes_ap coresight recfg ryuzaki clean

all: aes_ap coresight recfg ryuzaki

aes_ap:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb.c aes_ap.c -o aes_ap -framework IOKit -framework CoreFoundation -lcompression -Os

coresight:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb.c coresight.c -o coresight -framework IOKit -framework CoreFoundation -lcompression -Os

recfg:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb.c recfg.c -o recfg -framework IOKit -framework CoreFoundation -lcompression -Os

ryuzaki:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb.c ryuzaki.c -o ryuzaki -framework IOKit -framework CoreFoundation -lcompression -Os

clean:
	$(RM) aes_ap coresight recfg ryuzaki
