.PHONY: all aes_ap aes_ap_ppl clean

all: aes_ap aes_ap_ppl

aes_ap:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb.c aes_ap.c -o aes_ap -framework IOKit -framework CoreFoundation -lcompression -Os

aes_ap_ppl:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb_ppl.c aes_ap.c -o aes_ap_ppl -framework IOKit -framework CoreFoundation -lcompression -Os

clean:
	$(RM) aes_ap aes_ap_ppl
