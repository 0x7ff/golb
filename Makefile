.PHONY: all aes_ap aes_ap_ppl coresight coresight_ppl recfg recfg_ppl ryuzaki ryuzaki_ppl clean

all: aes_ap aes_ap_ppl coresight coresight_ppl recfg recfg_ppl ryuzaki ryuzaki_ppl

aes_ap:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb.c aes_ap.c -o aes_ap -framework IOKit -framework CoreFoundation -lcompression -Os

aes_ap_ppl:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb_ppl.c aes_ap.c -o aes_ap_ppl -framework IOKit -framework CoreFoundation -lcompression -Os

coresight:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb.c coresight.c -o coresight -framework IOKit -framework CoreFoundation -lcompression -Os

coresight_ppl:
xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb_ppl.c coresight.c -o coresight_ppl -framework IOKit -framework CoreFoundation -lcompression -Os

recfg:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb.c recfg.c -o recfg -framework IOKit -framework CoreFoundation -lcompression -Os

recfg_ppl:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb_ppl.c recfg.c -o recfg_ppl -framework IOKit -framework CoreFoundation -lcompression -Os

ryuzaki:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb.c ryuzaki.c -o ryuzaki -framework IOKit -framework CoreFoundation -lcompression -Os

ryuzaki_ppl:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything golb_ppl.c ryuzaki.c -o ryuzaki_ppl -framework IOKit -framework CoreFoundation -lcompression -Os

clean:
	$(RM) aes_ap aes_ap_ppl coresight coresight_ppl recfg recfg_ppl ryuzaki ryuzaki_ppl
