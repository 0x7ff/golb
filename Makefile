.PHONY: all
all:
	xcrun -sdk iphoneos clang -arch arm64 -Weverything golb.c -o golb -framework IOKit -O2
	codesign -s - --entitlements tfp0.plist golb

.PHONY: clean
clean:
	$(RM) golb
