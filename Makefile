.PHONY: all golb key_dumper clean

all: golb key_dumper

golb:
	xcrun -sdk iphoneos clang -arch arm64 -Weverything golb.c -o golb -framework IOKit -O2

key_dumper:
	xcrun -sdk iphoneos clang -arch arm64 -arch arm64e -Weverything key_dumper.c -o key_dumper -framework IOKit -O2

clean:
	$(RM) golb key_dumper
