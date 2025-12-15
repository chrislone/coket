GPP = g++
DEST = out/openssl
OPENSSLDEST = $(abspath $(lastword $(DEST)))
# .DEFAULT_GOAL := coket

coket: main.cpp llhttp openssl openssl_sw_install
	$(GPP) -static -std=c++11 $< -o $@ -I./out -L./out/llhttp/build -lllhttp -I./out/openssl/include -L./out/openssl/lib64 -lssl -lcrypto

clean:
	rm -rf coket && rm -rf out/*

llhttp:
	cd deps/llhttp && npm install && cd ../.. && cp -r deps/llhttp/build out/llhttp

openssl:
	mkdir -p out/openssl
	cd deps/openssl && ./Configure --prefix=$(OPENSSLDEST)

openssl_sw_install: openssl
	cd deps/openssl && make -j15 build_sw && make -j15 install_sw

.PHONY: clean
