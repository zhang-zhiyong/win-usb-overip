all:
	aarch64-rockchip-linux-gnu-cc  usbredirapi.c -fPIC -g -shared -o libusbredirapi.so
	aarch64-rockchip-linux-gnu-cc   usbredirapi_test.c -g  -L. -lusbredirapi -o usbredirapi_test
clean:
	rm -rf libusbredirapi.so usbredirapi_test
