include ../Makefile.kernel

.PHONY: userp
userp:
	make clean && \
	make -j && \
	cd ./build && \
	make check 2>&1 | tee build_log.txt