all:
	mkdir -p build-ejdb
	cd build-ejdb && cmake -DCMAKE_INSTALL_PREFIX=./libejdb -DCMAKE_BUILD_TYPE=Release  ../ejdb && make install

clean:
	rm -rf ./build-ejdb

.PHONY:	 all clean dummy
