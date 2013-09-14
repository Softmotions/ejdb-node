all:
	- mkdir -p var
	npm build .

clean:
	- $(MAKE) -C ./ejdb clean
	rm -rf ./build ./var/* *.tgz

.PHONY:	 all clean dummy
