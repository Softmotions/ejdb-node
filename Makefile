all:
	mkdir -p ./var
	npm build .

clean:
	$(MAKE) -f ./libejdb.mk clean
	rm -rf ./build ./var/* *.tgz

.PHONY:	 all clean dummy
