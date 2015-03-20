
check: | var
#	-- make -C ./ejdb/tcejdb check-ejdb
	nodeunit ./tests

var: ;mkdir -p var

.PHONY: check check-all
