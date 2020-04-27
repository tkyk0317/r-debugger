.PHONY: all
all:
	@cargo b
	@cd sample && clang++ -g main.cpp -o test
	@cd ..

.PHONY: strace
strace: all
	@./target/debug/r-debugger trace ./sample/test

.PHONY: dbg
dbg: all
	@RUST_BACKTRACE=1 ./target/debug/r-debugger dbg ./sample/test

.PHONY: clean
clean:
	@cd sample && rm ./test
	@cargo clean

