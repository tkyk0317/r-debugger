.PHONY: all
all:
	@cargo clippy
	@cargo b
	@cd sample && clang++ -g test.cpp main.cpp -o test
	@cd ..

.PHONY: strace
strace: all
	@./target/debug/r-debugger trace ./sample/test

.PHONY: dbg
dbg: all
	@RUST_BACKTRACE=1 ./target/debug/r-debugger dbg ./sample/test

.PHONY: clean
clean:
	@cd sample && rm -rf ./test
	@cargo clean

.PHONY: test
test:
	@cargo test
