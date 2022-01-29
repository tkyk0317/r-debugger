.PHONY: docker-build
docker-build:
	@ docker build -t r-debugger-dev .

.PHONY: build
build: docker-build
	@ docker run \
		--mount type=volume,src=r-debugger-dev,target=/app/target \
		-t \
		--rm \
		r-debugger-dev \
		cargo b

.PHONY: test
test: docker-build
	@ docker run \
		--mount type=volume,src=r-debugger-dev-rust,target=/app/target \
		-t \
		--rm \
		r-debugger-dev \
		cargo t
	
.PHONY: strace
strace: build
	@ docker run \
		--mount type=volume,src=r-debugger-dev-rust,target=/app/target \
		-t \
		--rm \
		r-debugger-dev \
		cargo r -- trace ./sample/test

.PHONY: dbg
dbg: build
	@ docker run \
		--mount type=volume,src=r-debugger-dev-rust,target=/app/target \
		-ti \
		--rm \
		r-debugger-dev \
		bash -c "RUST_BACKTRACE=1 cargo r -- dbg ./sample/test"

.PHONY: clippy
clippy: docker-build
	@ docker run \
		--mount type=volume,src=r-debugger-dev-rust,target=/app/target \
		-t \
		--rm \
		r-debugger-dev \
		cargo clippy
