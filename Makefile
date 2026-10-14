demo:
	./demo/run.sh
noamx:
	./deploy/noamx/build.sh
test: noamx
	cargo test --workspace
.PHONY: demo test noamx
