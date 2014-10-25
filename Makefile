#
# Make to Cargo wrappers
#
# So you can issue `make` and project will compile, or `make test` and will compile and issue
#
.PHONY: test build doc
test build doc:
	cargo $@
