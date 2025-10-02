.PHONY: fmt
fmt:
	cargo +nightly fmt


.PHONY: clean
clean:
	rm -rf target


.PHONY: update_deps
update_deps:
	cargo update
