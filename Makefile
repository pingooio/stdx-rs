.PHONY: fmt
fmt:
	cargo +nightly fmt


.PHONY: clean
clean:
	rm -rf target


.PHONY: update_deps
update_deps:
	cargo update


.PHONY: s3_integration_test
s3_integration_test:
	$(MAKE) -C s3 integration-test
