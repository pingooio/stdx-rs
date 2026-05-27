# check for all supported targets and target features
.PHONY: check
check:
	RUSTFLAGS="-C target-feature=-avx2,-avx512f" cargo check --target=x86_64-unknown-linux-gnu --all-features
	RUSTFLAGS="-C target-feature=-avx2,-avx512f" cargo check --target=x86_64-unknown-linux-gnu --no-default-features
	RUSTFLAGS="-C target-feature=+avx2,+avx512f" cargo check --target=x86_64-unknown-linux-gnu --all-features
	RUSTFLAGS="-C target-feature=+avx2,+avx512f" cargo check --target=x86_64-unknown-linux-gnu --no-default-features

	cargo check --target=aarch64-unknown-linux-gnu --all-features
	cargo check --target=aarch64-unknown-linux-gnu --no-default-features

	RUSTFLAGS="-C target-feature=-simd128" cargo check --target=wasm32-wasip1
	RUSTFLAGS="-C target-feature=+simd128" cargo check --target=wasm32-wasip1
