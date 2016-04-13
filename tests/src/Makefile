TESTS= \
	decode-base64 \
	decode-rc4 \
	decode-single-byte-xor \
	decode-from-global \
	decode-from-heap \
	decode-from-stack \
	decode-in-place \
	decode-global-stackstrings \
	decode-local-stackstrings \
	decode-split-stackstrings \
	decode-to-global \
	decode-to-heap \
	decode-to-output-buf \
	decode-to-stack


clean:
	for test in $(TESTS); do \
		$(MAKE) -C $$test clean; \
	done


all:
	for test in $(TESTS); do \
		$(MAKE) -C $$test all; \
	done
