TESTS= \
    decode-base64 \
	decode-from-global \
	decode-from-heap \
	decode-from-stack \
	decode-global-stackstrings \
	decode-in-place \
	decode-local-stackstrings \
	decode-single-byte-xor \
	decode-split-stackstrings \
	decode-to-global \
	decode-to-heap \
	decode-to-output-buf \
	decode-to-stack \
	decode-string-from-index


clean:
	for test in $(TESTS); do \
		$(MAKE) -C $$test clean; \
	done


all:
	for test in $(TESTS); do \
		$(MAKE) -C $$test all; \
	done
