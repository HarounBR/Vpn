CC  := gcc
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude
TEST_SRCS := $(wildcard tests/unit/*.c) $(wildcard tests/integration/*.c) tests/test_runner.c
SRC := src/protocol.c src/handshake.c src/session.c
OBJS := $(SRC:.c=.o) $(TEST_SRCS:.c=.o)



vpn_handshake_tests: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ 

test: vpn_handshake_tests
	./vpn_handshake_tests
clean:
	rm -f $(OBJS) vpn_handshake_tests
