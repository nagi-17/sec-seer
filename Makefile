ifeq ($(BUILD),debug)
CFLAGS := -Wall -Wextra -g -O0 -std=gnu11
else
CFLAGS := -O2 -std=gnu11
endif

CPPFLAGS := -Iinclude -Isrc
LDLIBS   := -lseccomp

BIN := secsee

SRCS := src/main.c \
        include/vector.c \
        include/parson.c \
        src/observer/observer.c \
        src/logger/logger.c \
        src/policy-translator/json-deserializer/json-parser.c \
        src/policy-translator/ctx-generator/ctx-build.c

OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all clean test test-hang

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OBJS) -o $@ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -MMD -MP -c $< -o $@

# Pull in auto-generated header dependencies
-include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) $(BIN)
