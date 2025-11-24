# Determine the operating system
UNAME := $(shell uname)

# Default compiler settings
CC = clang

# compiler flags:
#  -std=c23	comply with C23
#  -O3		optimize level at 3
#  -g		adds debugging information to the executable file
#  -Wall	turns on most, but not all, compiler warnings
#  -Wextra	additional warnings not covered by -Wall
CFLAGS = -std=c23 -O3 -Wall -Wextra -I.

# Change compiler based on OS
ifeq ($(UNAME), Linux)
    CC = gcc
    CFLAGS = -std=c2x -O3 -Wall -Wextra -I.
endif

RM = rm -f

# the build target executable:
TARGET = review_siftr_log
default: $(TARGET)

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c
	
.PHONY: depend clean

clean:
	$(RM) $(TARGET)
