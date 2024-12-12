# Determine the operating system
UNAME := $(shell uname)

# Default compiler settings
CC = gcc

# Change compiler based on OS
ifeq ($(UNAME), Darwin)
    CC = clang
endif

# compiler flags:
#  -O3   optimize level at 3
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS = -O3 -Wall -I.
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