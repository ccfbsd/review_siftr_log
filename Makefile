# the compiler: gcc for C program, define as g++ for C++
CC = gcc

# compiler flags:
#  -O3   optimize level at 3
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS = -O3 -Wall -I.
RM = rm -f


# the build target executable:
TARGET = review_siftr2_log
default: $(TARGET)

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

.PHONY: depend clean

clean:
	$(RM) $(TARGET)