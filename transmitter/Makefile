# Makefile

# Define the compiler
CC = gcc

# Define the source files
SRCS = main.c

CFLAGS = -luring -g

LDFLAGS = -luring -g

# Define the output executable name
TARGET = transmitter

# Define the object files
OBJS = $(SRCS:.c=.o)

# The default target, 'all', to build the program
all: $(TARGET)

# Rule to build the target executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)

# Rule to compile the source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to clean up the build files
clean:
	rm -f $(OBJS) $(TARGET)

# Rule to show help
help:
	@echo "Makefile targets:"
	@echo "  all       - Compile the program (default target)"
	@echo "  clean     - Remove compiled files"
	@echo "  help      - Show this help message"
