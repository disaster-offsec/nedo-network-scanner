CXX = g++
CXXFLAGS = -std=c++17 -pthread -O2 -Wall
TARGET = scanner
OBJS = main.o scanner.o args_handler.o fingerprint.o export.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

rebuild: clean all

.PHONY: all clean rebuild
