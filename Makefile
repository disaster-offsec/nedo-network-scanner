CXX = g++
CXXFLAGS = -std=c++17 -pthread -O2
TARGET = scanner
OBJS = main.o scanner.o args_handler.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
