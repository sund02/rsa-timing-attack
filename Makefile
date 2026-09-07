# Build a small static lib from src/, then link the apps and the test against it.

CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Iinclude
LDLIBS   := -lgmp

BUILD    := build
LIB      := $(BUILD)/librsatiming.a
LIB_OBJ  := $(BUILD)/rsa.o $(BUILD)/net.o

APPS     := bench server client

all: $(APPS)

# ---- library ----
$(BUILD)/%.o: src/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJ)
	ar rcs $@ $^

# ---- apps ----
bench:  apps/bench.cpp  $(LIB)
	$(CXX) $(CXXFLAGS) $< $(LIB) $(LDLIBS) -o $@
server: apps/server.cpp $(LIB)
	$(CXX) $(CXXFLAGS) $< $(LIB) $(LDLIBS) -o $@
client: apps/client.cpp $(LIB)
	$(CXX) $(CXXFLAGS) $< $(LIB) $(LDLIBS) -o $@

# ---- test ----
test: $(BUILD)/test_rsa
	./$(BUILD)/test_rsa

$(BUILD)/test_rsa: tests/test_rsa.cpp $(LIB) | $(BUILD)
	$(CXX) $(CXXFLAGS) $< $(LIB) $(LDLIBS) -o $@

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD) $(APPS) *.csv *.png

.PHONY: all test clean
