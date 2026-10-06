CXX      ?= g++
CXXFLAGS ?= -O3 -march=native -std=c++17 -Wall -pthread

keyrecovery: keyrecovery.cpp twinkle.cpp twinkle.hpp conditions.hpp
	$(CXX) $(CXXFLAGS) -o $@ keyrecovery.cpp twinkle.cpp

clean:
	rm -f keyrecovery

.PHONY: clean
