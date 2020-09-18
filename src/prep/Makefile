NAME = prep

CC = gcc
CXX = g++

CFLAGS = -Wall -I$(INCDIR) -O3 -march=sandybridge -mrdrnd -mrdseed
CXXFLAGS = -std=c++11

LDFLAGS = -lcrypto

INCDIR = ../../sais

SOURCE = prep.cpp
OBJ = prep.o

all: $(NAME)
	@mv $(NAME) ../../

$(NAME): $(OBJ)
	$(CXX) $^ -o $@ $(CFLAGS) $(CXXFLAGS) $(LDFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

%.o: %.cpp
	$(CXX) -c $< -o $@ $(CFLAGS) $(CXXFLAGS)

clean:
	@rm -rfv *.o
	@rm -rfv ../../$(NAME)
