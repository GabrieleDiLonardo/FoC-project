# === Percorsi OpenSSL ===
OPENSSL_INC = /opt/homebrew/opt/openssl@3/include
OPENSSL_LIB = /opt/homebrew/opt/openssl@3/lib

# === Directory progetto ===
SRC  = src
OBJ  = obj
BIN  = bin
INCLUDE_LOCAL = include

# === Compiler & linker ===
CXX = g++
CXXFLAGS = -std=c++17 -Wall -I$(OPENSSL_INC) -I$(INCLUDE_LOCAL)
LDFLAGS = -L$(OPENSSL_LIB) -lssl -lcrypto

# === File oggetto ===
SERVER_OBJS = $(OBJ)/main.o $(OBJ)/dss_server.o $(OBJ)/utility.o $(OBJ)/user.o
CLIENT_OBJS = $(OBJ)/main_client.o $(OBJ)/utility.o $(OBJ)/user.o
OFFLINE_OBJS = $(OBJ)/offline_reg.o $(OBJ)/user.o $(OBJ)/utility.o

# === Targets ===
all: dirs server client offline_reg secure_test

dirs:
	mkdir -p $(OBJ) $(BIN) keys

# === Compilazione Server ===
$(OBJ)/main.o: $(SRC)/main.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ)/dss_server.o: $(SRC)/dss_server.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# === Compilazione Client ===
$(OBJ)/main_client.o: $(SRC)/main_client.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# === Compilazione registrazione offline ===
$(OBJ)/offline_reg.o: $(SRC)/offline_reg.cpp $(INCLUDE_LOCAL)/user.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# === Compilazione secure_test ===
$(OBJ)/secure_test.o: $(SRC)/secure_test.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# === Compilazione utility ===
$(OBJ)/utility.o: $(SRC)/utility.cpp $(INCLUDE_LOCAL)/utility.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ)/user.o: $(SRC)/user.cpp $(INCLUDE_LOCAL)/user.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# === Link finali ===
server: $(SERVER_OBJS)
	$(CXX) $^ -o $(BIN)/server $(LDFLAGS)

client: $(CLIENT_OBJS)
	$(CXX) $^ -o $(BIN)/client $(LDFLAGS)

offline_reg: $(OFFLINE_OBJS)
	$(CXX) $^ -o $(BIN)/offline_reg $(LDFLAGS)

clean:
	rm -rf $(OBJ)/*.o $(BIN)/server $(BIN)/client $(BIN)/offline_reg $(BIN)/secure_test

.PHONY: all dirs clean server client offline_reg secure_test