# === Percorsi OpenSSL ===
OPENSSL_INC   = /opt/homebrew/opt/openssl@3/include
OPENSSL_LIB   = /opt/homebrew/opt/openssl@3/lib

# === Directory progetto ===
SRC           = src
OBJ           = obj
BIN           = bin
INCLUDE_LOCAL = include

# === Compiler & linker ===
CXX      = g++
CXXFLAGS = -std=c++17 -Wall -I$(OPENSSL_INC) -I$(INCLUDE_LOCAL)
LDFLAGS  = -L$(OPENSSL_LIB) -lssl -lcrypto

# === File oggetto ===
SERVER_OBJS = \
    $(OBJ)/main.o \
    $(OBJ)/dss_server.o \
    $(OBJ)/secure_channel.o \
    $(OBJ)/utility.o \
    $(OBJ)/user.o

CLIENT_OBJS = \
    $(OBJ)/main_client.o \
    $(OBJ)/secure_channel.o \
    $(OBJ)/utility.o \
    $(OBJ)/user.o

# === Targets di default ===
all: dirs server client

# crea le directory necessarie
dirs:
	mkdir -p $(OBJ) $(BIN)

# --- Regole di compilazione .cpp → .o ---
$(OBJ)/main.o: $(SRC)/main.cpp $(INCLUDE_LOCAL)/dss_server.h $(INCLUDE_LOCAL)/secure_channel.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ)/dss_server.o: $(SRC)/dss_server.cpp $(INCLUDE_LOCAL)/dss_server.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ)/secure_channel.o: $(SRC)/secure_channel.cpp $(INCLUDE_LOCAL)/secure_channel.h $(INCLUDE_LOCAL)/utility.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ)/utility.o: $(SRC)/utility.cpp $(INCLUDE_LOCAL)/utility.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ)/user.o: $(SRC)/user.cpp $(INCLUDE_LOCAL)/user.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ)/main_client.o: $(SRC)/main_client.cpp $(INCLUDE_LOCAL)/secure_channel.h $(INCLUDE_LOCAL)/utility.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# --- Link eseguibili ---
server: $(SERVER_OBJS)
	$(CXX) $^ -o $(BIN)/server $(LDFLAGS)

client: $(CLIENT_OBJS)
	$(CXX) $^ -o $(BIN)/client $(LDFLAGS)

# --- Pulizia ---
clean:
	rm -rf $(OBJ)/*.o $(BIN)/server $(BIN)/client

.PHONY: all dirs clean server client
