BINARY = sinkhole
CARGO_BIN = ./target/release/$(BINARY)
INTERFACE = wlp8s0
WEB = atun.com
WEBSHARED = ledvance.ewyse.agency
FILE = webs.txt
SOCKET = /tmp/sinkhole.sock

all: $(CARGO_BIN)

$(CARGO_BIN): src/main.rs
	@cargo build --release

start: all
	@sudo $(CARGO_BIN) $(INTERFACE) 

add:
	@echo "add $(WEB)" | sudo socat - UNIX-CONNECT:$(SOCKET)

add-shared:
	@echo "add $(WEBSHARED)" | sudo socat - UNIX-CONNECT:$(SOCKET)

remove:
	@echo "del $(WEB)" | sudo socat - UNIX-CONNECT:$(SOCKET)

add-many:
	@while read -r line; do echo "add $$line" | sudo socat - UNIX-CONNECT:$(SOCKET); done < $(FILE)

remove-many:
	@while read -r line; do echo "del $$line" | sudo socat - UNIX-CONNECT:$(SOCKET); done < $(FILE)

stop:
	@sudo pkill $(BINARY) || true
	@sudo rm -f $(SOCKET)

clean:
	@cargo clean

.PHONY: all start add add-shared remove add-many remove-many stop clean