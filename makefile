DAEMON = axond
CLI    = axon

.PHONY: all clean daemon cli

all: daemon cli

daemon:
	go build -o $(DAEMON) ./cmd/daemon

cli:
	go build -o $(CLI) ./cmd/cli

start-daemon: daemon
	sudo ./$(DAEMON)

clean:
	rm -f $(DAEMON) $(CLI)