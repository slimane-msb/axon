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

test: daemon cli
	sudo go test -v ./tests/integration_test.go

zip:
	zip -r ~/Downloads/axon.zip . -x "sinkhole/target/*"

clean:
	rm -f $(DAEMON) $(CLI)