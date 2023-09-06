build:
	go build -o bin/cvelint cmd/cvelint/main.go

clean:
	/bin/rm -f bin/cvelint
