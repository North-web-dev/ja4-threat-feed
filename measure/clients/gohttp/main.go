package main

import (
	"io"
	"net/http"
	"os"
	"runtime"
	"time"
)

func main() {
	os.Stderr.WriteString(runtime.Version() + "\n")
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Get(os.Args[1])
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
}
