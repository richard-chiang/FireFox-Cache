package main

import (
	"io"
	"log"
	"net/http"
	"time"
)

// go run web-cache.go [ip:port] [replacement_policy] [cache_size] [expiration_time]
// [ip:port] : The TCP IP address and the port at which the web-cache will be running.
// [replacement_policy] : The replacement policy ("LRU" or "LFU") that the web cache follows during eviction.
// [cache_size] : The capacity of the cache in MB (your cache cannot use more than this amount of capacity). Note that this specifies the (same) capacity for both the memory cache and the disk cache.
// [expiration_time] : The time period in seconds after which an item in the cache is considered to be expired.

func main() {
	// IpPort := os.Args[1] // send and receive data from Firefox
	// ReplacementPolicy := os.Args[2]
	// CacheSize := os.Args[3]
	// ExpirationTime := os.Args[4]

	IpPort := "localhost:8888"

	s := &http.Server{
		Addr: IpPort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			HandlerForFireFox(w, r)
		}),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Fatal(s.ListenAndServe())
}

func HandlerForFireFox(w http.ResponseWriter, r *http.Request) {
	var resp *http.Response
	var newRequest *http.Request
	client := &http.Client{}

	log.Printf("%v %v", r.Method, r.RequestURI)

	newRequest, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
	for name, value := range r.Header {
		newRequest.Header.Set(name, value[0])
	}

	resp, err = client.Do(newRequest)

	r.Body.Close()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	resp.Body.Close()
}
