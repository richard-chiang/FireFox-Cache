package main

import (
	"fmt"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// go run web-cache.go [ip:port] [replacement_policy] [cache_size] [expiration_time]
// [ip:port] : The TCP IP address and the port at which the web-cache will be running.
// [replacement_policy] : The replacement policy ("LRU" or "LFU") that the web cache follows during eviction.
// [cache_size] : The capacity of the cache in MB (your cache cannot use more than this amount of capacity). Note that this specifies the (same) capacity for both the memory cache and the disk cache.
// [expiration_time] : The time period in seconds after which an item in the cache is considered to be expired.

type CacheEntry struct {
	RawData    []byte
	Dtype      string // "img/png" | "img/jpg" | "text/javascript" ....
	UseFreq    uint64 // # of access
	CreateTime time.Time
	LastAccess time.Time
}

var MemoryCache map[string]CacheEntry

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
	MemoryCache = map[string]CacheEntry{}
	log.Fatal(s.ListenAndServe())
}

func HandlerForFireFox(w http.ResponseWriter, r *http.Request) {
	var resp *http.Response
	var newRequest *http.Request
	client := &http.Client{}

	newRequest, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
	for name, values := range r.Header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}

	resp, err = client.Do(newRequest)
	r.Body.Close()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Will probably be needed later
	if resp.StatusCode != 200 {
		return
	}
	_, ok := MemoryCache[r.RequestURI]

	if !ok {
		//NewEntry := CacheEntry{}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Something wrong while parsing data")
			if http.DetectContentType(data) == "text/html" {
				ParseHTML(resp)
			}
			ParseHTML(resp)
		 }
	 }

	// 	NewEntry.Dtype = http.DetectContentType(data)
	// 	NewEntry.RawData = data
	// 	NewEntry.CreateTime = time.Now()
	// 	NewEntry.LastAccess = time.Now()
	// 	NewEntry.UseFreq = 1
	// 	MemoryCache[r.RequestURI] = NewEntry
	// }
	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		panic(err)
	}
	resp.Body.Close()
}

func ParseHTML(resp *http.Response) {
	const LINK_TAG = "link"
	const IMG_TAG = "img"
	const SCRIPT_TAG = "script"

	cursor := html.NewTokenizer(resp.Body)

	for {
		token := cursor.Next()

		switch token {
		case html.ErrorToken:
			return
		case html.StartTagToken:
			fetchedToken := cursor.Token()
			switch fetchedToken.Data {
			case LINK_TAG:
				for _, a := range fetchedToken.Attr {
					if a.Key == "href" {
						entry := NewCacheEntry(*resp)
						resp, err := http.Get(a.Val)
						CheckError(err)
						bytes, err := ioutil.ReadAll(resp.Body)
						CheckError(err)
						entry.RawData = bytes
						MemoryCache[a.Val] = entry
					}
				}
			case IMG_TAG:
				for _, a := range fetchedToken.Attr {
					if a.Key == "src" {
						entry := NewCacheEntry(*resp)
						resp, err := http.Get(a.Val)
						CheckError(err)
						bytes, err := ioutil.ReadAll(resp.Body)
						CheckError(err)
						entry.RawData = bytes
						MemoryCache[a.Val] = entry
					}
				}
			case SCRIPT_TAG:
				for _, a := range fetchedToken.Attr {
					if a.Key == "src" {
						entry := NewCacheEntry(*resp)
						resp, err := http.Get(a.Val)
						CheckError(err)
						bytes, err := ioutil.ReadAll(resp.Body)
						CheckError(err)
						entry.RawData = bytes
						MemoryCache[a.Val] = entry
					}
				}
			}
		}
	}
	return
}

// ===========================================================
// ===========================================================
//					Helper for Cache Entry
// ===========================================================
// ===========================================================

// Fill in RawData
func NewCacheEntry(resp http.Response) CacheEntry {
	NewEntry := CacheEntry{}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Something wrong while parsing data")
	}

	NewEntry.Dtype = http.DetectContentType(data)
	NewEntry.CreateTime = time.Now()
	NewEntry.LastAccess = time.Now()
	NewEntry.UseFreq = 1
	return NewEntry
}

// ===========================================================
// ===========================================================
//					Helper
// ===========================================================
// ===========================================================

func CheckError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
