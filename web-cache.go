package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
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
	Header     http.Header
	CreateTime time.Time
	LastAccess time.Time
}

var CacheMutex *sync.Mutex
var MemoryCache map[string]CacheEntry

func main() {
	// IpPort := os.Args[1] // send and receive data from Firefox
	// ReplacementPolicy := os.Args[2]
	// CacheSize := os.Args[3]
	// ExpirationTime := os.Args[4]

	IpPort := "localhost:1243"

	s := &http.Server{
		Addr: IpPort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			HandlerForFireFox(w, r)
		}),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	MemoryCache = map[string]CacheEntry{}
	CacheMutex = &sync.Mutex{}
	log.Fatal(s.ListenAndServe())
}

func HandlerForFireFox(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Method == "GET" {
		// Cache <- Response
		_, existInCache := MemoryCache[r.RequestURI]

		if !existInCache {
			// call request to get data for caching
			// TODO: any error return http response with error code (parsing/ forwarding request)
			resp := NewRequest(w, r)
			defer resp.Body.Close()

			// If response code is not 200, forward response to firefox.

			// Create New Cache Entry
			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Something wrong while parsing data")
			}

			if strings.Contains(http.DetectContentType(data), "text/html") {
				newEntry := NewCacheEntry(data)
				newEntry.RawData = data

				for name, values := range resp.Header {
					for _, v := range values {
						newEntry.Header.Add(name, v)
					}
				}

				AddCacheEntry(r.RequestURI, newEntry)
				ParseHTML(resp)
			}
		}
		// TODO: Send from cache

	} else { // forward response to firefox
		resp := NewRequest(w, r)
		defer resp.Body.Close()

		for name, values := range resp.Header {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		_, err := io.Copy(w, resp.Body)
		if err != nil {
			http.Error(w, "Internal Server Error", 500)
			DebugPrint("io.Copy error", "Issue with")
			panic(err)
		}
	}

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
						RequestResource(a)
					}
				}
			case IMG_TAG:
				for _, a := range fetchedToken.Attr {
					if a.Key == "src" {
						RequestResource(a)
					}
				}
			case SCRIPT_TAG:
				for _, a := range fetchedToken.Attr {
					if a.Key == "src" {
						RequestResource(a)
					}
				}
			}
		}
	}
}

// ===========================================================
// ===========================================================
//					Helper for Cache Entry
// ===========================================================
// ===========================================================

// Fetch the img/link/script from the url provided in an html
func RequestResource(a html.Attribute) {
	resp, err := http.Get(a.Val)
	bytes, err := ioutil.ReadAll(resp.Body)
	CheckError(err)
	entry := NewCacheEntry(bytes)
	CheckError(err)

	entry.RawData = bytes
	AddCacheEntry(a.Val, entry)
}

// Fill in RawData
func NewCacheEntry(data []byte) CacheEntry {
	NewEntry := CacheEntry{}
	NewEntry.Dtype = http.DetectContentType(data)
	NewEntry.CreateTime = time.Now()
	NewEntry.LastAccess = time.Now()
	NewEntry.UseFreq = 1
	return NewEntry
}

// Atomic adding to the cache
func AddCacheEntry(URL string, entry CacheEntry) {
	CacheMutex.Lock()
	MemoryCache[URL] = entry
	CacheMutex.Unlock()
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

func DebugPrint(title string, msg string) {
	fmt.Println("============ " + title + " ===============")
	fmt.Println(msg)
	fmt.Println("---------------------------------------")
}

func NewRequest(w http.ResponseWriter, r *http.Request) *http.Response {
	var resp *http.Response
	var newRequest *http.Request
	client := &http.Client{}

	newRequest, err := http.NewRequest(r.Method, r.RequestURI, r.Body)

	resp, err = client.Do(newRequest)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Println("cannot fetch response in new request")
	}

	return resp
}
