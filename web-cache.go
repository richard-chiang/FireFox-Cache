package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

type UserOptions struct {
	EvictPolicy    string
	CacheSize      int64
	ExpirationTime time.Duration
}

var options UserOptions
var CacheMutex *sync.Mutex
var MemoryCache map[string]CacheEntry
var HashUrlMap map[string]*url.URL

const CacheFolderPath string = "./cache/"

func main() {
	options = UserOptions{
		EvictPolicy:    "LFU",
		CacheSize:      100,
		ExpirationTime: time.Duration(500) * time.Second}

	// IpPort := os.Args[1] // send and receive data from Firefox
	// ReplacementPolicy := os.Args[2] // LFU or LRU or ELEPHANT
	// CacheSize := os.Args[3]
	// ExpirationTime := os.Args[4] // time period in seconds after which an item in the cache is considered to be expired

	IpPort := "localhost:1243"

	// if !(EvictPolicy == "LRU") && !(EvictPolicy == "LFU") && !(EvictPolicy == "ELEPHANT") {
	// 	fmt.Println("Please enter the proper evict policy: LFU or LRU only")
	// 	os.Exit(1)
	// }

	s := &http.Server{
		Addr: IpPort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			HandlerForFireFox(w, r)
		}),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	MemoryCache = map[string]CacheEntry{}
	HashUrlMap = map[string]*url.URL{}
	CacheMutex = &sync.Mutex{}
	RestoreCache()
	log.Fatal(s.ListenAndServe())
}

func HandlerForFireFox(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var url *url.URL
	var foundTrueUrl bool
	fmt.Println("GETTING REQUEST", r.URL)
	//fmt.Println("Request", r.URL)
	if r.Method == "GET" {
		// Cache <- Response

		entry, existInCache := GetByURL(r.RequestURI)

		if !existInCache {
			hashArr := strings.Split(r.RequestURI, "/")
			if len(hashArr) > 3 {
				hash := hashArr[3]
				//fmt.Println("THE HASH", hash)
				entry, existInCache = GetByHash(hash)
				if existInCache {
					fmt.Println("FOUND IN MAP", hash, len(entry.RawData))
				}
				if !existInCache {
					storedUrl, ok := HashUrlMap[hash]
					if ok {
						fmt.Println("FOUND IN MAP THO", storedUrl, hash)
						url = storedUrl
						foundTrueUrl = true
					}
				}
			}
		}

		if !existInCache && options.EvictPolicy == "ELEPHANT" {
			entry, existInCache = GetFromDiskUrl(r.RequestURI)
		}

		//if existInCache {
		//	fmt.Println("FOUND ENTRY")
		//}

		if !existInCache {

			if foundTrueUrl {
				fmt.Println(url)
				r.RequestURI = url.String()
				fmt.Println("REQUESTING THE FOUND ", url.String())
			}

			// call request to get data for caching
			resp := NewRequest(w, r)

			if resp == nil {
				return
			}

			if resp.StatusCode != 200 {
				fmt.Println("RESP IS NOT 200 ", resp.StatusCode)
				ForwardResponseToFireFox(w, resp)
				return
			}

			fmt.Println("ok here", r.URL)

			//CacheControl := resp.Header.Get("Cache-Control")
			//if CacheControl == "no-cache" {
			//	ForwardResponseToFireFox(w, resp)
			//	return
			//}

			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Something wrong while reading body")
			}
			newEntry := NewCacheEntry(data)
			newEntry.RawData = data
			newEntry.Header = http.Header{}

			for name, values := range resp.Header {
				for _, v := range values {
					newEntry.Header.Add(name, v)
				}
			}

			if strings.Contains(http.DetectContentType(data), "text/html") {
				urlsToReplace := ParseHTML(data)          // grab resources
				newHTML := WriteHTML(data, urlsToReplace) // modify html
				newEntry.RawData = []byte(newHTML)
			}

			if !foundTrueUrl {
				CacheMutex.Lock()
				HashUrlMap[Encrypt(r.RequestURI)] = r.URL
				CacheMutex.Unlock()
				//fmt.Println("Adding new URL", r.URL.String())
				//fmt.Println("Became", HashUrlMap)
			}

			entry = newEntry
			AddCacheEntry(r.RequestURI, newEntry) // save original html
			resp.Body.Close()
		}

		for name, values := range entry.Header {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}

		fmt.Println("Forwarding ", r.URL, len(entry.RawData))
		//fmt.Printf("Writing response %d bytes \n",len(entry.RawData))
		_, err := io.Copy(w, bytes.NewReader(entry.RawData))

		CheckError("io copy", err)

	} else {
		resp := NewRequest(w, r)
		ForwardResponseToFireFox(w, resp)
	}
}

func ForwardResponseToFireFox(w http.ResponseWriter, resp *http.Response) {
	// forward response to firefox
	defer resp.Body.Close()
	if resp == nil {
		return
	}

	for name, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	_, err := io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
		DebugPrint("io.Copy error", "Issue with i.Copy in ForwardResponse")
	}
}

func WriteHTML(data []byte, urlsToReplace []string) string {
	htmlString := string(data)

	for _, url := range urlsToReplace {
		htmlString = strings.Replace(htmlString, url, Encrypt(url), -1)
	}
	return htmlString
}

// example
// tagData = "img"
// keyword = "src"

func ParseHTML(resp []byte) []string {
	const LINK_TAG = "link"
	const IMG_TAG = "img"
	const SCRIPT_TAG = "script"
	cursor := html.NewTokenizer(bytes.NewReader(resp))
	var urlsToReplace []string

	for {
		token := cursor.Next()
		switch token {
		case html.ErrorToken:
			return urlsToReplace
		case html.StartTagToken:
			//fmt.Println("NOT ERROR")
			fetchedToken := cursor.Token()
			//fmt.Println(fetchedToken.Data, fetchedToken.Attr)
			switch fetchedToken.Data {
			case LINK_TAG:
				for _, a := range fetchedToken.Attr {
					if a.Key == "href" && (strings.HasPrefix(a.Val, "http") || strings.HasPrefix(a.Val, "//")) {
						urlsToReplace = append(urlsToReplace, a.Val)
						RequestResource(a)
					}
				}
			case IMG_TAG:
				for _, a := range fetchedToken.Attr {
					if a.Key == "src" && (strings.HasPrefix(a.Val, "http") || strings.HasPrefix(a.Val, "//")) {
						urlsToReplace = append(urlsToReplace, a.Val)
						RequestResource(a)
					}
				}
			case SCRIPT_TAG:
				for _, a := range fetchedToken.Attr {

					if a.Key == "src" && (strings.HasPrefix(a.Val, "http") || strings.HasPrefix(a.Val, "//")) {
						urlsToReplace = append(urlsToReplace, a.Val)
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

func GetFromDiskHash(hashkey string) (CacheEntry, bool) {
	CacheMutex.Lock()
	defer CacheMutex.Unlock()

	files, err := filepath.Glob(CacheFolderPath + "*")
	CheckError("err restoring cache. Cannot fetch file names", err)

	for _, fileName := range files {
		fileName = strings.TrimPrefix(fileName, "cache/")

		if fileName == ".DS_Store" {
			continue
		}
		// If the file was found
		if fileName == hashkey {
			// Delete from memory if the cache is too big
			MemoryCache[fileName] = ReadFromDisk(fileName)
			Evict()
			return MemoryCache[fileName], true
		}
	}

	return CacheEntry{}, false
}

func GetFromDiskUrl(url string) (CacheEntry, bool) {
	hashkey := Encrypt(url)
	return GetFromDiskHash(hashkey)
}

// hostname: http://example.com
func GetByHash(hashkey string) (CacheEntry, bool) {
	CacheMutex.Lock()

	entry, exist := MemoryCache[hashkey]
	if exist {
		if isExpired(hashkey) {
			DeleteCacheEntry(hashkey)
			exist = false
		} else {
			entry.LastAccess = time.Now()
			entry.UseFreq++
		}
	}
	CacheMutex.Unlock()

	return entry, exist
}

func GetByURL(url string) (CacheEntry, bool) {
	hashkey := Encrypt(url)
	return GetByHash(hashkey)
}

// Fetch the img/link/script from the url provided in an html
func RequestResource(a html.Attribute) {
	var resp *http.Response
	var err error
	var newUrl *url.URL
	if strings.HasPrefix(a.Val, "//") {
		resp, err = http.Get("http:" + a.Val)
		if err != nil {
			time.Sleep(time.Second)
			resp, err = http.Get(a.Val)
		}
		newUrl, err = url.ParseRequestURI("http:" + a.Val)

	} else {
		resp, err = http.Get(a.Val)
		if err != nil {
			time.Sleep(time.Second)
			resp, err = http.Get(a.Val)
		}
		newUrl, err = url.ParseRequestURI(a.Val)

	}
	CheckError("request resource: stroring hash for new url", err)
	CacheMutex.Lock()
	fmt.Println("CREATED NEW URL ", newUrl, "FOR ", Encrypt(a.Val), "or " , Encrypt("http:" + a.Val))
	HashUrlMap[Encrypt(a.Val)] = newUrl
	CacheMutex.Unlock()
	//fmt.Println("Adding new URL", newUrl.String())
	//fmt.Println("Became", HashUrlMap)
	CheckError("request resource: get request", err)
	entryBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	CheckError("request resource: readall", err)
	entry := NewCacheEntry(entryBytes)
	entry.RawData = entryBytes

	entry.Header = http.Header{}

	for name, values := range resp.Header {
		for _, v := range values {
			entry.Header.Add(name, v)
		}
	}

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
	Evict()
	fileName := Encrypt(URL)
	WriteToDisk(fileName, &entry)
	MemoryCache[fileName] = entry
	CacheMutex.Unlock()
}

func WriteToDisk(fileHash string, entry *CacheEntry) {
	bytes, err := json.Marshal(entry)
	CheckError("json marshal error", err)
	filePath := CacheFolderPath + fileHash
	var file *os.File

	_, err = os.Stat(filePath)
	if err != nil { // file does not exist, do create
		file, err = os.Create(filePath)
		CheckError("Create File Error", err)
	} else { // file exist, do write
		file, err = os.OpenFile(filePath, os.O_WRONLY, 0666)
		CheckError("open existing file error", err)
	}
	defer file.Close()
	CheckError("warning with write", err)
	if FolderHasExceedCache(int64(len(bytes))) {
		EvictForFile(int64(len(bytes)))
	}
	writer := bufio.NewWriter(file)
	n, err := writer.Write(bytes)

	writer.Flush()
	writer.Reset(writer)
	os.Truncate(filePath, int64(n))
	currentSize, err := DirectorySize(CacheFolderPath)
	ExceedMaxCache(currentSize)
}

func RestoreCache() {
	CacheMutex.Lock()
	defer CacheMutex.Unlock()

	files, err := filepath.Glob(CacheFolderPath + "*")
	CheckError("err restoring cache. Cannot fetch file names", err)

	for _, fileName := range files {
		fileName = strings.TrimPrefix(fileName, "cache/")
		if fileName == ".DS_Store" {
			continue
		}
		MemoryCache[fileName] = ReadFromDisk(fileName)
	}

	for key := range MemoryCache {
		if isExpired(key) {
			DeleteCacheEntry(key)
		}
	}

	Evict()
}

func Encrypt(input string) string {
	h := sha1.New()
	h.Write([]byte(input))
	sha := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return sha
}

func ReadFromDisk(hash string) CacheEntry {
	data, err := ioutil.ReadFile(CacheFolderPath + hash)
	CheckError("read error from disk", err)

	var cacheEntry CacheEntry
	err = json.Unmarshal(data, &cacheEntry)
	CheckError("json unmarshal err", err)
	return cacheEntry
}

func DeleteFromDisk(fileHash string) {
	if fileHash == "" {
		fmt.Println("cannot remove file of empty string from cache folder")
		return
	}
	err := os.Remove(CacheFolderPath + fileHash)
	CheckError("remove "+fileHash+" error", err)
}

func DeleteCacheEntry(hashkey string) {
	delete(MemoryCache, hashkey)
	DeleteFromDisk(hashkey)
}

func DeleteEntryElephant(hashkey string) {
	delete(MemoryCache, hashkey)
}

func Evict() {
	EvictExpired()

	folderSize, err := DirectorySize(CacheFolderPath)
	CheckError("err on reading directory size", err)
	for ExceedMaxCache(folderSize) {
		var KeyToEvict string
		if options.EvictPolicy == "LRU" {
			KeyToEvict = EvictLRU()
		} else if options.EvictPolicy == "LFU" {
			KeyToEvict = EvictLFU()
		} else {
			KeyToEvict = EvictLRU()
			DeleteEntryElephant(KeyToEvict)
			return
		}

		if KeyToEvict == "" {
			return
		}

		DeleteCacheEntry(KeyToEvict)
	}
}

func EvictForFile(size int64) {
	EvictExpired()

	folderSize, err := DirectorySize(CacheFolderPath)
	CheckError("err on reading directory size", err)
	for ExceedMaxCache(folderSize + size) {
		var KeyToEvict string
		if options.EvictPolicy == "LRU" {
			KeyToEvict = EvictLRU()
		} else if options.EvictPolicy == "LFU" {
			KeyToEvict = EvictLFU()
		} else {
			KeyToEvict = EvictLRU()
			DeleteEntryElephant(KeyToEvict)
			return
		}

		if KeyToEvict == "" {
			return
		}

		DeleteCacheEntry(KeyToEvict)
	}
}

func EvictLRU() string {
	oldestTime := time.Now()
	oldestKey := ""
	for key, cacheEntry := range MemoryCache {
		if cacheEntry.LastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = cacheEntry.LastAccess
		}
	}
	return oldestKey
}

func EvictLFU() string {
	var mostFrequentNumber uint64
	bestKey := ""
	for key, cacheEntry := range MemoryCache {
		if cacheEntry.UseFreq > mostFrequentNumber {
			bestKey = key
			mostFrequentNumber = cacheEntry.UseFreq
		}
	}
	return bestKey
}

func EvictExpired() {
	for key := range MemoryCache {
		if isExpired(key) {
			DeleteCacheEntry(key)
		}
	}
}

func isExpired(hash string) bool {
	cache, _ := MemoryCache[hash]
	elapsed := time.Since(cache.CreateTime)
	if elapsed > options.ExpirationTime {
		return true
	} else {
		return false
	}
}

func DirectorySize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})

	return size, err
}

// check if folder will exceed set cache size after adding the new file
func FolderHasExceedCache(fileSize int64) bool {
	currentSize, err := DirectorySize(CacheFolderPath)
	CheckError("Issue with fetching cache folder size", err)
	return ExceedMaxCache(currentSize + fileSize)
}

func ExceedMaxCache(size int64) bool {
	MBToBytes := 1048576
	//MBToBytes := 300000

	r := size > options.CacheSize*int64(MBToBytes)
	return r
}

// ===========================================================
// ===========================================================
//					Helper
// ===========================================================
// ===========================================================

func CheckError(msg string, err error) {
	if err != nil {
		fmt.Println("***********************************")
		fmt.Println("***********************************")
		fmt.Println(msg)
		fmt.Println("***********************************")
		fmt.Println(err)
		fmt.Println("***********************************")
		fmt.Println("***********************************")
	}
}

func DebugPrint(title string, msg string) {
	fmt.Println("============ " + title + " ===============")
	fmt.Println(msg)
	fmt.Println("---------------------------------------")
}

func PrintMemoryCache() {
	for key, _ := range MemoryCache {
		fmt.Println("========= Cache ============")
		fmt.Println("key: " + key)
		fmt.Println("=========================")
	}
}

func NewRequest(w http.ResponseWriter, r *http.Request) *http.Response {
	var resp *http.Response
	var newRequest *http.Request
	client := &http.Client{}

	newRequest, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Println("cannot fetch response in new request")
		return nil
	}

	resp, err = client.Do(newRequest)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Println("cannot fetch response in new request")
		return nil
	}

	return resp
}
