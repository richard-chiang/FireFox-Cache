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
	"strconv"
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
	CacheControl   bool
}

var options UserOptions
var CacheMutex *sync.Mutex
var MemoryCache map[string]CacheEntry
var HashUrlMap map[string]*url.URL

const CacheFolderPath string = "./cache/"

func main() {
	// IpPort := os.Args[1] // send and receive data from Firefox
	// ReplacementPolicy := os.Args[2] // LFU or LRU or ELEPHANT
	// CacheSize := os.Args[3]
	// ExpirationTime := os.Args[4] // time period in seconds after which an item in the cache is considered to be expired
	// CacheControl := os.Args[5] // whether to use cache control or not

	options = UserOptions{
		EvictPolicy:    "LFU",
		CacheSize:      1,
		ExpirationTime: time.Duration(100) * time.Second,
		CacheControl:   false,
	}


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
	HashUrlMap = map[string]*url.URL{}
	CacheMutex = &sync.Mutex{}
	RestoreCache()
	log.Fatal(s.ListenAndServe())
}

func HandlerForFireFox(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var storedUrl *url.URL
	var foundTrueUrl bool
	fmt.Println("HANDLER_FOR_FIREFOX: Got request ", r.RequestURI, " ", r.URL)
	// If not get, just forward the response to firefox

	if r.Method == "GET" {
		/**
		 * Checking if the entry is inside the cache
		 */
		// Check if entry with given request URL is already cached
		entry, existInCache := GetByURL(r.RequestURI)

		if !existInCache {
			// Extract the hash from the request URL, see if it matches the already stored entries

			hashArr := strings.Split(r.RequestURI, "/")
			var hash string
			if len(hashArr) > 3 {
				hash = hashArr[len(hashArr)-1]
				fmt.Println("FIRST HASH", hash)
			} else if len(hashArr) == 2 {

				hash = hashArr[1]
				fmt.Println("SECOND HASH", hash)
			}
			// Hash extracted, check the CacheMap
			entry, existInCache = GetByHash(hash)
			if existInCache && !isExpired(entry) {
				fmt.Println("HANDLER_FOR_FIREFOX: Found the entry by its hash inside our cache", hash)
			}
			// If the entry is still not found, it could be that it was fetched before but expired. Or it could just
			// expire before but still be stored. Use its hash to check if we saved the url for this hash
			if !existInCache || isExpired(entry) {
				CacheMutex.Lock()
				storedUrlMap, ok := HashUrlMap[hash]
				fmt.Println("HANDLER_FOR_FIREFOX: Stored urlmap")
				CacheMutex.Unlock()
				if ok {
					storedUrl = storedUrlMap
					foundTrueUrl = true
				}
				// If the entry was found on cache but expired, we need to refetch it later
				existInCache = false
			}
		}



		// For elephant, the entry could be just stored on disk
		if !existInCache && options.EvictPolicy == "ELEPHANT" {
			entry, existInCache = GetFromDiskUrl(r.RequestURI)
		}

		if !existInCache || isExpired(entry) {

			if foundTrueUrl {
				r.RequestURI = storedUrl.String()
			}

			// call request to get data for caching
			resp := NewRequest(w, r)
			fmt.Println("HANDLER_FOR_FIREFOX: Fetching ", r.URL, " ", r.RequestURI)

			if resp == nil {
				fmt.Println("HANDLER_FOR_FIREFOX: Response is nil")
				return
			}

			if resp.StatusCode != 200 {
				ForwardResponseToFireFox(w, resp)
				fmt.Println("HANDLER_FOR_FIREFOX: Response is not 200")
				return
			}
			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("HANDLER_FOR_FIREFOX: Something wrong while reading body")
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
			newEntry.Header.Set("Content-Length", strconv.Itoa(len(newEntry.RawData)))
			fmt.Println("Setting content length: ", strconv.Itoa(len(newEntry.RawData)))

			if !foundTrueUrl {
				CacheMutex.Lock()
				HashUrlMap[Encrypt(r.RequestURI)] = r.URL
				CacheMutex.Unlock()
			}

			if existInCache && isExpired(entry) {
				newEntry.UseFreq = entry.UseFreq + 1
				fmt.Println(newEntry.UseFreq)
			}

			AddCacheEntry(r.RequestURI, newEntry) // save original html
			entry = newEntry
			resp.Body.Close()
		}
		fmt.Println(entry.UseFreq)
		for name, values := range entry.Header {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
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
	htmlString = html.UnescapeString(htmlString)
	for _, url := range urlsToReplace {
		fmt.Println("Replacing ", url, "with ", "http://localhost:1243/" + Encrypt(url))
		htmlString = strings.Replace(htmlString, url, "http://localhost:1243/" + Encrypt(url), -1)
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
		if token == html.ErrorToken {
			return urlsToReplace
		} else if token == html.StartTagToken || token == html.SelfClosingTagToken || token == html.EndTagToken {
			fetchedToken := cursor.Token()
			//fmt.Println("Got start token, name ", fetchedToken.Data, fetchedToken.Type, fetchedToken.Attr)
			//fmt.Println(fetchedToken.Data, fetchedToken.Attr)
			switch fetchedToken.Data {
			case LINK_TAG:
				for _, a := range fetchedToken.Attr {
					if a.Key == "href" && ValidParseUrl(a.Val) {
						urlsToReplace = append(urlsToReplace, a.Val)
						RequestResource(a)
					}
				}
			case IMG_TAG:
				for _, a := range fetchedToken.Attr {
					if a.Key == "src" && ValidParseUrl(a.Val) {
						urlsToReplace = append(urlsToReplace, a.Val)
						RequestResource(a)
					}
				}
			case SCRIPT_TAG:
				for _, a := range fetchedToken.Attr {

					if a.Key == "src" && ValidParseUrl(a.Val) {
						urlsToReplace = append(urlsToReplace, a.Val)
						RequestResource(a)
					}
				}
			}
		}
	}
}

func ValidParseUrl(val string) bool {
	return strings.HasPrefix(val, "http") || strings.HasPrefix(val, "//")
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
			entry, err := ReadFromDisk(fileName)
			CheckError("Error with elephant, ", err)
			MemoryCache[fileName] = entry
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
		entry.LastAccess = time.Now()
		entry.UseFreq++
		MemoryCache[hashkey] = entry
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
	HashUrlMap[Encrypt(a.Val)] = newUrl
	CacheMutex.Unlock()

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
	entry.Header.Set("Content-Length", strconv.Itoa(len(entryBytes)))
	fmt.Println("Setting content length: ", strconv.Itoa(len(entryBytes)))
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
	fileName := Encrypt(URL)
	fmt.Println("ADD_CACHE_ENTRY: Attempting to add entry ", fileName, " with URL ", URL)
	writeOk := WriteToDisk(fileName, &entry)
	if writeOk {
		MemoryCache[fileName] = entry
		fmt.Println("ADD_CACHE_ENTRY: Successfully added entry ", fileName, " with URL ", URL)
	} else {
		fmt.Println("ADD_CACHE_ENTRY: Could not add entry ", fileName, " with URL ", URL)
	}
	CacheMutex.Unlock()
}

func WriteToDisk(fileHash string, entry *CacheEntry) (bool) {
	bytes, err := json.Marshal(entry)

	fmt.Println("WRITE_TO_DISK: Attempting to write ", fileHash, " to disk. ", len(bytes), " bytes.")

	if ExceedMaxCache(int64(len(bytes))) {
		fmt.Println("WRITE_TO_DISK: Cannot add ", fileHash, " to disk. ", len(bytes), " bytes. Too big to fit in cache.")
		return false
	}

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
	fmt.Println("WRITE_TO_DISK: wrote to disk ", fileHash, " ", len(bytes), " bytes.")
	return true
}

func RestoreCache() {

	CacheMutex.Lock()
	defer CacheMutex.Unlock()

	files, err := filepath.Glob(CacheFolderPath + "*")
	CheckError("RESTORE_CACHE: err restoring cache. Cannot fetch file names", err)

	for _, fileName := range files {
		fileName = strings.TrimPrefix(fileName, "cache/")
		if fileName == ".DS_Store" {
			continue
		}
		entry, err := ReadFromDisk(fileName)
		if err == nil {
			MemoryCache[fileName] = entry
			fmt.Println("RESTORE_CACHE: Successfully read ", fileName, " from disk.")
		}
	}
	// In case cache size changed
	Evict()
}

func Encrypt(input string) string {
	h := sha1.New()
	h.Write([]byte(input))
	sha := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return sha
}

func ReadFromDisk(hash string) (CacheEntry, error) {
	data, err := ioutil.ReadFile(CacheFolderPath + hash)
	CheckError("READ_FROM_DISK: read error from disk", err)

	var cacheEntry CacheEntry
	err = json.Unmarshal(data, &cacheEntry)
	CheckError("READ_FROM_DISK: json unmarshal err", err)
	return cacheEntry, err
}

func DeleteFromDisk(fileHash string) {
	if fileHash == "" {
		fmt.Println("DELETE_FROM_DISK: cannot remove file of empty string from cache folder")
		return
	}
	err := os.Remove(CacheFolderPath + fileHash)
	CheckError("DELETE_FROM_DISK: remove "+fileHash+" error", err)
}

func DeleteCacheEntry(hashkey string) {
	delete(MemoryCache, hashkey)
	DeleteFromDisk(hashkey)
}

func DeleteEntryElephant(hashkey string) {
	delete(MemoryCache, hashkey)
}

func Evict() {
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

func isExpired(entry CacheEntry) bool {
	CacheMutex.Lock()
	defer CacheMutex.Unlock()

	elapsed := time.Since(entry.CreateTime)
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
	CheckError("FOLDER_HAS_EXCEEDED_CACHE: Issue with fetching cache folder size", err)
	return ExceedMaxCache(currentSize + fileSize)
}

func ExceedMaxCache(size int64) bool {
	//MBToBytes := 1048576
	MBToBytes := 1550
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
		fmt.Println("NEW_REQUEST: cannot fetch response in new request")
		return nil
	}

	resp, err = client.Do(newRequest)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Println("NEW_REQUEST: cannot fetch response in new request")
		return nil
	}

	return resp
}
