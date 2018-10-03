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
	"math"
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
	PublicIpPort   string
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
	PrivateIpPort := os.Args[1] // send and receive data from Firefox
	PublicIpPort := os.Args[2] // send and receive data from Firefox
	ReplacementPolicy := os.Args[3] // LFU or LRU or ELEPHANT
	CacheSize := os.Args[4]
	ExpirationTime := os.Args[5] // time period in seconds after which an item in the cache is considered to be expired
	CacheControl := os.Args[6] // whether to use cache control or not

	CacheSizeInt, err := strconv.Atoi(CacheSize)
	if err != nil || CacheSizeInt < 1 {
		fmt.Println("Please enter valid cache size ")
		return
	}
	CacheSizeInt64 := int64(CacheSizeInt)

	ExpirationTimeInt, err := strconv.Atoi(ExpirationTime)
	if err != nil || ExpirationTimeInt < 1 {
		fmt.Println("Please enter valid expiration time ")
		return
	}

	CacheControlBool, err := strconv.ParseBool(CacheControl)
	if err != nil {
		fmt.Println("Please enter valid cache control ")
		return
	}


	options = UserOptions{
		PublicIpPort:		PublicIpPort,
		EvictPolicy:    ReplacementPolicy,
		CacheSize:      CacheSizeInt64,
		ExpirationTime: time.Duration(ExpirationTimeInt) * time.Second,
		CacheControl:   CacheControlBool,
	}


	s := &http.Server{
		Addr: PrivateIpPort,
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

		// For elephant, the entry could be just stored on disk
		if !existInCache && options.EvictPolicy == "ELEPHANT" {
			fmt.Println("HANDLER_FOR_FIREFOX: Using ELEPHANT: ", Encrypt(r.RequestURI), " not in memory, getting from disk")
			entry, existInCache = GetFromDiskUrl(r.RequestURI)
		}

		var hash string
		if !existInCache {
			// Extract the hash from the request URL, see if it matches the already stored entries

			hashArr := strings.Split(r.RequestURI, "/")
			if len(hashArr) > 3 {
				hash = hashArr[len(hashArr)-1]
			} else if len(hashArr) == 2 {
				hash = hashArr[1]
			}
			// Hash extracted, check the CacheMap
			entry, existInCache = GetByHash(hash)

			// For elephant, the entry could be just stored on disk
			if !existInCache && options.EvictPolicy == "ELEPHANT" {
				entry, existInCache = GetFromDiskHash(hash)
			}

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

		if !existInCache || isExpired(entry) {
			if foundTrueUrl {
				r.RequestURI = storedUrl.String()
			}

			// call request to get data for caching
			resp := NewRequest(w, r)
			avoidCopy := false
			if options.CacheControl {
				cacheControlString := resp.Header.Get("Cache-Control")
				if strings.Contains(cacheControlString, "no-store") {
					fmt.Println("HANDLER_FOR_FIREFOX: CACHE-CONTROL - enabled. Not saving entries for this request/response")
					avoidCopy = true
				}
			}

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

			if !foundTrueUrl {
				if options.CacheControl {
					if !avoidCopy {
						AddUrlHash(Encrypt(r.RequestURI), r.URL)
					}
				} else {
					fmt.Println("HANDLER_FOR_FIREFOX: Storing Request url ", r.URL, " for ", "")
					AddUrlHash(Encrypt(r.RequestURI), r.URL)
				}
			}
			if existInCache && isExpired(entry) {
				newEntry.UseFreq = entry.UseFreq + 1
			}

			if options.CacheControl {
				if !avoidCopy{
					if options.EvictPolicy == "ELEPHANT" {
						AddEntryElephant(Encrypt(r.RequestURI), newEntry)
					} else {
						AddCacheEntry(r.RequestURI, newEntry) // save original html
					}
				}
			} else {
				if options.EvictPolicy == "ELEPHANT" {
					AddEntryElephant(Encrypt(r.RequestURI), newEntry)
				} else {
					AddCacheEntry(r.RequestURI, newEntry) // save original html
				}

			}
			entry = newEntry
			resp.Body.Close()
		}
		fmt.Println("HANDLER_FOR_FIREFOX: Use frequency of ", r.RequestURI, " is ", entry.UseFreq)
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
		htmlString = strings.Replace(htmlString, url, "http://" + options.PublicIpPort + "/" + Encrypt(url), -1)
	}
	return htmlString
}

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
			if err != nil {
				return CacheEntry{}, false
			}
			CheckError("Error with elephant, ", err)
			AddToMemoryElephant(fileName, entry)
			return entry, true
		}
	}
	return CacheEntry{}, false
}

func AddToMemoryElephant(fileName string, entry CacheEntry) {

	bytesNewEntry, err := json.Marshal(entry)
	if err != nil {
		return
	}
	bytesAllEntries, _ := json.Marshal(MemoryCache)

	sizeNewElement := int64(len(bytesNewEntry))
	sizeAllEntries := int64(len(bytesAllEntries))

	if sizeNewElement > 1048576 * options.CacheSize {
		return
	}

	for ExceedMaxCache(sizeAllEntries + sizeNewElement) {
		hashkey := EvictLRU()
		DeleteEntryElephant(hashkey)
		bytesAllEntries, _ := json.Marshal(MemoryCache)
		sizeAllEntries = int64(len(bytesAllEntries))
	}

	MemoryCache[fileName] = entry
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
	var avoidCopy bool
	var oldEntry CacheEntry
	var exist 	 bool

	link := a.Val
	if strings.HasPrefix(link, "//") {
		link = "http:" + link
	}
	oldEntry, exist = GetByHash(Encrypt(link))

	if !exist && options.EvictPolicy == "ELEPHANT" {
			fmt.Println("HANDLER_FOR_FIREFOX: Using ELEPHANT: ", Encrypt(link), " not in memory, getting from disk")
			oldEntry, exist = GetFromDiskUrl(link)
	}

	if exist && !isExpired(oldEntry)  {
		fmt.Println("REQUEST_RESOURCE: Entry is already saved and fresh, no need to overwrite")
		return
	}

	fmt.Println("REQUEST_RESOURCE: Fetching ", link)

	resp, err = http.Get(link)
	newUrl, err = url.ParseRequestURI(link)

	CheckError("request resource: stroring hash for new url", err)

	if options.CacheControl {
		cacheControlString := resp.Header.Get("Cache-Control")
		if strings.Contains(cacheControlString, "no-store") {
			avoidCopy = true
		}
	}

	if options.CacheControl {
		if !avoidCopy {
			AddUrlHash(Encrypt(link), newUrl)
		}
	} else {
		AddUrlHash(Encrypt(link), newUrl)
	}

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

	if options.CacheControl {
		if !avoidCopy {
			if options.EvictPolicy == "ELEPHANT" {
				AddEntryElephant(Encrypt(link), entry)
			} else {
				AddCacheEntry(link, entry)
			}
		}
	} else {
		if options.EvictPolicy == "ELEPHANT" {
			AddEntryElephant(Encrypt(link), entry)
		} else {
			AddCacheEntry(link, entry)
		}
	}
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
	writeOk := WriteToDisk(fileName, entry)
	if writeOk {
		MemoryCache[fileName] = entry
		fmt.Println("ADD_CACHE_ENTRY: Successfully added entry ", fileName, " with URL ", URL)
	} else {
		fmt.Println("ADD_CACHE_ENTRY: Could not add entry ", fileName, " with URL ", URL)
	}
	CacheMutex.Unlock()
}

func AddEntryElephant(hash string, entry CacheEntry) {
	CacheMutex.Lock()
	fmt.Println("ADD_ENTRY_ELEPHANT: Adding entry ", hash)
	defer  CacheMutex.Unlock()
	WriteToDisk(hash, entry)
	AddToMemoryElephant(hash, entry)
}

func AddUrlHash(hash string, newUrl *url.URL) {
	CacheMutex.Lock()
	defer CacheMutex.Unlock()
	HashUrlMap[hash] = newUrl
	WriteUrlHashToDisk()
}

func WriteToDisk(fileHash string, entry CacheEntry) (bool) {
	bytes, err := json.Marshal(entry)

	fmt.Println("WRITE_TO_DISK: Attempting to write ", fileHash, " to disk. ", len(bytes), " bytes.")

	if options.EvictPolicy != "ELEPHANT" {
		if ExceedMaxCache(int64(len(bytes))) {
			fmt.Println("WRITE_TO_DISK: Cannot add ", fileHash, " to disk. ", len(bytes), " bytes. Too big to fit in cache.")
			return false
		}
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

	if options.EvictPolicy != "ELEPHANT" {
		if FolderHasExceedCache(int64(len(bytes))) {
			EvictForFile(int64(len(bytes)))
		}
	}
	writer := bufio.NewWriter(file)
	n, err := writer.Write(bytes)

	writer.Flush()
	writer.Reset(writer)
	os.Truncate(filePath, int64(n))
	file.Sync()

	fmt.Println("WRITE_TO_DISK: wrote to disk ", fileHash, " ", len(bytes), " bytes.")
	return true
}

func WriteUrlHashToDisk()  (err error) {

	tempMap := "./tempHashMap"
	hashmap := "./hashUrlMap"

	var tempFile *os.File

	bytes, err := json.Marshal(HashUrlMap)

	_, err = os.Stat(tempMap)
	if err != nil { // file does not exist, do create
		tempFile, err = os.Create(tempMap)
		CheckError("Create File Error", err)
	} else { // file exist, do write
		tempFile, err = os.OpenFile(tempMap, os.O_WRONLY, 0666)
		CheckError("open existing file error", err)
	}
	writer := bufio.NewWriter(tempFile)
	_, err = writer.Write(bytes)
	writer.Flush()

	writer.Reset(writer)
	tempFile.Close()
	tempFile.Sync()

	CheckError("open existing file error", err)
	os.Rename(tempMap, hashmap)
	directory, err := os.OpenFile("./", os.O_WRONLY, 0666)
	directory.Sync()

	return err
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

	hashmap := "./hashUrlMap"
	_, err = os.Stat(hashmap)

	if err == nil {
		data, err := ioutil.ReadFile(hashmap)
		CheckError("READ_FROM_DISK: URL MAP read error from disk", err)

		err = json.Unmarshal(data, &HashUrlMap)
		CheckError("RESTORE_CACHE: URL MAP json unmarshal err", err)
		fmt.Println("RESTORE_CACHE: Restored URL map successfully!", HashUrlMap)
	}
	// In case cache size changed
	if options.EvictPolicy != "ELEPHANT" {
		Evict()
	}
}

func Encrypt(input string) string {
	h := sha1.New()
	h.Write([]byte(input))
	sha := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return sha
}

func ReadFromDisk(hash string) (CacheEntry, error) {
	data, err := ioutil.ReadFile(CacheFolderPath + hash)
	if err != nil {
		return CacheEntry{}, err
	}
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
	fmt.Println("DELETE_FROM_DISK: removing "+fileHash)
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
		}

		if KeyToEvict == "" {
			return
		}

		DeleteCacheEntry(KeyToEvict)
	}
}

func EvictForFile(size int64) {
	fmt.Println("EVICT_FOR_FILE: Evicting for ", size, " bytes.")
	folderSize, err := DirectorySize(CacheFolderPath)
	CheckError("err on reading directory size", err)
	for ExceedMaxCache(folderSize + size) {
		var KeyToEvict string
		if options.EvictPolicy == "LRU" {
			KeyToEvict = EvictLRU()
		} else if options.EvictPolicy == "LFU" {
			KeyToEvict = EvictLFU()
		}

		if KeyToEvict == "" {
			return
		}
		DeleteCacheEntry(KeyToEvict)
		folderSize, err = DirectorySize(CacheFolderPath)
		CheckError("err on reading directory size", err)
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
	var leastFrequentNumber uint64
	leastFrequentNumber = math.MaxUint64

	bestKey := ""
	for key, cacheEntry := range MemoryCache {
		if cacheEntry.UseFreq < leastFrequentNumber {
			bestKey = key
			leastFrequentNumber = cacheEntry.UseFreq
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
	MBToBytes := 1048576
	//MBToBytes := 110000
	fmt.Printf("EXCEED_MAX_CACHE: Folder with new file is now %d bytes. %d bytes available overall. \n", size, options.CacheSize*int64(MBToBytes))
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
