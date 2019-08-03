package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	MegaBytes     int64 = 1024 * 1024
	MaxUploadSize int64 = 50 * MegaBytes
	UploadsDir          = "uploads"
	UploadsLimit        = 10 * time.Second
)

var UploadsLimiter = NewRateLimiter(UploadsLimit, 100)
var Stats = NewByNameCounter(100)

var config struct {
	BaseURL      string
	UploadSecret string
	AdminSecret  string
}

type UploadInfo struct {
	ID           string    `json:"id"`
	FileName     string    `json:"filename"`
	ContentType  string    `json:"content-type"`
	DateUploaded time.Time `json:"date-uploaded"`
	Size         int64     `json:"-"`
}

func main() {
	addr := "localhost:9999"

	config.BaseURL = os.Getenv("BASE_URL")
	if config.BaseURL == "" {
		config.BaseURL = fmt.Sprintf("http://%s", addr)
	}

	uploadSecret, err := ioutil.ReadFile("upload-secret.txt")
	if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}
	config.UploadSecret = strings.TrimSpace(string(uploadSecret))

	adminSecret, err := ioutil.ReadFile("admin-secret.txt")
	if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}
	config.AdminSecret = strings.TrimSpace(string(adminSecret))

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			logRequest(req, http.StatusBadRequest, "")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		Stats.Count("visit")

		errorMsg := req.URL.Query().Get("error")
		if errorMsg != "" {
			errorMsg = fmt.Sprintf(`<p id="error">Error: %s!</p>`, errorMsg)
		}

		secretInput := ""
		if config.UploadSecret != "" {
			secretInput = `<div class="field">
	<label for="secret">Upload secret:</label>
	<input type="text" name="secret" required placeholder="Secret required to upload" />
</div>`
		}

		fmt.Fprintf(w, `
<!doctype html>
<html>
<head>
	<meta charset="utf-8" />
	<title>share</title>
	<style>
	.field {
		margin-bottom: 0.5em;
	}

	#error {
		background-color: rgba(255, 0, 0, 10%%);
		max-width: 20em;
		padding: 0.5em;
		border-radius: 0.3ex;
		font-weight: bold;
	}
	</style>
</head>

<body>
	<h1>share files</h1>
	
	%s

	<p>%s upload limit, files expire after 14 days.</p>

	<form method="POST" action="/up" enctype="multipart/form-data">
		%s

		<div class="field">
			<label for="file">File to upload:</label>
			<input id="file" type="file" required name="file" />
		</div>

		<input type="submit" value="Upload" />
	</form>

	<script src="/validation.js"></script>
	<script>
		var maxFileSize = %d;
		var fileElement = document.getElementById("file");
		fileElement.addEventListener("change", function(ev) {
			validateFileSize(maxFileSize, ev.target);
		});
		window.addEventListener("load", function() {
			validateFileSize(maxFileSize, fileElement);
		});
	</script>
</body>
</html>
		`, errorMsg, formatBytes(MaxUploadSize), secretInput, MaxUploadSize)
	})

	http.HandleFunc("/up", func(w http.ResponseWriter, req *http.Request) {
		req.Body = CountingReadCloser(req.Body, func(n int) { Stats.Add("bytes-received", n) })
		w = CountingResponseWriter(w, func(n int) { Stats.Add("bytes-written", n) })

		req.Body = http.MaxBytesReader(w, req.Body, MaxUploadSize+1*MegaBytes)

		if req.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		if UploadsLimiter.IsLimited(hashIP(req)) {
			Stats.Count("rate-limit")
			logRequest(req, http.StatusTooManyRequests, "")
			w.Header().Set("Retry-After", time.Now().Add(UploadsLimit).UTC().String())
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		err := req.ParseMultipartForm(MaxUploadSize)
		if err != nil {
			logRequest(req, http.StatusBadRequest, fmt.Sprintf("file too big, tried to upload %s", formatBytes(req.ContentLength)))
			http.Error(w, "file too big", http.StatusBadRequest)
			return
		}

		if config.UploadSecret != req.FormValue("secret") {
			http.Error(w, "uploads only allowed using upload secret", http.StatusForbidden)
			return
		}

		file, header, err := req.FormFile("file")
		if err != nil {
			log.Printf("could not read file: %s", err)
			http.Error(w, "could not read file", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		if header.Size > MaxUploadSize {
			http.Error(w, "file too big", http.StatusBadRequest)
			return
		}

		data := make([]byte, 8)
		_, err = rand.Read(data)
		if err != nil {
			log.Printf("could not generate id: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		id := fmt.Sprintf("%x", data)

		uploadInfo := UploadInfo{
			ID:           id,
			FileName:     header.Filename,
			ContentType:  header.Header.Get("Content-Type"),
			DateUploaded: time.Now().Round(time.Second).UTC(),
		}

		uf, err := os.OpenFile(path.Join(UploadsDir, id+"-info.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			log.Printf("could not create info file: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer uf.Close()

		enc := json.NewEncoder(uf)
		err = enc.Encode(uploadInfo)
		if err != nil {
			log.Printf("could not write info file: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		f, err := os.OpenFile(path.Join(UploadsDir, id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			log.Printf("could not create file: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		_, err = io.Copy(f, file)
		if err != nil {
			log.Printf("could not write file: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		Stats.Count("upload")
		logRequest(req, http.StatusSeeOther, "")
		w.Header().Set("Location", fmt.Sprintf("/dl/%s/%s?dl=false", id, uploadInfo.FileName))
		w.WriteHeader(http.StatusSeeOther)
		fmt.Fprintf(w, "%s/dl/%s/%s", config.BaseURL, id, uploadInfo.FileName)
	})

	http.HandleFunc("/dl/", func(w http.ResponseWriter, req *http.Request) {
		req.Body = CountingReadCloser(req.Body, func(n int) { Stats.Add("bytes-received", n) })
		w = CountingResponseWriter(w, func(n int) { Stats.Add("bytes-written", n) })

		parts := strings.SplitN(req.URL.Path[1:], "/", 3)
		if len(parts) < 2 || parts[1] == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		id := url.PathEscape(parts[1])

		if strings.HasSuffix(id, ".json") {
			id = id[:len(id)-len(".json")]

			f, err := os.Open(path.Join(UploadsDir, id+"-info.json"))
			if err != nil {
				if os.IsNotExist(err) {
					logRequest(req, http.StatusNotFound, "")
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}

				log.Printf("could not read info: %s", err)
				logRequest(req, http.StatusInternalServerError, "")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			defer f.Close()

			var uploadInfo UploadInfo
			dec := json.NewDecoder(f)
			err = dec.Decode(&uploadInfo)
			if err != nil {
				log.Printf("could not decode upload info: %s", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			data, err := json.MarshalIndent(uploadInfo, "", "  ")
			if err != nil {
				log.Printf("could not marshal info: %s", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
			return
		}

		Stats.Count("visit")

		if req.URL.Query().Get("dl") == "false" {
			Stats.Count("visit-" + id)
			logRequest(req, http.StatusOK, "")
			filePart := ""
			if len(parts) == 3 {
				filePart = "/" + parts[2]
			}
			fmt.Fprintf(w, "%s/dl/%s%s", config.BaseURL, id, filePart)
			return
		}

		f, err := os.Open(path.Join(UploadsDir, id))
		if err != nil {
			if os.IsNotExist(err) {
				logRequest(req, http.StatusNotFound, "")
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			log.Printf("could not read file: %s", err)
			logRequest(req, http.StatusInternalServerError, "")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		logRequest(req, http.StatusOK, "")
		_, err = io.Copy(w, f)
		if err != nil {
			log.Printf("could not write response: %s", err)
		}

		Stats.Count("dl-" + id)
	})

	if config.AdminSecret != "" {
		http.HandleFunc("/stats", func(w http.ResponseWriter, req *http.Request) {
			username, password, ok := req.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="admin"`)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			if username != "admin" && password != config.AdminSecret {
				logRequest(req, http.StatusForbidden, "wrong username or password")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}

			uploadsRepo := NewDirectoryUploadsRepo(UploadsDir)
			uploads, err := uploadsRepo.List()
			if err != nil {
				logRequest(req, http.StatusInternalServerError, fmt.Sprintf("could not list uploads: %s", err))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			fmt.Fprintf(w, "%d visits, %d uploads\n", Stats.Get("visit"), Stats.Get("upload"))
			fmt.Fprintf(w, "%d rate limits\n", Stats.Get("rate-limit"))
			fmt.Fprintf(w, "%s received, %s written\n",
				formatBytes(int64(Stats.Get("bytes-received"))),
				formatBytes(int64(Stats.Get("bytes-written"))))
			fmt.Fprintln(w)

			for _, upload := range uploads {
				fmt.Fprintf(w, "- %s/dl/%s/%s (%s, %d views, %d downloads)\n", config.BaseURL, upload.ID, upload.FileName, formatBytes(upload.Size), Stats.Get("visit-"+upload.ID), Stats.Get("dl-"+upload.ID))
			}
			logRequest(req, http.StatusOK, "")
		})
	}

	http.HandleFunc("/validation.js", func(w http.ResponseWriter, req *http.Request) {
		http.ServeFile(w, req, "./validation.js")
	})

	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("Listening on %s", config.BaseURL)
	log.Fatal(srv.ListenAndServe())
}

func logRequest(req *http.Request, statusCode int, msg string) {
	ipHash := hashIP(req)

	query := req.URL.RawQuery
	if query != "" {
		query = "?" + query
	}

	log.Printf("%s %s%s %d - %s - User-Agent=%q IP-Hash=%s", req.Method, req.URL.Path, query, statusCode, msg, req.Header.Get("User-Agent"), ipHash)
}

func hashIP(req *http.Request) string {
	ip := req.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip, _, _ = net.SplitHostPort(req.RemoteAddr)
	}
	ipHash := sha256.New()
	ipHash.Write([]byte(ip))
	hash := fmt.Sprintf("%x", ipHash.Sum(nil))
	return hash
}

func formatBytes(bytes int64) string {
	switch {
	case bytes < 1024:
		return fmt.Sprintf("%db", bytes)
	case bytes < 1024*1024:
		return fmt.Sprintf("%dkb", bytes/1024)
	case bytes < 1024*1024*1024:
		if bytes%(1024*1024) == 0 {
			return fmt.Sprintf("%dmb", bytes/(1024*1024))
		}
		return fmt.Sprintf("%.1fmb", float64(bytes)/(1024*1024))
	default:
		if bytes%(1024*1024*1024) == 0 {
			return fmt.Sprintf("%dgb", bytes/(1024*1024*1024))
		}
		return fmt.Sprintf("%.1fgb", float64(bytes)/(1024*1024*1024))
	}
}

type UploadsRepository interface {
	List() ([]UploadInfo, error)
	GetInfo(id string) (*UploadInfo, error)
}

func NewDirectoryUploadsRepo(uploadsDirectory string) UploadsRepository {
	return &directoryUploadsRepo{directory: uploadsDirectory}
}

type directoryUploadsRepo struct {
	directory string
}

func (ur *directoryUploadsRepo) List() ([]UploadInfo, error) {
	dir, err := os.Open(ur.directory)
	if err != nil {
		return nil, fmt.Errorf("could not open uploads directory: %s", err)
	}

	files, err := dir.Readdir(-1)
	if err != nil {
		return nil, fmt.Errorf("could not list uploads: %s", err)
	}

	uploads := make([]UploadInfo, 0, len(files)/2)
	for _, fi := range files {
		if !strings.HasSuffix(fi.Name(), "-info.json") {
			continue
		}

		id := fi.Name()[:(len(fi.Name()) - len("-info.json"))]
		info, err := ur.GetInfo(id)
		if err != nil {
			return nil, fmt.Errorf("could not read info for %s: %s", id, err)
		}
		if info == nil {
			return nil, fmt.Errorf("could not find info for %s: %s", id, err)
		}

		stat, err := os.Lstat(path.Join(ur.directory, id))
		if err != nil {
			return nil, fmt.Errorf("could not lstat %s: %s", id, err)
		}
		info.Size = stat.Size()

		uploads = append(uploads, *info)
	}

	return uploads, nil
}

func (ur *directoryUploadsRepo) GetInfo(id string) (*UploadInfo, error) {
	f, err := os.Open(path.Join(ur.directory, id+"-info.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("could not open info: %s", err)
	}
	defer f.Close()

	var uploadInfo UploadInfo
	dec := json.NewDecoder(f)
	err = dec.Decode(&uploadInfo)
	if err != nil {
		return nil, fmt.Errorf("could not decode upload info: %s", err)
	}

	return &uploadInfo, nil
}

// RateLimiter limits something to be allowed only every duration.
type RateLimiter struct {
	visits      map[string]time.Time
	maxIDs      int
	minDuration time.Duration
	mu          sync.Mutex
}

func NewRateLimiter(minDuration time.Duration, maxIDs int) *RateLimiter {
	return &RateLimiter{
		visits:      make(map[string]time.Time, maxIDs),
		maxIDs:      maxIDs,
		minDuration: minDuration,
	}
}

func (rl *RateLimiter) IsLimited(id string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	lastVisit := rl.visits[id]
	timeSinceLast := time.Now().Sub(lastVisit)
	if timeSinceLast < rl.minDuration {
		return true
	}

	if len(rl.visits) > rl.maxIDs {
		for key := range rl.visits {
			if key != id {
				delete(rl.visits, key)
				break
			}
		}
	}

	rl.visits[id] = time.Now()
	return false

}

type ByNameCounter struct {
	countsByName map[string]int
	maxCounts    int
	mu           sync.Mutex
}

func NewByNameCounter(maxCounts int) *ByNameCounter {
	return &ByNameCounter{
		countsByName: make(map[string]int, maxCounts),
		maxCounts:    maxCounts,
	}
}

func (c *ByNameCounter) Count(name string) {
	c.Add(name, 1)
}

func (c *ByNameCounter) Add(name string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.countsByName) > c.maxCounts {
		for key := range c.countsByName {
			if key != name {
				delete(c.countsByName, key)
				break
			}
		}
	}

	c.countsByName[name] += n
}

func (c *ByNameCounter) Get(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.countsByName[name]
}
