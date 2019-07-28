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

var config struct {
	BaseURL string
	Secret  string
}

type UploadInfo struct {
	ID           string    `json:"id"`
	FileName     string    `json:"filename"`
	ContentType  string    `json:"content-type"`
	DateUploaded time.Time `json:"date-uploaded"`
}

func main() {
	addr := "localhost:9999"

	config.BaseURL = os.Getenv("BASE_URL")
	if config.BaseURL == "" {
		config.BaseURL = fmt.Sprintf("http://%s", addr)
	}

	secret, err := ioutil.ReadFile("upload-secret.txt")
	if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}
	config.Secret = strings.TrimSpace(string(secret))

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			logRequest(req, http.StatusBadRequest, "")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		errorMsg := req.URL.Query().Get("error")
		if errorMsg != "" {
			errorMsg = fmt.Sprintf(`<p id="error">Error: %s!</p>`, errorMsg)
		}

		secretInput := ""
		if config.Secret != "" {
			secretInput = `<input type="text" name="secret" placeholder="Key required for upload privileges..." />`
		}

		fmt.Fprintf(w, `
<!doctype html>
<html>
<head>
	<meta charset="utf-8" />
	<title>share</title>
	<style>
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

	<p>%s upload limit, files expire after 7 days.</p>

	<form method="POST" action="/up" enctype="multipart/form-data">
		%s
		<input id="file" type="file" name="file" />
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
		req.Body = http.MaxBytesReader(w, req.Body, MaxUploadSize + 1*MegaBytes)

		if req.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		if UploadsLimiter.IsLimited(hashIP(req)) {
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

		if config.Secret != req.FormValue("secret") {
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

		logRequest(req, http.StatusSeeOther, "")
		w.Header().Set("Location", fmt.Sprintf("/dl/%s/%s?dl=false", id, uploadInfo.FileName))
		w.WriteHeader(http.StatusSeeOther)
		fmt.Fprintf(w, "%s/dl/%s/%s", config.BaseURL, id, uploadInfo.FileName)
	})

	http.HandleFunc("/dl/", func(w http.ResponseWriter, req *http.Request) {
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

		if req.URL.Query().Get("dl") == "false" {
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
	})

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

// RateLimiter limits something to be allowed only every duration.
type RateLimiter struct {
	visits map[string]time.Time
	maxIDs int
	minDuration time.Duration
	mu sync.Mutex
}

func NewRateLimiter(minDuration time.Duration, maxIDs int) *RateLimiter {
	return &RateLimiter{
		visits: make(map[string]time.Time, maxIDs),
		maxIDs: maxIDs,
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
