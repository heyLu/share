package upload

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

type Info struct {
	ID           string    `json:"id"`
	FileName     string    `json:"filename"`
	ContentType  string    `json:"content-type"`
	DateUploaded time.Time `json:"date-uploaded"`

	Size            int64  `json:"-"`
	ContentFileName string `json:"-"`
}

type Repo interface {
	List() ([]Info, error)
	GetInfo(id string) (*Info, error)
}

func NewDirectoryRepo(uploadsDirectory string) Repo {
	return &directoryRepo{directory: uploadsDirectory}
}

type directoryRepo struct {
	directory string
}

func (ur *directoryRepo) List() ([]Info, error) {
	dir, err := os.Open(ur.directory)
	if err != nil {
		return nil, fmt.Errorf("could not open uploads directory: %s", err)
	}

	files, err := dir.Readdir(-1)
	if err != nil {
		return nil, fmt.Errorf("could not list uploads: %s", err)
	}

	uploads := make([]Info, 0, len(files)/2)
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

		info.ContentFileName = path.Join(ur.directory, id)

		uploads = append(uploads, *info)
	}

	return uploads, nil
}

func (ur *directoryRepo) GetInfo(id string) (*Info, error) {
	f, err := os.Open(path.Join(ur.directory, id+"-info.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("could not open info: %s", err)
	}
	defer f.Close()

	var uploadInfo Info
	dec := json.NewDecoder(f)
	err = dec.Decode(&uploadInfo)
	if err != nil {
		return nil, fmt.Errorf("could not decode upload info: %s", err)
	}

	return &uploadInfo, nil
}

type Logger interface {
	Printf(format string, args ...interface{})
}

func Deduplicate(repo Repo, logger Logger) error {
	uploads, err := repo.List()
	if err != nil {
		return fmt.Errorf("could not list uploads: %s", err)
	}

	// maps sha256 hash to matching filenames
	hashes := make(map[string][]string, len(uploads))
	for i, upload := range uploads {
		calculateSHA := func(fileName string) (string, error) {
			f, err := os.Open(fileName)
			if err != nil {
				return "", fmt.Errorf("could not open %q: %s", fileName, err)
			}
			defer f.Close()

			hash := sha256.New()
			_, err = io.Copy(hash, f)
			if err != nil {
				return "", fmt.Errorf("could not calculate sha256 for %q: %s", fileName, err)
			}

			return fmt.Sprintf("%x", hash.Sum(nil)), nil
		}

		if logger != nil {
			logger.Printf("%02d/%02d: calculating sha for %q (%d bytes)", i, len(uploads), upload.ContentFileName, upload.Size)
		}

		hash, err := calculateSHA(upload.ContentFileName)
		if err != nil {
			return err
		}

		_, ok := hashes[hash]
		if ok {
			hashes[hash] = append(hashes[hash], upload.ContentFileName)
		} else {
			hashes[hash] = []string{upload.ContentFileName}
		}
	}

	for hash, files := range hashes {
		if len(files) == 1 {
			continue
		}

		if logger != nil {
			logger.Printf("found %d duplicates with hash %q: %s", len(files), hash, files)
		}

		keep := files[0]

		for _, link := range files[1:] {
			if logger != nil {
				logger.Printf("removing %q (to replace with link)", link)
			}
			err := os.Remove(link)
			if err != nil {
				return fmt.Errorf("could not remove %q: %s", link, err)
			}

			if logger != nil {
				logger.Printf("linking %q to %q", link, keep)
			}
			err = os.Symlink(path.Base(keep), link)
			if err != nil {
				return fmt.Errorf("could not link %q to %q: %s", link, keep, err)
			}
		}
	}

	return nil
}
