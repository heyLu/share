package upload

import (
	"encoding/json"
	"fmt"
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
	Size         int64     `json:"-"`
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
	defer dir.Close()

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
