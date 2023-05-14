package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Config struct {
	DirsPath []string `json:"dirs_path"`
	HashAlgo string   `json:"hash_algo"`
}

type FileData struct {
	Path    string    `json:"path"`
	ModTime time.Time `json:"mod_time"`
	Size    int64     `json:"size"`
	Hash    []byte    `json:"hash"`
}

type Results struct {
	Files map[string]FileData `json:"files"`
}

func readConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	return config, err
}

func getHashFunc(hashAlgo string) (func() hash.Hash, error) {
	switch hashAlgo {
	case "md5":
		return md5.New, nil
	case "sha1":
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashAlgo)
	}
}

func calculateFileHash(path string, hashFunc func() hash.Hash, oldFileData FileData) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !oldFileData.ModTime.IsZero() && oldFileData.ModTime == info.ModTime() && oldFileData.Size == info.Size() {
		return oldFileData.Hash, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hash := hashFunc()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func processDirectory(dirPath string, results *Results, hashFunc func() hash.Hash, totalFiles *int, processedFiles *int, mutex *sync.Mutex) (map[string]FileData, error) {
	newFileData := make(map[string]FileData)

	err := filepath.Walk(dirPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Skip the results file
		if filepath.Base(path) == "results.json" {
			return nil
		}

		fileHash, err := calculateFileHash(path, hashFunc, results.Files[path])
		if err != nil {
			return err
		}

		fileData := FileData{
			Path:    path,
			ModTime: info.ModTime(),
			Size:    info.Size(),
			Hash:    fileHash,
		}

		newFileData[path] = fileData

		mutex.Lock()
		(*processedFiles)++
		fmt.Printf("Processed %d out of %d files in directory: %s\n", *processedFiles, *totalFiles, dirPath)
		mutex.Unlock()

		return nil
	})

	if err != nil {
		return nil, err
	}

	return newFileData, nil
}

func removeDuplicateFiles(dirPaths []string, hashFunc func() hash.Hash) error {
	hashToFileData := make(map[string][]FileData)

	for _, dirPath := range dirPaths {
		resultsFilePath := filepath.Join(dirPath, "results.json")
		results := Results{Files: make(map[string]FileData)}

		if _, err := os.Stat(resultsFilePath); err == nil {
			resultsFile, err := os.Open(resultsFilePath)
			if err != nil {
				return err
			}
			decoder := json.NewDecoder(resultsFile)
			err = decoder.Decode(&results)
			if err != nil {
				return err
			}
		}

		dirFileCount := 0
		filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
			if !d.IsDir() {
				dirFileCount++
			}
			return nil
		})

		processedFiles := 0
		newFileData, err := processDirectory(dirPath, &results, hashFunc, &dirFileCount, &processedFiles, &sync.Mutex{})
		if err != nil {
			return err
		}

		results.Files = newFileData

		resultsFile, err := os.Create(resultsFilePath)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(resultsFile)
		err = encoder.Encode(results)
		if err != nil {
			return err
		}

		for _, fileData := range results.Files {
			hash := hex.EncodeToString(fileData.Hash)
			hashToFileData[hash] = append(hashToFileData[hash], fileData)
		}
	}

	for _, files := range hashToFileData {
		if len(files) > 1 {
			// Find the latest file
			latestFile := files[0]
			for _, file := range files {
				if file.ModTime.After(latestFile.ModTime) {
					latestFile = file
				}
			}

			// Remove all other files
			for _, file := range files {
				if file.Path != latestFile.Path {
					fmt.Println("Removing file:", file.Path)
					if err := os.Remove(file.Path); err != nil {
						fmt.Println("Error removing file:", file.Path)
					}
				}
			}
		}
	}

	return nil
}

func main() {
	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	config, err := readConfig(configPath)
	if err != nil {
		fmt.Println("Error reading config:", err)
		return
	}

	hashFunc, err := getHashFunc(config.HashAlgo)
	if err != nil {
		fmt.Println("Error getting hash function:", err)
		return
	}

	if err := removeDuplicateFiles(config.DirsPath, hashFunc); err != nil {
		fmt.Println("Error removing duplicate files:", err)
		return
	}
}
