package fileoperator

import (
	"io"
	"os"
)

type FileOperator struct {
}

func NewFileOperator() *FileOperator {
	return &FileOperator{}
}

func (f *FileOperator) LoadTxtFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	b, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GetFileNames returns a list of file names in the specified directory.
func (f *FileOperator) GetFileNames(dirPath string) ([]string, error) {
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}
	var fileNames []string
	for _, file := range files {
		if !file.IsDir() {
			fileNames = append(fileNames, file.Name())
		}
	}
	return fileNames, nil
}
