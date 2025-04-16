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
