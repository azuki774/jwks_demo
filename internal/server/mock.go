package server

// MockFileOperator は FileOperator インターフェースのモック実装です。
type MockFileOperator struct {
	ErrLoadTxtFile  error
	ErrGetFileNames error
}

// LoadTxtFile はモックの LoadTxtFileFunc を呼び出します。
// もし LoadTxtFileFunc が設定されていなければ、エラーを返します。
func (m *MockFileOperator) LoadTxtFile(filePath string) ([]byte, error) {
	if m.ErrLoadTxtFile != nil {
		return nil, m.ErrLoadTxtFile
	}
	return []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwYDYgYnwhxMfR9hE7isN1rWHubXvEW1EJ/gYirMuxyY=
-----END PUBLIC KEY-----
`), nil
}

// GetFileNames はモックの GetFileNamesFunc を呼び出します。
// もし GetFileNamesFunc が設定されていなければ、エラーを返します。
func (m *MockFileOperator) GetFileNames(dirPath string) ([]string, error) {
	if m.ErrGetFileNames != nil {
		return nil, m.ErrGetFileNames
	}

	return []string{"files/public/key-001.pem", "files/public/key-002.pem"}, nil
}
