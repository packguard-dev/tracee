package payload

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"path/filepath"

	enry "github.com/go-enry/go-enry/v2"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

// FileClassification holds detected payload file category and type.
type FileClassification struct {
	Category string
	Type     string
}

// Classify detects whether artifact content is an executable or script.
// Returns empty fields when content is empty or type cannot be determined.
func Classify(path string, content []byte) FileClassification {
	if len(content) == 0 {
		return FileClassification{}
	}

	if cat, typ := detectELF(content); typ != "" {
		return FileClassification{Category: cat, Type: typ}
	}
	if cat, typ := detectPE(content); typ != "" {
		return FileClassification{Category: cat, Type: typ}
	}

	if enry.IsBinary(content) {
		return FileClassification{
			Category: model.PayloadCategoryExecutable,
			Type:     model.PayloadTypeBinary,
		}
	}

	lang := enry.GetLanguage(filepath.Base(path), content)
	if lang == "" {
		return FileClassification{}
	}

	return FileClassification{
		Category: model.PayloadCategoryScript,
		Type:     mapEnryLanguage(lang),
	}
}

// ApplyClassification sets file category and type on info when detection succeeds.
func ApplyClassification(info *model.PayloadInfo, path string, content []byte) {
	if info == nil {
		return
	}
	c := Classify(path, content)
	if c.Category == "" {
		return
	}
	info.FileCategory = c.Category
	info.FileType = c.Type
}

func detectELF(content []byte) (string, string) {
	if len(content) < 4 || content[0] != 0x7f || content[1] != 'E' || content[2] != 'L' || content[3] != 'F' {
		return "", ""
	}
	if _, err := elf.NewFile(bytes.NewReader(content)); err != nil {
		return "", ""
	}
	return model.PayloadCategoryExecutable, model.PayloadTypeELF
}

func detectPE(content []byte) (string, string) {
	if len(content) < 2 || content[0] != 'M' || content[1] != 'Z' {
		return "", ""
	}
	f, err := pe.NewFile(bytes.NewReader(content))
	if err != nil {
		return "", ""
	}

	typ := model.PayloadTypePE
	if f.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		typ = model.PayloadTypeDLL
	}
	return model.PayloadCategoryExecutable, typ
}

func mapEnryLanguage(lang string) string {
	switch lang {
	case "Python":
		return model.PayloadTypePython
	case "JavaScript":
		return model.PayloadTypeJavaScript
	case "Shell":
		return model.PayloadTypeBash
	default:
		return lang
	}
}
