package app

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vlyl/opssh/internal/config"
	"github.com/vlyl/opssh/internal/domain"
	securefs "github.com/vlyl/opssh/internal/filesystem"
	"github.com/vlyl/opssh/internal/security"
)

var (
	ErrConcurrentModification = errors.New("a managed file changed after the preview was created")
	ErrSensitiveManagedData   = errors.New("managed file content was rejected by the security policy")
)

type Repository struct {
	Layout       securefs.Layout
	configWriter *securefs.AtomicWriter
	sshWriter    *securefs.AtomicWriter
	stateWriter  *securefs.AtomicWriter
}

type FileChange struct {
	Path           string
	Data           []byte
	Mode           os.FileMode
	Delete         bool
	ExpectedDigest []byte
}

type fileSnapshot struct {
	change FileChange
	data   []byte
	mode   os.FileMode
	exists bool
	writer *securefs.AtomicWriter
}

func NewRepository(layout securefs.Layout) (*Repository, error) {
	configWriter, err := securefs.NewAtomicWriter(layout.ConfigDir)
	if err != nil {
		return nil, err
	}
	sshWriter, err := securefs.NewAtomicWriter(layout.SSHDir)
	if err != nil {
		return nil, err
	}
	stateWriter, err := securefs.NewAtomicWriter(layout.StateDir)
	if err != nil {
		return nil, err
	}
	return &Repository{Layout: layout, configWriter: configWriter, sshWriter: sshWriter, stateWriter: stateWriter}, nil
}

func (repository *Repository) Ensure() error {
	return repository.Layout.Ensure()
}

func (repository *Repository) Load() (domain.Configuration, error) {
	_, _, exists, err := repository.configWriter.Read(repository.Layout.ConfigFile, config.MaxConfigBytes)
	if err != nil {
		return domain.Configuration{}, err
	}
	if !exists {
		return config.New(), nil
	}
	return config.LoadFile(repository.Layout.ConfigFile)
}

func (repository *Repository) Read(path string, limit int64) ([]byte, os.FileMode, bool, error) {
	writer, err := repository.writerFor(path)
	if err != nil {
		return nil, 0, false, err
	}
	data, mode, exists, err := writer.Read(path, limit)
	if err != nil {
		return nil, 0, false, err
	}
	if security.ContainsSensitiveMarker(data) {
		security.Wipe(data)
		return nil, 0, false, ErrSensitiveManagedData
	}
	return data, mode, exists, nil
}

func (repository *Repository) Apply(changes []FileChange) error {
	return repository.ApplyAndCheck(changes, nil)
}

func (repository *Repository) ApplyAndCheck(changes []FileChange, check func() error) error {
	if len(changes) == 0 {
		if check != nil {
			return check()
		}
		return nil
	}
	if err := repository.Ensure(); err != nil {
		return err
	}
	transactionLock := filepath.Join(repository.Layout.StateDir, "transaction.lock")
	return repository.stateWriter.WithLock(transactionLock, func() error {
		snapshots := make([]fileSnapshot, 0, len(changes))
		for _, change := range changes {
			writer, err := repository.writerFor(change.Path)
			if err != nil {
				return err
			}
			data, mode, exists, err := writer.Read(change.Path, 8<<20)
			if err != nil {
				return err
			}
			if change.ExpectedDigest != nil {
				digest := digestFor(data, exists)
				if !bytes.Equal(digest, change.ExpectedDigest) {
					return ErrConcurrentModification
				}
			}
			snapshots = append(snapshots, fileSnapshot{change: change, data: data, mode: mode, exists: exists, writer: writer})
		}
		for index, snapshot := range snapshots {
			var err error
			if snapshot.change.Delete {
				err = snapshot.writer.Remove(snapshot.change.Path)
			} else {
				_, err = snapshot.writer.Write(snapshot.change.Path, snapshot.change.Data, securefs.WriteOptions{Mode: snapshot.change.Mode, Backup: snapshot.exists})
			}
			if err != nil {
				rollbackErr := rollback(snapshots[:index+1])
				return errors.Join(fmt.Errorf("apply managed file transaction: %w", err), rollbackErr)
			}
		}
		if check != nil {
			if err := check(); err != nil {
				rollbackErr := rollback(snapshots)
				return errors.Join(fmt.Errorf("validate managed file transaction: %w", err), rollbackErr)
			}
		}
		return nil
	})
}

func (repository *Repository) writerFor(path string) (*securefs.AtomicWriter, error) {
	for _, writer := range []*securefs.AtomicWriter{repository.configWriter, repository.sshWriter, repository.stateWriter} {
		if writer.Owns(path) {
			return writer, nil
		}
	}
	return nil, securefs.ErrPathOutsideRoot
}

func rollback(snapshots []fileSnapshot) error {
	var rollbackErr error
	for index := len(snapshots) - 1; index >= 0; index-- {
		snapshot := snapshots[index]
		if snapshot.exists {
			if _, err := snapshot.writer.Write(snapshot.change.Path, snapshot.data, securefs.WriteOptions{Mode: snapshot.mode.Perm()}); err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
			}
		} else {
			if err := snapshot.writer.Remove(snapshot.change.Path); err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
			}
		}
	}
	if rollbackErr != nil {
		return fmt.Errorf("rollback managed file transaction: %w", rollbackErr)
	}
	return nil
}

func Digest(data []byte, exists bool) []byte {
	return digestFor(data, exists)
}

func digestFor(data []byte, exists bool) []byte {
	hash := sha256.New()
	if exists {
		_, _ = hash.Write([]byte{1})
	} else {
		_, _ = hash.Write([]byte{0})
	}
	_, _ = hash.Write(data)
	return hash.Sum(nil)
}
