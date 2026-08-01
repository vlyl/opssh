package filesystem

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrPathOutsideRoot = errors.New("path is outside the managed root")
	ErrUnsafePath      = errors.New("managed path contains a symlink or non-regular object")
)

type WriteOptions struct {
	Mode   os.FileMode
	Backup bool
}

type WriteResult struct {
	BackupPath string
}

type AtomicWriter struct {
	Root         string
	beforeRename func() error
}

func (writer *AtomicWriter) Owns(path string) bool {
	absPath, err := filepath.Abs(path)
	return err == nil && pathWithin(writer.Root, absPath) && absPath != writer.Root
}

func (writer *AtomicWriter) Read(path string, limit int64) ([]byte, os.FileMode, bool, error) {
	absPath, err := filepath.Abs(path)
	if err != nil || !writer.Owns(absPath) {
		return nil, 0, false, ErrPathOutsideRoot
	}
	if err := verifyPath(writer.Root, filepath.Dir(absPath)); err != nil {
		return nil, 0, false, err
	}
	return readRegularFileLimit(absPath, limit)
}

func (writer *AtomicWriter) Remove(path string) (returnErr error) {
	absPath, err := filepath.Abs(path)
	if err != nil || !writer.Owns(absPath) {
		return ErrPathOutsideRoot
	}
	if err := verifyPath(writer.Root, filepath.Dir(absPath)); err != nil {
		return err
	}
	lock, err := acquireLock(absPath + ".opssh.lock")
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, lock.Close())
	}()
	if err := verifyTarget(absPath); err != nil {
		return err
	}
	if err := os.Remove(absPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("remove managed file: %w", err)
	}
	return syncDirectory(filepath.Dir(absPath))
}

func (writer *AtomicWriter) WithLock(path string, action func() error) (returnErr error) {
	absPath, err := filepath.Abs(path)
	if err != nil || !writer.Owns(absPath) {
		return ErrPathOutsideRoot
	}
	if err := verifyPath(writer.Root, filepath.Dir(absPath)); err != nil {
		return err
	}
	lock, err := acquireLock(absPath)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, lock.Close())
	}()
	return action()
}

func (writer *AtomicWriter) OpenAppend(path string, mode os.FileMode, rotateAt int64) (*os.File, error) {
	absPath, err := filepath.Abs(path)
	if err != nil || !writer.Owns(absPath) {
		return nil, ErrPathOutsideRoot
	}
	if err := verifyPath(writer.Root, filepath.Dir(absPath)); err != nil {
		return nil, err
	}
	if err := verifyTarget(absPath); err != nil {
		return nil, err
	}
	if rotateAt <= 0 || rotateAt > 64<<20 {
		return nil, errors.New("log rotation limit is outside the supported range")
	}
	if info, statErr := os.Lstat(absPath); statErr == nil && info.Size() >= rotateAt {
		rotated := absPath + ".1"
		if targetInfo, targetErr := os.Lstat(rotated); targetErr == nil {
			if !targetInfo.Mode().IsRegular() || targetInfo.Mode()&os.ModeSymlink != 0 {
				return nil, ErrUnsafePath
			}
			if err := os.Remove(rotated); err != nil {
				return nil, fmt.Errorf("remove old rotated log: %w", err)
			}
		}
		if err := os.Rename(absPath, rotated); err != nil {
			return nil, fmt.Errorf("rotate managed log: %w", err)
		}
	}
	fd, err := unix.Open(absPath, unix.O_CREAT|unix.O_APPEND|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, uint32(mode.Perm()))
	if err != nil {
		return nil, fmt.Errorf("open managed append file: %w", err)
	}
	file := os.NewFile(uintptr(fd), absPath)
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrUnsafePath
	}
	if err := file.Chmod(mode.Perm()); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("restrict managed append file permissions: %w", err)
	}
	return file, nil
}

func NewAtomicWriter(root string) (*AtomicWriter, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil || root == "" {
		return nil, errors.New("invalid managed root")
	}
	return &AtomicWriter{Root: filepath.Clean(absRoot)}, nil
}

func (writer *AtomicWriter) Write(path string, data []byte, options WriteOptions) (result WriteResult, returnErr error) {
	if options.Mode == 0 {
		options.Mode = 0o600
	}
	if options.Mode.Perm()&0o022 != 0 {
		return WriteResult{}, errors.New("managed file mode must not be group or world writable")
	}
	absPath, err := filepath.Abs(path)
	if err != nil || !pathWithin(writer.Root, absPath) || absPath == writer.Root {
		return WriteResult{}, ErrPathOutsideRoot
	}
	if err := verifyPath(writer.Root, filepath.Dir(absPath)); err != nil {
		return WriteResult{}, err
	}
	if err := verifyTarget(absPath); err != nil {
		return WriteResult{}, err
	}

	lock, err := acquireLock(absPath + ".opssh.lock")
	if err != nil {
		return WriteResult{}, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, lock.Close())
	}()
	if err := verifyTarget(absPath); err != nil {
		return WriteResult{}, err
	}

	result = WriteResult{}
	if options.Backup {
		oldData, oldMode, exists, readErr := readRegularFile(absPath)
		if readErr != nil {
			return WriteResult{}, readErr
		}
		if exists {
			defer clearBytes(oldData)
			result.BackupPath = fmt.Sprintf("%s.opssh.bak.%d", absPath, time.Now().UTC().UnixNano())
			if err := writer.writePrepared(result.BackupPath, oldData, oldMode.Perm()); err != nil {
				return WriteResult{}, fmt.Errorf("create backup: %w", err)
			}
		}
	}
	if err := writer.writePrepared(absPath, data, options.Mode.Perm()); err != nil {
		return WriteResult{}, err
	}
	return result, nil
}

func (writer *AtomicWriter) writePrepared(path string, data []byte, mode os.FileMode) error {
	if err := verifyTarget(path); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".opssh-tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	defer cleanup()
	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary file permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if writer.beforeRename != nil {
		if err := writer.beforeRename(); err != nil {
			return fmt.Errorf("before atomic rename: %w", err)
		}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("atomic rename: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return nil
}

func verifyPath(root, target string) error {
	if !pathWithin(root, target) {
		return ErrPathOutsideRoot
	}
	current := root
	info, err := os.Lstat(current)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafePath
	}
	relative, _ := filepath.Rel(root, target)
	for _, part := range splitRelativePath(relative) {
		current = filepath.Join(current, part)
		info, err = os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafePath
		}
	}
	return nil
}

func verifyTarget(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafePath
	}
	return nil
}

func pathWithin(root, path string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && relative != ".." && !filepath.IsAbs(relative) && !startsWithParent(relative)
}

func startsWithParent(relative string) bool {
	return len(relative) > 3 && relative[:3] == ".."+string(filepath.Separator)
}

type fileLock struct {
	file *os.File
}

func acquireLock(path string) (*fileLock, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open file lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire file lock: %w", err)
	}
	return &fileLock{file: file}, nil
}

func (lock *fileLock) Close() error {
	fd := int(lock.file.Fd())
	unlockErr := unix.Flock(fd, unix.LOCK_UN)
	closeErr := lock.file.Close()
	return errors.Join(unlockErr, closeErr)
}

func readRegularFile(path string) ([]byte, os.FileMode, bool, error) {
	return readRegularFileLimit(path, 8<<20)
}

func readRegularFileLimit(path string, limit int64) ([]byte, os.FileMode, bool, error) {
	if limit <= 0 || limit > 64<<20 {
		return nil, 0, false, errors.New("read limit is outside the supported range")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, fmt.Errorf("open existing managed file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, 0, false, ErrUnsafePath
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, 0, false, fmt.Errorf("read existing managed file: %w", err)
	}
	if int64(len(data)) > limit {
		clearBytes(data)
		return nil, 0, false, errors.New("existing managed file exceeds size limit")
	}
	return data, info.Mode(), true, nil
}

func syncDirectory(path string) error {
	// #nosec G304 -- callers provide a verified managed parent directory.
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func clearBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
