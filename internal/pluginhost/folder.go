// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

// Limits on a plugin's folder (the folder.read permission): a listing names
// at most MaxFolderFiles files, and one read takes a file of at most
// MaxFolderRead bytes.
const (
	MaxFolderFiles = 10000
	MaxFolderRead  = 1 << 20
)

// Folder is the one folder vpnw opens for a plugin with the folder.read
// permission. The plugin can list the files directly in it and read them,
// and nothing else: no subfolders, nothing outside it, no writing.
type Folder interface {
	List() ([]FolderEntry, error)
	Read(name string) ([]byte, error)
	Close() error
}

// FolderEntry is one file in a plugin's folder.
type FolderEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// DirFolder is a folder on disk, opened so that nothing in it can lead
// outside it: a link to a file elsewhere is not followed.
type DirFolder struct {
	root *os.Root
	Dir  string
}

// OpenFolder opens dir for a plugin to read.
func OpenFolder(dir string) (*DirFolder, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", dir)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &DirFolder{root: r, Dir: dir}, nil
}

// List names the regular files directly in the folder, a link to one in the
// folder included, in name order, with their sizes.
func (f *DirFolder) List() ([]FolderEntry, error) {
	d, err := f.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	ents, err := d.ReadDir(MaxFolderFiles + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(ents) > MaxFolderFiles {
		return nil, fmt.Errorf("the folder has more than %d entries", MaxFolderFiles)
	}
	var out []FolderEntry
	for _, e := range ents {
		name := e.Name()
		if !folderName(name) {
			continue
		}
		// Stat follows a link only while it stays inside the folder.
		st, err := f.root.Stat(name)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		out = append(out, FolderEntry{Name: name, Size: st.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Read reads one regular file directly in the folder, of at most
// MaxFolderRead bytes.
func (f *DirFolder) Read(name string) ([]byte, error) {
	if !folderName(name) {
		return nil, fmt.Errorf("%q is not the name of a file in the folder", clean(name, 100))
	}
	// Non-blocking, so a named pipe can't hold the plugin up; it is refused
	// below as not a regular file.
	fh, err := f.root.OpenFile(name, os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return nil, folderErr(name, err)
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, folderErr(name, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if st.Size() > MaxFolderRead {
		return nil, fmt.Errorf("%s is %d bytes, over the %d-byte limit for one read", name, st.Size(), MaxFolderRead)
	}
	b, err := io.ReadAll(io.LimitReader(fh, MaxFolderRead+1))
	if err != nil {
		return nil, folderErr(name, err)
	}
	if len(b) > MaxFolderRead {
		return nil, fmt.Errorf("%s grew past the %d-byte limit for one read", name, MaxFolderRead)
	}
	return b, nil
}

// Close closes the folder.
func (f *DirFolder) Close() error { return f.root.Close() }

// folderName accepts the name of one entry in the folder, nothing that
// could reach another: no separators, no "." or "..", and printable.
func folderName(n string) bool {
	return n != "" && n != "." && n != ".." && len(n) <= 255 && utf8.ValidString(n) &&
		!strings.ContainsAny(n, "/\\\x00") && clean(n, 255) == n
}

// folderErr says what went wrong without the folder's full path.
func folderErr(name string, err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%s: no such file in the folder", name)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%s: permission denied", name)
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %v", name, pe.Err)
	}
	return fmt.Errorf("%s: %v", name, err)
}
