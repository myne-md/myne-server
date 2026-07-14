// SPDX-License-Identifier: AGPL-3.0

// Command fetchtool downloads a release asset, verifies its SHA-256 against a
// pinned digest, and extracts a single binary from it (.bz2 or .zip). It exists
// so the Dockerfile can bundle sha256-pinned restic + rclone into the image
// WITHOUT apt/apk or a shell — the fetch stays deterministic (a digest mismatch
// aborts the build, so the repro-gate's two-build digest holds) and depends only
// on the Go stdlib already present in the pinned build image. Not part of the
// server binary; a build-time tool only.
//
// Usage: fetchtool <url> <sha256-hex> <bz2|zip> <zip-member-suffix> <out-path>
// For bz2 the member-suffix arg is ignored (the archive is a single stream).
package main

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 6 {
		fatalf("usage: fetchtool <url> <sha256> <bz2|zip> <zip-member-suffix> <out>")
	}
	url, wantSum, format, member, out := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]

	data, err := download(url)
	if err != nil {
		fatalf("download %s: %v", url, err)
	}
	sum := hex.EncodeToString(sha256Sum(data))
	if sum != wantSum {
		fatalf("sha256 mismatch for %s: got %s, want %s", url, sum, wantSum)
	}

	var bin []byte
	switch format {
	case "bz2":
		if bin, err = io.ReadAll(bzip2.NewReader(bytes.NewReader(data))); err != nil {
			fatalf("bunzip2 %s: %v", url, err)
		}
	case "zip":
		if bin, err = extractZip(data, member); err != nil {
			fatalf("unzip %s: %v", url, err)
		}
	default:
		fatalf("unknown format %q (want bz2|zip)", format)
	}
	if err := os.WriteFile(out, bin, 0o755); err != nil {
		fatalf("write %s: %v", out, err)
	}
}

func download(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec // url is a build-arg release asset, verified by sha256 below
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func extractZip(data []byte, memberSuffix string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, memberSuffix) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("no zip member ending in %q", memberSuffix)
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "fetchtool: "+format+"\n", a...)
	os.Exit(1)
}
