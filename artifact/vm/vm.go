package vm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	ext4 "github.com/masahiro331/go-ext4-filesystem/pkg"
	"github.com/masahiro331/go-vmdk-parser/pkg/virtualization/vmdk"
	"github.com/opencontainers/go-digest"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"
)

const (
	parallel = 10
)

type Artifact struct {
	dir      string
	cache    cache.ArtifactCache
	analyzer analyzer.Analyzer
}

func NewArtifact(dir string, c cache.ArtifactCache, disabled []analyzer.Type) artifact.Artifact {
	return Artifact{
		dir:      dir,
		cache:    c,
		analyzer: analyzer.NewAnalyzer(disabled),
	}
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	var wg sync.WaitGroup
	result := new(analyzer.AnalysisResult)
	limit := semaphore.NewWeighted(parallel)
	// TODO: scan virtual machine image

	image, err := os.Open(a.dir)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to open image file: %w", err)
	}
	reader, err := vmdk.NewReader(image)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to open vmdk file: %w", err)
	}

	for {
		partition, err := reader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return types.ArtifactReference{}, xerrors.Errorf("failed to read partition: %w", err)
		}

		if !partition.Bootable() {
			ext4Reader, err := ext4.NewReader(reader)
			if err != nil {
				return types.ArtifactReference{}, xerrors.Errorf("failed to open ext4 file: %w", err)
			}
			for {
				file, err := ext4Reader.Next()
				if err != nil {
					if err == io.EOF {
						break
					}
					return types.ArtifactReference{}, xerrors.Errorf("failed to open file in ext4: %w", err)
				}
				if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, file.FilePath(), file, readerOnceOpener(ext4Reader)); err != nil {
					return types.ArtifactReference{}, xerrors.Errorf("analyze file (%s): %w", file.FilePath(), err)
				}
			}
		}
	}

	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		OS:            result.OS,
		PackageInfos:  result.PackageInfos,
		Applications:  result.Applications,
		Configs:       result.Configs,
	}

	h := sha256.New()
	if err := json.NewEncoder(h).Encode(blobInfo); err != nil {
		return types.ArtifactReference{}, err
	}

	d := digest.NewDigest(digest.SHA256, h)
	diffID := d.String()
	blobInfo.DiffID = diffID
	versionedDiffID := cache.WithVersionSuffix(diffID, a.analyzer.AnalyzerVersions())

	if err := a.cache.PutBlob(versionedDiffID, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", diffID, err)
	}

	// get hostname
	var hostName string
	b, err := ioutil.ReadFile(filepath.Join(a.dir, "etc", "hostname"))
	if err == nil && string(b) != "" {
		hostName = strings.TrimSpace(string(b))
	} else {
		hostName = a.dir
	}

	return types.ArtifactReference{
		Name:    hostName,
		ID:      versionedDiffID, // use diffID as pseudo artifactID
		BlobIDs: []string{versionedDiffID},
	}, nil
}

func readerOnceOpener(r io.Reader) func() ([]byte, error) {
	var once sync.Once
	var b []byte
	var err error

	return func() ([]byte, error) {
		once.Do(func() {
			b, err = ioutil.ReadAll(r)
		})
		if err != nil {
			return nil, xerrors.Errorf("unable to read file: %w", err)
		}
		return b, nil
	}
}
