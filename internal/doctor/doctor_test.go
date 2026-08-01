package doctor

import (
	"context"
	"errors"
	"testing"

	"github.com/vlyl/opssh/internal/app"
	securefs "github.com/vlyl/opssh/internal/filesystem"
	"github.com/vlyl/opssh/internal/process"
)

type missingResolver struct{}

func (missingResolver) Resolve(process.Tool) (string, error) { return "", errors.New("missing") }

func TestDoctorProducesCompleteStructuredBaseline(t *testing.T) {
	t.Parallel()

	layout, err := securefs.NewLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repository, err := app.NewRepository(layout)
	if err != nil {
		t.Fatal(err)
	}
	service := &app.Service{Repository: repository}
	findings := (Doctor{Service: service, Resolver: missingResolver{}}).Run(context.Background())
	if len(findings) < 24 {
		t.Fatalf("doctor returned %d findings, want at least 24", len(findings))
	}
	for _, finding := range findings {
		if finding.Code == "" || finding.Level == "" || finding.Message == "" {
			t.Fatalf("incomplete finding: %#v", finding)
		}
	}
}
