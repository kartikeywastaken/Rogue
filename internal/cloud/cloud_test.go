package cloud

import (
	"context"
	"testing"
)

func TestCloudGatesWithoutEnvAndRejectsInvalidArgs(t *testing.T) {
	t.Setenv("ROGUE_CLOUD", "")
	if _, err := EnumerateAWS(context.Background(), "us-east-1"); err == nil {
		t.Fatal("expected error when ROGUE_CLOUD is unset")
	}
	if _, err := CheckMetadataPosture(context.Background()); err == nil {
		t.Fatal("expected metadata check error when ROGUE_CLOUD is unset")
	}

	t.Setenv("ROGUE_CLOUD", "true")
	if _, err := EnumerateAWS(context.Background(), "--evil-flag"); err == nil {
		t.Fatal("expected flag injection rejection in region")
	}
	if _, err := EnumerateGCP(context.Background(), "proj;rm"); err == nil {
		t.Fatal("expected invalid character rejection in project")
	}
}
