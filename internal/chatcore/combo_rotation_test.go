package chatcore

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// firstTried drives one HandleCombo round with an always-200 tryOne and
// reports which model was attempted first (the rotation head).
func firstTried(s *Service, models []string, comboName string, sticky int) string {
	first := ""
	resp := s.HandleCombo(context.Background(), ChatRequest{}, models, comboName, "round-robin", sticky,
		func(ctx context.Context, req ChatRequest, modelStr string) *http.Response {
			if first == "" {
				first = modelStr
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("{}")),
			}
		})
	if resp == nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	return first
}

func TestResetComboRotationByName(t *testing.T) {
	s := NewService(Service{})
	models := []string{"a/m1", "b/m2", "c/m3"}

	if got := firstTried(s, models, "combo-a", 1); got != "a/m1" {
		t.Fatalf("first head = %q, want a/m1", got)
	}
	if got := firstTried(s, models, "combo-a", 1); got != "b/m2" {
		t.Fatalf("rotated head = %q, want b/m2", got)
	}
	// A second combo keeps independent state.
	if got := firstTried(s, models, "combo-b", 1); got != "a/m1" {
		t.Fatalf("combo-b head = %q, want a/m1", got)
	}

	// Resetting one combo must not touch the other.
	s.ResetComboRotation("combo-a")
	if got := firstTried(s, models, "combo-a", 1); got != "a/m1" {
		t.Fatalf("after reset head = %q, want a/m1", got)
	}
	if got := firstTried(s, models, "combo-b", 1); got != "b/m2" {
		t.Fatalf("combo-b head after sibling reset = %q, want b/m2 (untouched)", got)
	}
}

func TestResetAllComboRotation(t *testing.T) {
	s := NewService(Service{})
	models := []string{"a/m1", "b/m2"}

	_ = firstTried(s, models, "combo-a", 1)
	_ = firstTried(s, models, "combo-b", 1)
	s.ResetAllComboRotation()
	if got := firstTried(s, models, "combo-a", 1); got != "a/m1" {
		t.Fatalf("combo-a head after reset-all = %q, want a/m1", got)
	}
	if got := firstTried(s, models, "combo-b", 1); got != "a/m1" {
		t.Fatalf("combo-b head after reset-all = %q, want a/m1", got)
	}
	// Empty name is the JS no-argument form: also clears all.
	_ = firstTried(s, models, "combo-a", 1)
	s.ResetComboRotation("")
	if got := firstTried(s, models, "combo-a", 1); got != "a/m1" {
		t.Fatalf("combo-a head after empty-name reset = %q, want a/m1", got)
	}
}

func TestResetComboRotationZeroValueService(t *testing.T) {
	s := &Service{}                  // no NewService: rotation is nil
	s.ResetComboRotation("anything") // must not panic
	s.ResetAllComboRotation()
	var nilSvc *Service
	nilSvc.ResetComboRotation("x") // must not panic
}
