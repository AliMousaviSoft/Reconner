package capture

import (
	"slices"
	"testing"
)

// A multipart/form-data capture (the shape a real file-upload request always
// has) must suggest file_upload testing -- otherwise a captured upload
// endpoint gives the operator no hint that Guided Analyze can attack it.
func TestSuggestedTestsFlagsMultipartAsFileUpload(t *testing.T) {
	got := SuggestedTests(Request{
		Method:   "POST",
		URL:      "https://app.example.test/api/avatar",
		MimeType: "multipart/form-data; boundary=----ReconTestBoundary",
		Body:     []byte("ignored for suggestion purposes"),
	})
	if !slices.Contains(got, "file_upload") {
		t.Fatalf("SuggestedTests(multipart request) = %v, want it to contain file_upload", got)
	}
}

func TestSuggestedTestsDoesNotFlagOrdinaryJSONAsFileUpload(t *testing.T) {
	got := SuggestedTests(Request{
		Method:   "POST",
		URL:      "https://app.example.test/api/orders",
		MimeType: "application/json",
		Body:     []byte(`{"id":1}`),
	})
	if slices.Contains(got, "file_upload") {
		t.Fatalf("SuggestedTests(plain JSON request) = %v, must not contain file_upload", got)
	}
}
