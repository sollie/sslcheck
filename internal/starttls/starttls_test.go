package starttls

import "testing"

func TestInfer(t *testing.T) {
	want := map[int]string{
		25: "smtp", 587: "smtp", 143: "imap", 110: "pop3",
		465: "", 993: "", 995: "", 5061: "", 443: "", 0: "",
	}
	for port, proto := range want {
		if got := Infer(port); got != proto {
			t.Errorf("Infer(%d) = %q, want %q", port, got, proto)
		}
	}
}
