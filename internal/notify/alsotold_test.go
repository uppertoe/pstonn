package notify

import (
	"testing"
	"time"
)

// Each member's copy names everyone else the outcome reaches: the other
// members by their channel (held until quiet hours end where they are) and the
// rego's driver when they were emailed. The reader is never named, a driver who
// is also a member is named once, and a household of one gets no line at all.
func TestAlsoToldLine(t *testing.T) {
	six := time.Date(2026, 9, 18, 6, 0, 0, 0, time.UTC)
	jo := Recipient{Email: "jo@example.com", ByEmail: true}
	sam := Recipient{Email: "sam@example.com", ByEmail: true, ByPush: true, NotBefore: six}
	alex := Recipient{Email: "alex@example.com", ByPush: true}
	cases := []struct {
		name string
		rs   []Recipient
		self string
		o    ApplyOutcome
		want string
	}{
		{"alone", []Recipient{jo}, "jo@example.com", ApplyOutcome{}, ""},
		{"one other", []Recipient{jo, alex}, "jo@example.com", ApplyOutcome{},
			"\n\nWe have also told alex@example.com (by push notification)."},
		{"two others, one on quiet hours", []Recipient{jo, sam, alex}, "alex@example.com", ApplyOutcome{},
			"\n\nWe have also told jo@example.com (by email) and sam@example.com (by email and push notification, once their quiet hours end)."},
		{"driver", []Recipient{jo}, "jo@example.com", ApplyOutcome{Reg: "NAN123", DriverTold: "nanny@example.com"},
			"\n\nWe have also told nanny@example.com (by email, as the driver of NAN123)."},
		{"driver who is a member", []Recipient{jo, alex}, "jo@example.com", ApplyOutcome{Reg: "NAN123", DriverTold: "Alex@example.com"},
			"\n\nWe have also told alex@example.com (by push notification)."},
		{"the reader is the driver", []Recipient{jo}, "jo@example.com", ApplyOutcome{Reg: "NAN123", DriverTold: "jo@example.com"}, ""},
	}
	for _, c := range cases {
		if got := alsoToldLine(c.rs, c.self, c.o); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}
