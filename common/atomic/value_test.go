package atomic

import (
	"io"
	"os"
	"testing"
)

func TestTypedValue(t *testing.T) {
	{
		var v TypedValue[int]
		got, gotOk := v.LoadOk()
		if got != 0 || gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (0, false)", got, gotOk)
		}
		v.Store(1)
		got, gotOk = v.LoadOk()
		if got != 1 || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (1, true)", got, gotOk)
		}
	}

	{
		var v TypedValue[error]
		got, gotOk := v.LoadOk()
		if got != nil || gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (nil, false)", got, gotOk)
		}
		v.Store(io.EOF)
		got, gotOk = v.LoadOk()
		if got != io.EOF || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (EOF, true)", got, gotOk)
		}
		err := &os.PathError{}
		v.Store(err)
		got, gotOk = v.LoadOk()
		if got != err || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (%v, true)", got, gotOk, err)
		}
		v.Store(nil)
		got, gotOk = v.LoadOk()
		if got != nil || !gotOk {
			t.Fatalf("LoadOk = (%v, %v), want (nil, true)", got, gotOk)
		}
	}

	{
		c1, c2, c3 := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var v TypedValue[chan struct{}]
		if v.CompareAndSwap(c1, c2) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if v.CompareAndSwap(nil, c1) != true {
			t.Fatalf("CompareAndSwap = false, want true")
		}
		if v.CompareAndSwap(c2, c3) != false {
			t.Fatalf("CompareAndSwap = true, want false")
		}
		if v.CompareAndSwap(c1, c2) != true {
			t.Fatalf("CompareAndSwap = false, want true")
		}
	}
}
