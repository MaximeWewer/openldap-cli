package ldapx

import "testing"

func TestRollbackRunsOnlyWhilePending(t *testing.T) {
	ran := 0
	done := DeferRollback(func() { ran++ })

	if !HasPendingRollbacks() {
		t.Fatal("HasPendingRollbacks = false right after registering one")
	}
	// the interrupt path: the undo runs
	RunRollbacks()
	if ran != 1 {
		t.Errorf("RunRollbacks ran the undo %d times, want 1", ran)
	}
	if HasPendingRollbacks() {
		t.Error("rollback still pending after RunRollbacks")
	}
	// and it does not run twice
	RunRollbacks()
	if ran != 1 {
		t.Errorf("undo ran again on the second RunRollbacks: %d", ran)
	}
	done()
}

func TestRollbackUnregisters(t *testing.T) {
	ran := 0
	done := DeferRollback(func() { ran++ })

	// the normal path: the caller's own defer reverted, so the registration goes
	done()
	if HasPendingRollbacks() {
		t.Error("rollback still pending after done()")
	}
	RunRollbacks()
	if ran != 0 {
		t.Errorf("undo ran %d times after being unregistered, want 0", ran)
	}
}
