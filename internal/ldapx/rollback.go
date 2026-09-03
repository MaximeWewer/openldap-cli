package ldapx

import "sync"

// Some operations put the server in a temporary state that a deferred function
// undoes: searchEscalated widens a size limit for the length of one search, for
// instance. A deferred function does not run when the process is signalled, so
// a Ctrl-C at the wrong moment leaves that state behind - in cn=config, where
// nothing will ever clean it up.
//
// Pending registers those undo functions so the signal handler in cmd can run
// them before exiting. SIGKILL and a power cut are still unrecoverable; this
// covers the interruption an operator actually causes, which is Ctrl-C on a
// long-running dump.
var pending = struct {
	sync.Mutex
	next int
	fns  map[int]func()
}{fns: map[int]func(){}}

// DeferRollback registers undo to run if the process is interrupted, and
// returns the function that unregisters it once the normal path has run it.
// Use it alongside a defer, never instead of one:
//
//	done := ldapx.DeferRollback(func() { _ = revert() })
//	defer func() { done(); revert() }()
func DeferRollback(undo func()) (done func()) {
	pending.Lock()
	id := pending.next
	pending.next++
	pending.fns[id] = undo
	pending.Unlock()

	return func() {
		pending.Lock()
		delete(pending.fns, id)
		pending.Unlock()
	}
}

// RunRollbacks runs and clears every pending rollback. The signal handler calls
// it on the way out; it is a no-op when nothing is pending.
func RunRollbacks() {
	pending.Lock()
	fns := make([]func(), 0, len(pending.fns))
	for id, fn := range pending.fns {
		fns = append(fns, fn)
		delete(pending.fns, id)
	}
	pending.Unlock()

	for _, fn := range fns {
		fn()
	}
}

// HasPendingRollbacks reports whether an interruption right now would leave
// server-side state behind.
func HasPendingRollbacks() bool {
	pending.Lock()
	defer pending.Unlock()
	return len(pending.fns) > 0
}
