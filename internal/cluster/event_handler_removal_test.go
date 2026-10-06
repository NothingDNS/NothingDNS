package cluster

import "testing"

// ptrKindHandler is a pointer-kind EventHandler, the shape every caller
// registered before the struct-kind case was handled.
type ptrKindHandler struct{ joins int }

func (p *ptrKindHandler) OnNodeJoin(*Node)        { p.joins++ }
func (p *ptrKindHandler) OnNodeLeave(*Node)       {}
func (p *ptrKindHandler) OnNodeUpdate(*Node)      {}
func (p *ptrKindHandler) OnCacheInvalid([]string) {}

// TestRemoveEventHandler_ValueKind pins that a struct-kind handler — the
// EventHandlerFunc value, whose four methods have value receivers and which
// therefore satisfies EventHandler on its own — can be registered and then
// removed.
//
// It used to panic. RemoveEventHandler compared handlers with
// reflect.ValueOf(h).Pointer(), and reflect.Value.Pointer is defined only for
// Chan, Func, Map, Ptr, Slice and UnsafePointer kinds; on a struct Value it
// panics with "reflect: call of reflect.Value.Pointer on struct Value". Every
// existing test registered a &EventHandlerFunc pointer, so the panic stayed
// latent.
func TestRemoveEventHandler_ValueKind(t *testing.T) {
	c := &Cluster{}

	h := EventHandlerFunc{OnJoinFunc: func(*Node) {}}
	c.AddEventHandler(h)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RemoveEventHandler panicked on a value-kind handler: %v", r)
		}
	}()

	c.RemoveEventHandler(h)

	if len(c.handlers) != 0 {
		t.Fatalf("value-kind handler not removed: %d handler(s) left", len(c.handlers))
	}
}

// TestRemoveEventHandler_PointerKind is the control: the pointer-kind path that
// every existing test exercises must keep working unchanged.
func TestRemoveEventHandler_PointerKind(t *testing.T) {
	c := &Cluster{}

	h := &ptrKindHandler{}
	c.AddEventHandler(h)
	c.RemoveEventHandler(h)

	if len(c.handlers) != 0 {
		t.Fatalf("pointer-kind handler not removed: %d handler(s) left", len(c.handlers))
	}
}

// TestRemoveEventHandler_ValueKindRemovesOnlyTheMatch guards the boundary the
// fix must not cross: removing one handler must not take its neighbours with
// it. Two distinct EventHandlerFunc values differ by their func code pointer,
// so identity has to be field-wise rather than "first struct wins".
func TestRemoveEventHandler_ValueKindRemovesOnlyTheMatch(t *testing.T) {
	c := &Cluster{}

	first := EventHandlerFunc{OnJoinFunc: func(*Node) {}}
	second := EventHandlerFunc{OnJoinFunc: func(*Node) {}}
	tail := &ptrKindHandler{}

	c.AddEventHandler(first)
	c.AddEventHandler(second)
	c.AddEventHandler(tail)

	c.RemoveEventHandler(second)

	if len(c.handlers) != 2 {
		t.Fatalf("expected 2 handlers after removing the middle one, got %d", len(c.handlers))
	}
	if _, ok := c.handlers[0].(EventHandlerFunc); !ok {
		t.Errorf("handler[0] should still be the first EventHandlerFunc, got %T", c.handlers[0])
	}
	if _, ok := c.handlers[1].(*ptrKindHandler); !ok {
		t.Errorf("handler[1] should still be the pointer handler, got %T", c.handlers[1])
	}
}

// TestRemoveEventHandler_UnknownHandlerIsNoOp pins that removing something
// that was never registered leaves the slice untouched — the lookup must not
// match on a different dynamic type.
func TestRemoveEventHandler_UnknownHandlerIsNoOp(t *testing.T) {
	c := &Cluster{}

	c.AddEventHandler(EventHandlerFunc{OnJoinFunc: func(*Node) {}})
	c.AddEventHandler(&ptrKindHandler{})

	// Different dynamic type entirely.
	c.RemoveEventHandler(&ptrKindHandler{})

	if len(c.handlers) != 2 {
		t.Fatalf("removing an unregistered handler changed the slice: %d handler(s) left", len(c.handlers))
	}
}

// TestSameEventHandler covers the identity helper directly, including the
// nil-handler and mismatched-type edges that the switch guards.
func TestSameEventHandler(t *testing.T) {
	fn := func(*Node) {}

	tests := []struct {
		name string
		a, b EventHandler
		want bool
	}{
		{"same pointer", &ptrKindHandler{}, &ptrKindHandler{}, false}, // distinct allocations
		{"same pointer value", nil, nil, false},                       // filled in below
		{"struct same func", EventHandlerFunc{OnJoinFunc: fn}, EventHandlerFunc{OnJoinFunc: fn}, true},
		{"struct all nil", EventHandlerFunc{}, EventHandlerFunc{}, true},
		{"struct different func", EventHandlerFunc{OnJoinFunc: fn}, EventHandlerFunc{OnJoinFunc: func(*Node) {}}, false},
		{"different types", EventHandlerFunc{}, &ptrKindHandler{}, false},
		{"nil interfaces", nil, nil, false},
	}

	p := &ptrKindHandler{}
	tests[1] = struct {
		name string
		a, b EventHandler
		want bool
	}{"same pointer value", p, p, true}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameEventHandler(tc.a, tc.b); got != tc.want {
				t.Errorf("sameEventHandler(%T, %T) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
