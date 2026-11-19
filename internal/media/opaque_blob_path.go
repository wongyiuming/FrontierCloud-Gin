package media

import (
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// opaqueBlobParent pins each random-object directory separately. A symlink at
// any level is rejected, even when it points elsewhere inside the volume.
type opaqueBlobParent struct {
	roots []*os.Root
	names []string
}

func openOpaqueBlobParent(root *os.Root, blob string) (*opaqueBlobParent, error) {
	if root == nil || !ownedObjectID.MatchString(blob) {
		return nil, store.ErrNodeState
	}
	result := &opaqueBlobParent{roots: []*os.Root{root}, names: []string{"objects", blob[:2], blob[2:4]}}
	for _, name := range result.names {
		parent := result.roots[len(result.roots)-1]
		before, err := parent.Lstat(name)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			result.Close()
			return nil, store.ErrNodeState
		}
		next, err := parent.OpenRoot(name)
		if err != nil {
			result.Close()
			return nil, store.ErrNodeState
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(before, opened) {
			next.Close()
			result.Close()
			return nil, store.ErrNodeState
		}
		result.roots = append(result.roots, next)
	}
	if result.Check() != nil {
		result.Close()
		return nil, store.ErrNodeState
	}
	return result, nil
}

func (p *opaqueBlobParent) Check() error {
	if p == nil || len(p.roots) != len(p.names)+1 {
		return store.ErrNodeState
	}
	for i, name := range p.names {
		current, err := p.roots[i].Lstat(name)
		if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 {
			return store.ErrNodeState
		}
		opened, err := p.roots[i+1].Stat(".")
		if err != nil || !os.SameFile(current, opened) {
			return store.ErrNodeState
		}
	}
	return nil
}

func (p *opaqueBlobParent) Leaf() *os.Root { return p.roots[len(p.roots)-1] }
func (p *opaqueBlobParent) Close() {
	if p == nil {
		return
	}
	for i := len(p.roots) - 1; i > 0; i-- {
		_ = p.roots[i].Close()
	}
	p.roots = nil
}
