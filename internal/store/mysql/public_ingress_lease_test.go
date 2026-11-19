package mysql_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	driver "github.com/go-sql-driver/mysql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	mysqlstore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/mysql"
)

type ingressFixtureAuth struct{}

func (ingressFixtureAuth) Authenticate(context.Context, http.Header, string, string, []byte, bool, bool) (store.Relationship, error) {
	return store.Relationship{PeerID: leaseMaster, Direction: "downstream", State: "active", Protocol: protocol.Version}, nil
}

func ingressFixtureRequest(path string, generation int64) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	r.Host = "public.test"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("X-Fc-Public-Hop", "1")
	r.Header.Set("X-Fc-Public-Version", "1")
	r.Header.Set("X-Fc-Public-Ingress", leaseMaster)
	r.Header.Set("X-Fc-Public-Generation", fmt.Sprint(generation))
	r.Header.Set("X-Fc-Public-Origin", leaseOrigin)
	r.Header.Set("X-Fc-Public-Client-Ip", "192.0.2.10")
	return r
}

const (
	leaseMaster   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	leasePeer     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	leaseRelation = "cccccccccccccccccccccccccccccccc"
	leaseOrigin   = "https://public.test"
)

func ingressMySQLConfig(t *testing.T) mysqlstore.Config {
	t.Helper()
	host := os.Getenv("FRONTIERCLOUD_MYSQL_INGRESS_HOST")
	if host == "" {
		t.Skip("isolated MySQL ingress fixture is not configured")
	}
	database := os.Getenv("FRONTIERCLOUD_MYSQL_INGRESS_DATABASE")
	if !strings.HasPrefix(database, "fc_ingress_") || os.Getenv("FRONTIERCLOUD_MYSQL_INGRESS_PASSWORD_FILE") == "" {
		t.Fatal("isolated ingress fixture database and password file required")
	}
	return mysqlstore.Config{Host: host, Port: 3306, Database: database, User: os.Getenv("FRONTIERCLOUD_MYSQL_INGRESS_USER"), PasswordFile: os.Getenv("FRONTIERCLOUD_MYSQL_INGRESS_PASSWORD_FILE")}
}

func ingressMySQLOpen(t *testing.T, config mysqlstore.Config) (*mysqlstore.Store, store.PublicRoutingRepository) {
	t.Helper()
	db, err := mysqlstore.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := db.Nodes().(store.PublicRoutingRepository)
	if err := repo.ConfigurePublicOrigin(leaseOrigin); err != nil {
		t.Fatal(err)
	}
	return db, repo
}

// Invoked by the parent test against the same isolated database. Killing this
// process must release the transaction and its cross-process shared row lock.
func TestMySQLIngressLeaseChild(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_MYSQL_INGRESS_CHILD") != "1" {
		return
	}
	_, repo := ingressMySQLOpen(t, ingressMySQLConfig(t))
	_, release, err := repo.AcquireCurrentIngress(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release.Release()
	fmt.Println("MYSQL_INGRESS_LEASE_HELD")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func TestMySQLIngressLease(t *testing.T) {
	ctx := context.Background()
	config := ingressMySQLConfig(t)
	db, repo := ingressMySQLOpen(t, config)
	var count int
	if err := db.Database().QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()").Scan(&count); err != nil || count != 0 {
		t.Fatalf("fixture must use a fresh isolated database: tables=%d err=%v", count, err)
	}
	if err := db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: leaseMaster, Role: "Standalone", PrivateKey: "sealed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://control.test", Allocation: store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	relation := store.Relationship{ID: leaseRelation, PeerID: leasePeer, Endpoint: "https://peer.test", PublicKey: strings.Repeat("A", 43), Credential: "sealed", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: time.Now().Unix()}
	if err := db.Nodes().PrepareRelationship(ctx, relation, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().ActivateRelationship(ctx, relation.ID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	other, otherRepo := ingressMySQLOpen(t, config)
	memberBefore, err := other.Pool().MemberConfiguration(ctx, leasePeer)
	if err != nil {
		t.Fatal(err)
	}
	db.Database().SetMaxOpenConns(4)
	other.Database().SetMaxOpenConns(4)
	start := make(chan struct{})
	type initialResult struct {
		value store.PublicIngress
		err   error
	}
	initials := make(chan initialResult, 4)
	for _, candidate := range []store.PublicRoutingRepository{repo, otherRepo, repo, otherRepo} {
		go func(candidate store.PublicRoutingRepository) {
			<-start
			value, err := candidate.PublicIngress(ctx)
			initials <- initialResult{value, err}
		}(candidate)
	}
	close(start)
	var initial store.PublicIngress
	for range 4 {
		result := <-initials
		if result.err != nil || result.value.NodeID != leaseMaster || result.value.Generation != 1 {
			t.Fatal("concurrent initialization", result)
		}
		if initial.Generation != 0 && initial != result.value {
			t.Fatal("inconsistent initialization", initial, result.value)
		}
		initial = result.value
	}

	// Independent pools can simultaneously hold readers, while normal business
	// transactions continue and every authority-changing path waits.
	first, releaseFirst, err := repo.AcquireCurrentIngress(ctx)
	if err != nil || first != initial {
		t.Fatal(first, err)
	}
	second, releaseSecond, err := otherRepo.AcquireCurrentIngress(ctx)
	if err != nil || second != initial {
		releaseFirst.Release()
		t.Fatal(second, err)
	}
	t.Cleanup(releaseFirst.Release)
	t.Cleanup(releaseSecond.Release)
	checks := []func(context.Context) error{
		func(c context.Context) error {
			_, e := repo.ConfirmNativeTransport(c, leaseMaster, "Direct", 0, store.NodeAudit{})
			return e
		},
		func(c context.Context) error {
			_, e := otherRepo.ConfirmNativeTransport(c, leasePeer, "Relay", 0, store.NodeAudit{})
			return e
		},
		func(c context.Context) error {
			_, e := repo.CommitMasterPublicIngress(c, leaseOrigin, 1, store.NodeAudit{})
			return e
		},
		func(c context.Context) error {
			_, e := repo.CommitMasterPublicIngress(c, leaseOrigin, 1, store.NodeAudit{})
			return e
		},
		func(c context.Context) error {
			_, e := otherRepo.CommitMasterPublicIngress(c, leaseOrigin, 1, store.NodeAudit{})
			return e
		},
		func(c context.Context) error {
			return other.Nodes().RevokeRelationship(c, leaseRelation, false, store.NodeAudit{})
		},
		func(c context.Context) error {
			configuration := store.ResourceConfiguration{}
			configuration.Storage.Enabled, configuration.Storage.Allocation = true, 2*store.GiB
			return other.Pool().ConfigureMember(c, leasePeer, configuration, store.NodeAudit{})
		},
		func(c context.Context) error {
			_, e := other.Pool().(store.RetirementFenceRepository).BeginRetirement(c, leaseRelation, leasePeer, store.NodeAudit{})
			return e
		},
		func(c context.Context) error {
			_, e := other.Pool().(store.RetirementFenceRepository).CompleteRetirement(c, leaseRelation, leasePeer, store.NodeAudit{})
			return e
		},
		func(c context.Context) error {
			_, e := other.Nodes().ResetIdentity(c, leaseMaster, "Master", store.NodeIdentity{ID: strings.Repeat("d", 32), Role: "Standalone", PrivateKey: "sealed"}, store.NodeAudit{})
			return e
		},
	}
	results := make(chan error, len(checks))
	for _, check := range checks {
		go func(check func(context.Context) error) {
			blocked, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
			defer cancel()
			results <- check(blocked)
		}(check)
	}
	work, cancelWork := context.WithTimeout(ctx, 3*time.Second)
	_, err = db.Database().ExecContext(work, "UPDATE cluster_storage_members SET updated_at=updated_at WHERE member_id=?", leaseMaster)
	cancelWork()
	if err != nil {
		t.Fatal("ordinary business write blocked by ingress readers", err)
	}
	for range checks {
		if err := <-results; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("authority change bypassed shared lease: %v", err)
		}
	}
	releaseFirst.Release()
	releaseSecond.Release()
	releaseSecond.Release()
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 2*store.GiB
	if err := other.Pool().ConfigureMember(ctx, leasePeer, configuration, store.NodeAudit{}); err != nil {
		t.Fatal("member configuration did not resume after ingress readers", err)
	}
	if err := other.Pool().ConfigureMember(ctx, leasePeer, memberBefore, store.NodeAudit{}); err != nil {
		t.Fatal("restore member configuration", err)
	}
	policy, err := repo.ConfirmNativeTransport(ctx, leaseMaster, "Direct", 0, store.NodeAudit{})
	if err != nil || policy.Revision != 1 {
		t.Fatal("policy did not proceed after admitted readers", policy, err)
	}
	selected, err := otherRepo.CommitMasterPublicIngress(ctx, leaseOrigin, 1, store.NodeAudit{})
	if err != nil || selected.Generation != 2 {
		t.Fatal(selected, err)
	}
	if _, err := repo.CommitMasterPublicIngress(ctx, leaseOrigin, 1, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("stale generation accepted", err)
	}

	// Cancellation of an admitted request does not release authority before its
	// handler unwinds. A blocked acquisition is promptly cancellable.
	request, cancelRequest := context.WithCancel(ctx)
	_, release, err := repo.AcquireCurrentIngress(request)
	if err != nil {
		t.Fatal(err)
	}
	rowTx, err := other.Database().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var singleton int
	err = rowTx.QueryRowContext(ctx, "SELECT singleton FROM public_ingress_config WHERE singleton=1 FOR UPDATE NOWAIT").Scan(&singleton)
	if rollbackErr := rowTx.Rollback(); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	var lockError *driver.MySQLError
	if !errors.As(err, &lockError) || lockError.Number != 3572 {
		t.Fatal("direct change bypassed row lock", err)
	}
	cancelRequest()
	blocked, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	_, err = otherRepo.CommitMasterPublicIngress(blocked, leaseOrigin, 2, store.NodeAudit{})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cancellation dropped a live handler's fence", err)
	}
	release.Release()
	rowTx, err = other.Database().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rowTx.QueryRowContext(ctx, "SELECT singleton FROM public_ingress_config WHERE singleton=1 FOR UPDATE").Scan(&singleton); err != nil {
		_ = rowTx.Rollback()
		t.Fatal(err)
	}
	blocked, cancel = context.WithTimeout(ctx, 200*time.Millisecond)
	_, pendingRelease, err := repo.AcquireCurrentIngress(blocked)
	cancel()
	if err := rowTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(err, context.DeadlineExceeded) || pendingRelease != nil {
		t.Fatal("blocked reader did not cancel", err)
	}

	// A crashed process cannot strand its database transaction.
	child := exec.Command(os.Args[0], "-test.run=^TestMySQLIngressLeaseChild$", "-test.timeout=20s")
	child.Env = append(os.Environ(), "FRONTIERCLOUD_MYSQL_INGRESS_CHILD=1")
	child.Stderr = os.Stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	})
	ready := make(chan bool, 1)
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if s.Text() == "MYSQL_INGRESS_LEASE_HELD" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child failed to acquire lease")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child lease timed out")
	}
	blocked, cancel = context.WithTimeout(ctx, 200*time.Millisecond)
	_, err = repo.CommitMasterPublicIngress(blocked, leaseOrigin, 2, store.NodeAudit{})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cross-process fence bypassed", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	afterCrash, err := repo.CommitMasterPublicIngress(ctx, leaseOrigin, 2, store.NodeAudit{})
	if err != nil || afterCrash.Generation != 3 {
		t.Fatal("crashed process stranded lease", afterCrash, err)
	}

	// Inject a server-side disconnect of the exact connection holding the
	// shared row lock. Selection then wins before the suspended handler returns;
	// its buffered cookie and envelope must never reach the client.
	db.Database().SetMaxIdleConns(0)
	other.Database().SetMaxIdleConns(0)
	verifier, err := publicproxy.NewVerifier(publicproxy.VerifierConfig{MasterOrigin: "https://master.test", Authenticator: ingressFixtureAuth{}, Current: repo})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	proceed := make(chan struct{})
	resume := sync.OnceFunc(func() { close(proceed) })
	defer resume()
	response := make(chan *httptest.ResponseRecorder, 1)
	secured := verifier.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "frontiercloud_browser_crypto=must-not-escape")
		_, _ = w.Write([]byte("must-not-escape-envelope"))
		close(entered)
		<-proceed
	}))
	go func() {
		w := httptest.NewRecorder()
		secured.ServeHTTP(w, ingressFixtureRequest("/api/v1/media/crypto/session", 3))
		response <- w
	}()
	select {
	case <-entered:
	case w := <-response:
		t.Fatal("handler rejected before acquiring lease", w.Code, w.Body.String())
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not enter with lease")
	}
	var lockedConnection int64
	if err := other.Database().QueryRow("SELECT ID FROM information_schema.processlist WHERE DB=DATABASE() AND ID<>CONNECTION_ID()").Scan(&lockedConnection); err != nil || lockedConnection <= 0 {
		t.Fatal("cannot identify isolated lease connection", err, lockedConnection)
	}
	type selectionResult struct {
		ingress store.PublicIngress
		err     error
	}
	selectedAfterDisconnect := make(chan selectionResult, 1)
	go func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		item, e := otherRepo.CommitMasterPublicIngress(c, leaseOrigin, 3, store.NodeAudit{})
		selectedAfterDisconnect <- selectionResult{item, e}
	}()
	select {
	case result := <-selectedAfterDisconnect:
		t.Fatal("selection bypassed live lease", result)
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := other.Database().Exec(fmt.Sprintf("KILL CONNECTION %d", lockedConnection)); err != nil {
		t.Fatal("kill lease connection", err)
	}
	var disconnected selectionResult
	select {
	case disconnected = <-selectedAfterDisconnect:
	case <-time.After(5 * time.Second):
		t.Fatal("selection did not proceed after disconnect")
	}
	if disconnected.err != nil || disconnected.ingress.Generation != 4 {
		t.Fatal("selection after disconnect", disconnected)
	}
	resume()
	select {
	case w := <-response:
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "must-not-escape") || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("disconnected lease leaked authorization", w.Code, w.Header(), w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("disconnected handler did not finish")
	}
	// A new pooled connection can admit the new generation after the failure.
	reconnected := httptest.NewRecorder()
	verifier.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("new-generation")) })).ServeHTTP(reconnected, ingressFixtureRequest("/api/v1/media/crypto/session", 4))
	if reconnected.Code != http.StatusOK || reconnected.Body.String() != "new-generation" {
		t.Fatal("reconnect failed", reconnected.Code, reconnected.Body.String())
	}

	// A playback admitted before selection may finish afterward. A fresh request
	// from its old generation is rejected; playback itself has durable deduping.
	playEntered, playFinish := make(chan struct{}), make(chan struct{})
	releasePlay := sync.OnceFunc(func() { close(playFinish) })
	defer releasePlay()
	playResponse := make(chan int, 1)
	playback := verifier.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(playEntered)
		<-playFinish
		w.WriteHeader(http.StatusNoContent)
	}))
	go func() {
		w := httptest.NewRecorder()
		playback.ServeHTTP(w, ingressFixtureRequest("/api/v1/media/playback", 4))
		playResponse <- w.Code
	}()
	select {
	case <-playEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("playback did not start")
	}
	newSelection, err := otherRepo.CommitMasterPublicIngress(ctx, leaseOrigin, 4, store.NodeAudit{})
	if err != nil || newSelection.Generation != 5 {
		t.Fatal("admitted playback blocked selection", newSelection, err)
	}
	releasePlay()
	select {
	case status := <-playResponse:
		if status != http.StatusNoContent {
			t.Fatal("playback did not drain", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("playback drain timed out")
	}
	stale := httptest.NewRecorder()
	playback.ServeHTTP(stale, ingressFixtureRequest("/api/v1/media/playback", 4))
	if stale.Code != http.StatusForbidden {
		t.Fatal("old generation accepted after selection", stale.Code)
	}
	afterCrash = newSelection

	// Audit failure rolls the selection back, including its generation.
	if _, err := db.Database().Exec("CREATE TRIGGER ingress_audit_failure BEFORE INSERT ON node_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit unavailable'"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CommitMasterPublicIngress(ctx, leaseOrigin, 5, store.NodeAudit{}); err == nil {
		t.Fatal("unaudited selection succeeded")
	}
	if _, err := db.Database().Exec("DROP TRIGGER ingress_audit_failure"); err != nil {
		t.Fatal(err)
	}
	still, err := repo.PublicIngress(ctx)
	if err != nil || still != afterCrash {
		t.Fatal("audit rollback changed ingress", still, err)
	}

	for _, tamper := range []struct{ column, value string }{{"node_id", leasePeer}, {"public_origin", "http://invalid.test"}} {
		if _, err := db.Database().Exec("UPDATE public_ingress_config SET "+tamper.column+"=? WHERE singleton=1", tamper.value); err != nil {
			t.Fatal(err)
		}
		if _, release, err := repo.AcquireCurrentIngress(ctx); err == nil || release != nil {
			t.Fatal("tampered ingress admitted", tamper, err)
		}
		if _, err := db.Database().Exec("UPDATE public_ingress_config SET node_id=?,public_origin=? WHERE singleton=1", leaseMaster, leaseOrigin); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Database().Exec("ALTER TABLE public_ingress_config ENGINE=MyISAM"); err != nil {
		t.Fatal(err)
	}
	if _, release, err := repo.AcquireCurrentIngress(ctx); !errors.Is(err, store.ErrNodeState) || release != nil {
		t.Fatal("nontransactional ingress admitted", err)
	}
	if _, err := repo.CommitMasterPublicIngress(ctx, leaseOrigin, 5, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("nontransactional ingress mutation admitted", err)
	}
	if _, err := db.Database().Exec("ALTER TABLE public_ingress_config ENGINE=InnoDB"); err != nil {
		t.Fatal(err)
	}

	// Repeated cancellation and concurrent readers leave no checked-out pooled
	// connections; queued readers consume no connection while waiting for a slot.
	var readers sync.WaitGroup
	for range 16 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			c, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			_, done, err := repo.AcquireCurrentIngress(c)
			if err != nil {
				t.Error(err)
				return
			}
			done.Release()
		}()
	}
	readers.Wait()
	if inUse := db.Database().Stats().InUse; inUse != 0 {
		t.Fatal("leaked pooled connections", inUse)
	}
	_, firstSlot, err := repo.AcquireCurrentIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, secondSlot, err := repo.AcquireCurrentIngress(ctx)
	if err != nil {
		firstSlot.Release()
		t.Fatal(err)
	}
	blocked, cancel = context.WithTimeout(ctx, 200*time.Millisecond)
	_, pendingRelease, err = repo.AcquireCurrentIngress(blocked)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || pendingRelease != nil {
		firstSlot.Release()
		secondSlot.Release()
		t.Fatal("reader capacity did not cancel", err)
	}
	if inUse := db.Database().Stats().InUse; inUse != 2 {
		firstSlot.Release()
		secondSlot.Release()
		t.Fatal("waiting reader used a connection", inUse)
	}
	firstSlot.Release()
	secondSlot.Release()
	if inUse := db.Database().Stats().InUse; inUse != 0 {
		t.Fatal("reader slots leaked connections", inUse)
	}
	if inUse := other.Database().Stats().InUse; inUse != 0 {
		t.Fatal("second pool leaked connections", inUse)
	}

	// The fixture explicitly opens the otherwise-closed peer gate to exercise
	// MySQL CAS and shared fencing without enabling it in the runtime.
	if err := db.Nodes().RecordHeartbeat(ctx, leaseRelation, true, 1, map[string]any{"public_ingress_candidate_origin": "https://candidate.test", "capabilities": []string{protocol.PublicIngressProxyCapability}}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	relation, err = db.Nodes().Relationship(ctx, leaseRelation)
	if err != nil {
		t.Fatal(err)
	}
	evidence := store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, PublicOrigin: "https://candidate.test", CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt, LastHeartbeat: relation.LastHeartbeat}
	peer := db.Nodes().(store.PeerIngressRepository)
	if _, err := peer.CommitPeerPublicIngress(ctx, evidence, 5, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("closed peer gate", err)
	}
	peer.EnablePeerIngress()
	otherPeer := other.Nodes().(store.PeerIngressRepository)
	otherPeer.EnablePeerIngress()
	_, held, err := repo.AcquireCurrentIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	peerResult := make(chan selectionResult, 1)
	go func() {
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		value, err := otherPeer.CommitPeerPublicIngress(wait, evidence, 5, store.NodeAudit{Actor: "fixture"})
		peerResult <- selectionResult{value, err}
	}()
	select {
	case result := <-peerResult:
		t.Fatal("peer selection bypassed admission", result)
	case <-time.After(200 * time.Millisecond):
	}
	if err := held.Commit(); err != nil {
		t.Fatal(err)
	}
	var peerSelected selectionResult
	select {
	case peerSelected = <-peerResult:
	case <-time.After(5 * time.Second):
		t.Fatal("peer selection did not proceed")
	}
	if peerSelected.err != nil || peerSelected.ingress.NodeID != leasePeer || peerSelected.ingress.Generation != 6 {
		t.Fatal("peer selection", peerSelected)
	}
	current, peerLease, err := repo.AcquireCurrentIngress(ctx)
	if err != nil || current != peerSelected.ingress {
		t.Fatal("peer admission", current, err)
	}
	peerLease.Release()
	if _, err := db.Database().Exec("UPDATE node_relationships SET credential=?,created_at=created_at+1 WHERE relationship_id=?", "replacement-fixture", relation.ID); err != nil {
		t.Fatal(err)
	}
	if _, lease, err := repo.AcquireCurrentIngress(ctx); !errors.Is(err, store.ErrNodeState) || lease != nil {
		t.Fatal("replacement relationship inherited ingress admission", err)
	}
	relation, err = db.Nodes().Relationship(ctx, leaseRelation)
	if err != nil {
		t.Fatal(err)
	}
	evidence.CredentialDigest = store.PeerCredentialDigest(relation.Credential)
	evidence.CreatedAt = relation.CreatedAt
	renewed, err := peer.CommitPeerPublicIngress(ctx, evidence, 6, store.NodeAudit{Actor: "fixture"})
	if err != nil || renewed.NodeID != leasePeer || renewed.Generation != 7 {
		t.Fatal("explicit relationship re-selection", renewed, err)
	}
	if _, lease, err := repo.AcquireCurrentIngress(ctx); err != nil {
		t.Fatal("re-selected relationship denied", err)
	} else {
		lease.Release()
	}
	if _, err := repo.ConfirmNativeTransport(ctx, leaseMaster, "Relay", 1, store.NodeAudit{}); err != nil {
		t.Fatal("policy update at peer ingress", err)
	}
	back, err := repo.CommitMasterPublicIngress(ctx, leaseOrigin, 7, store.NodeAudit{Actor: "fixture"})
	if err != nil || back.NodeID != leaseMaster || back.Generation != 8 {
		t.Fatal("explicit public ingress selection for Master", back, err)
	}
	// Restore the fixture's original offline condition before the independent
	// retirement assertions below; the peer selection test needed it online.
	if err := other.Nodes().RecordHeartbeat(ctx, leaseRelation, false, 0, nil, time.Now().Unix()+121); err != nil {
		t.Fatal("restore offline fixture", err)
	}

	ledger, err := other.Pool().(store.RetirementRepository).RetirementLedger(ctx, leaseRelation, leasePeer)
	if err != nil || ledger.DatabaseClear || !ledger.RequiresPhysicalVerification {
		t.Fatal("offline fixture must retain retirement blockers", ledger, err)
	}
	if _, err := other.Pool().(store.RetirementFenceRepository).BeginRetirement(ctx, leaseRelation, leasePeer, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("retirement bypassed its ledger", err)
	}
	if _, err := other.Pool().(store.RetirementFenceRepository).CompleteRetirement(ctx, leaseRelation, leasePeer, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("unfenced retirement completed", err)
	}
	if err := other.Nodes().RevokeRelationship(ctx, leaseRelation, false, store.NodeAudit{}); err != nil {
		t.Fatal("revocation did not proceed after drain", err)
	}
	if _, err := db.Nodes().ResetIdentity(ctx, leaseMaster, "Master", store.NodeIdentity{ID: strings.Repeat("d", 32), Role: "Standalone", PrivateKey: "sealed"}, store.NodeAudit{}); err != nil {
		t.Fatal("identity reset did not proceed", err)
	}
	if _, release, err := repo.AcquireCurrentIngress(ctx); err == nil || release != nil {
		t.Fatal("old ingress survived identity reset", err)
	}
}
