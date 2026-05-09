# Rio → JGDMS / DirtyChai Migration Plan

**Purpose:** This document is the AI-agent context document for the work required to
update Rio to use the latest features in JGDMS and DirtyChai, and to lock it down
against DoS vectors.  It captures the full architectural analysis, every identified
code-level issue, and the ordered work plan.  Future agents should read this document
before starting any implementation work.

**Reference document:**
`pfirmstone/JGDMS` → `JGDMS/docs/Big picture security architecture/AI_Agent_JGDMS-GrantPermission-RoleManagement-context_8.md`

**Repository:** `pfirmstone/Rio`, branch `copilot/update-rio-dirtychai-jgdms`

---

## 1. Background — What JGDMS and DirtyChai Provide

### 1.1 DirtyChai — Custom JDK

DirtyChai is a fork of OpenJDK that provides:

| Feature | Class / API | Significance for Rio |
|---|---|---|
| Sealed Subject hierarchy | `WorkerSubject` (sealed, `SpiffeSubject` only), `UserSubject` (final, public) | `doAs(WorkerSubject,…)` throws `IllegalArgumentException`; must use `callAs` for user |
| Multi-subject `ScopedValue` | `SCOPED_SUBJECT ScopedValue<Subject[]>` | Per-request user identity; survives `doPrivileged` boundaries |
| `AccessController.getContext()` enrichment | Iterates `Subject[]`, bakes principals into `ProtectionDomain` array | User grants work transparently across `doPrivileged` |
| Thread Subject propagation | `Thread.scopedSubject` captured at construction; re-established in `runWith()` | Spawned threads inherit user identity automatically |
| Guard inventory | `LoadClassPermission`, `SerialObjectPermission`, `NativeInvocationPermission`, etc. | Granular permission model replaces coarse `RuntimePermission("*")` |
| `CombinerSecurityManager` | Recursion guard (depth 7) | Three-layer policy stack uses 3; headroom of 4 |

### 1.2 JGDMS — Jini Platform

JGDMS replaces Apache River 2.2.2 and provides:

| Feature | Description |
|---|---|
| `Startable` interface | `org.apache.river.api.util.Startable` — export happens after construction, not inside it |
| `AbstractJiniService` | Base class for all Jini services; uses `ReadyState`; implements `Startable`; handles JAAS / SPIFFE login |
| `@AtomicSerial` | Wire-safe serialization with public `(GetArg)` constructor; BAE rejects non-compliant proxies |
| Three-layer policy stack | `DynamicPolicyProvider` → `RemotePolicyProvider` → `SpiffePolicyFile` |
| `VerifyingProxyPreparer` | Replaces `BasicProxyPreparer`; enforces three-way grant intersection |
| `AdvisoryDynamicPermissions` | Interface on ClassLoader; reads `META-INF/PERMISSIONS.LIST` |
| `RemotePolicyService` | Five-method interface for runtime policy push from administrator |
| SPIFFE/SPIRE workload identity | `SpiffeCredentialManager`; `SpiffePolicyFile`; `SpiffeSubjectHolder` |
| `BasicInvocationDispatcher` wire limits | `MAX_USER_PRINCIPALS = 64`; `MAX_STRING_BYTES = 8192` |
| SCAP pipeline | Five-host: Lookup → BAE Pool → VerdictRegistry → Codebase Downloader → JFR Telemetry |
| `ProxyCodebaseSpi` / `VerdictRegistry` | Refuses `DANGEROUS`-verdicted JARs before ClassLoader creation |

---

## 2. Critical Bug: `this` Escaping During Construction

### 2.1 The Problem

**All three Rio service implementations export themselves from inside their
two-argument constructor**, via the call chain:

```
CybernodeImpl(String[] args, LifeCycle lc)          // constructor
  └── bootstrap(args)
        └── start(context)                           // ServiceBeanAdapter
              └── doStart(context)
                    └── exportDo(exporter)
                          └── exporter.export(this)  // THIS ESCAPES
```

The same pattern applies to `ProvisionMonitorImpl` and `EventCollectorImpl`.

`exporter.export(this)` makes `this` accessible to remote clients **before the
constructor has returned**.  This is a Java Memory Model (JMM) violation: the JMM does
not guarantee that other threads see a fully initialized object until a safe publication
point (final field assignment, `synchronized` block exit, or `volatile` write) occurs
after construction completes.  A remote call arriving between `export()` and the end of
the constructor body can observe an incompletely initialized object.

### 2.2 The JGDMS Solution — `Startable`

JGDMS defines `org.apache.river.api.util.Startable`:

```java
public interface Startable {
    /**
     * Called after construction.  Enables objects to delay starting threads
     * or exporting until after construction is complete, for JMM compliance.
     *
     * The implementation must be idempotent.
     */
    void start() throws Exception;
}
```

`AbstractJiniService` implements `Startable`.  Its constructor only reads
configuration and stores fields.  The actual export (`exporter.export(this)`)
happens inside `start()`, which is called by `NonActivatableServiceDescriptor`
(or `RioServiceDescriptor`) after the constructor returns.

`NonActivatableServiceDescriptor.create()` in JGDMS does:

```java
impl = constructor.newInstance(args, lifeCycle);   // construct only
if (impl instanceof Startable) {
    ((Startable) impl).start();                    // export happens here
}
```

### 2.3 What Rio Must Do

1. Add `org.apache.river.api.util.Startable` (or a Rio-local copy) to the codebase.
2. `ServiceBeanAdapter` (or its successor) must implement `Startable`.
3. Move all export and background-thread startup out of the two-arg constructor into
   `start()`.
4. The two-arg constructor must contain **only configuration reading** — no export, no
   `start(context)` call, no thread creation.
5. `RioServiceDescriptor.create()` must call `((Startable) impl).start()` after
   `constructor.newInstance(args, lifeCycle)`.

This is a prerequisite for all other areas of work because it eliminates the JMM
violation that could allow remote callers to see a partially constructed service.

---

## 3. Work Areas — Ordered by Dependency

### Area 1 — `Startable` + Fix `this` Escaping (Pre-requisite)

**Files affected:**

| File | Change |
|---|---|
| `rio-start/.../RioServiceDescriptor.java` | After `constructor.newInstance(args, lc)`, check `instanceof Startable` and call `start()` |
| `rio-core/rio-lib/.../ServiceBeanAdapter.java` | Implement `Startable`; move export and thread creation from two-arg constructor chain into `start()` |
| `rio-services/cybernode/.../CybernodeImpl.java` | Move `bootstrap(configArgs)` call from constructor to `start()`; constructor body becomes config-read only |
| `rio-services/monitor/.../ProvisionMonitorImpl.java` | Same as CybernodeImpl |
| `rio-services/event-collector/.../EventCollectorImpl.java` | Same as CybernodeImpl |

**Mechanics:**

```java
// BEFORE (current, broken)
public CybernodeImpl(String[] configArgs, LifeCycle lifeCycle) throws Exception {
    super();
    this.lifeCycle = lifeCycle;
    bootstrap(configArgs);          // ← export happens here, "this" escapes
}

// AFTER (fixed)
public CybernodeImpl(String[] configArgs, LifeCycle lifeCycle) throws Exception {
    super();
    this.lifeCycle = lifeCycle;
    this.configArgs = configArgs;   // store only; do not start
}

@Override
public void start() throws Exception {  // called by RioServiceDescriptor after construction
    bootstrap(configArgs);
}
```

`RioServiceDescriptor.create()` addition (after `impl = constructor.newInstance(...)`):

```java
if (impl instanceof Startable) {
    ((Startable) impl).start();
}
```

**ReadyState guard:** After implementing `Startable`, add a `ReadyState` guard (from
JGDMS or a local implementation) to `ServiceBeanAdapter`.  Service methods should
call `readyState.check()` at entry and `readyState.shutdown()` in `destroy()`.  This
ensures that remote calls arriving before `start()` completes are queued or rejected
cleanly rather than observing partially initialized state.

---

### Area 2 — Dependency Upgrade: River 2.2.2 → JGDMS

**Current state:** `pom.xml` pins `river.version=2.2.2` and uses `org.apache.river` /
`net.jini` artifacts.

**Required changes:**

1. Replace all `org.apache.river:*` / `net.jini:*` Maven coordinates with JGDMS
   equivalents (`au.net.zeus.jgdms:*`). JGDMS preserves `net.jini` package names
   internally.
2. Replace DirtyChai's JDK as the runtime JDK dependency. This enables:
   - `Subject.callAs()` with `UserSubject` / `WorkerSubject` routing
   - `SCOPED_SUBJECT ScopedValue<Subject[]>`
   - `AccessController.getContext()` domain enrichment
3. Update all `import com.sun.jini.*` to equivalent JGDMS / JGDMS-relocated packages.
4. Verify Groovy, SLF4J, JMX, Aether compatibility with the JGDMS platform BOM.

**Risk:** Most invasive change; all other areas depend on JGDMS being on the classpath.

---

### Area 3 — `doAsPrivileged` → `callAs` Migration

**Current state:** `ServiceBeanAdapter.java` line 247:
```java
Subject.doAsPrivileged(loginContext.getSubject(), doStart, null);
```

**Issues:**
- `doAsPrivileged` is deprecated in JGDMS/DirtyChai.
- JGDMS routing rule: `doAs` accepts only vanilla `Subject` and `null`; `UserSubject`
  must use `callAs`; `WorkerSubject` is rejected with `IllegalArgumentException`.
- Under the SPIFFE path (`loginContext == null`), the `WorkerSubject` is **ambient** —
  baked into every `ProtectionDomain` by `SecureClassLoader` at class load time.  No
  `doAs` / `callAs` wrapper is needed for the worker identity.

**Required changes:**

1. In `ServiceBeanAdapter.start()`, replace:
   ```java
   Subject.doAsPrivileged(loginContext.getSubject(), doStart, null);
   ```
   with:
   ```java
   Subject.callAs(loginContext.getSubject(), () -> {
       doStart(context);
       return null;
   });
   ```
2. SPIFFE path (`loginContext == null`): call `doStart(context)` directly.  No
   `callAs` wrapper needed; worker identity is ambient.
3. Executor-submitted tasks that must carry per-request user identity: capture
   `Subject.current()` before submission and wrap with
   `Subject.callAs(captured, () -> ...)`.
4. Daemon threads (sweeper, SPIRE watcher, log writer): must not be created from inside
   a `callAs` scope unless user identity propagation is intentional.

---

### Area 4 — Smart Proxy Serialization: `Serializable` → `@AtomicSerial`

**Current state:** `AbstractProxy`, `CybernodeProxy`, `ProvisionMonitorProxy`,
`EventCollectorBackend`, and all constrainable inner classes use plain
`java.io.Serializable` with `private void readObject(ObjectInputStream s)`.

**Issues identified (BAE will verdict `DANGEROUS`):**
- RULE-1 violation: no `@AtomicSerial` annotation
- RULE-2 violation: no public `(GetArg)` constructor
- RULE-3 violation: no static check method called before field assignment
- RULE-4 violation: no type-checked `GetArg.get()` calls
- RULE-5 violation: no `serialPersistentFields` / `serialForm()`
- RULE-6 violation: no static `serialize(PutArg, T)` method

**Files affected:**
- `rio-core/rio-proxy/src/main/java/org/rioproject/proxy/service/AbstractProxy.java`
- `rio-core/rio-proxy/src/main/java/org/rioproject/proxy/admin/ServiceAdminProxy.java`
- `rio-core/rio-proxy/src/main/java/org/rioproject/proxy/admin/ConstrainableServiceAdminProxy.java`
- `rio-services/cybernode/cybernode-proxy/src/main/java/org/rioproject/cybernode/proxy/CybernodeProxy.java`
  (incl. `ConstrainableCybernodeProxy` and `Verifier` inner classes)
- `rio-services/monitor/monitor-proxy/src/main/java/org/rioproject/monitor/proxy/ProvisionMonitorProxy.java`
- `rio-services/monitor/monitor-proxy/src/main/java/org/rioproject/monitor/proxy/ProvisionMonitorAdminProxy.java`
- `rio-services/event-collector/event-collector-proxy/src/main/java/org/rioproject/eventcollector/proxy/EventCollectorBackend.java`
- `rio-core/rio-proxy/src/main/java/org/rioproject/proxy/bean/BeanDelegator.java`
- `rio-core/rio-proxy/src/main/java/org/rioproject/proxy/bean/PackagedMethod.java`

**Pattern (using `AbstractProxy` as example):**

```java
@AtomicSerial
public abstract class AbstractProxy implements ReferentUuid, Service, Serializable {
    private static final long serialVersionUID = 2L;

    // RULE-5: serial form declaration
    private static final ObjectStreamField[] serialPersistentFields = {
        new ObjectStreamField("server", Remote.class),
        new ObjectStreamField("uuid",   Uuid.class),
    };

    final protected Remote server;
    final protected Uuid uuid;

    // RULE-2: public (GetArg) constructor
    public AbstractProxy(GetArg args) throws IOException, ClassNotFoundException {
        // RULE-3: static check BEFORE any field assignment
        check(args);
        this.server = (Remote) args.get("server", null);
        this.uuid   = (Uuid)   args.get("uuid",   null);
    }

    // RULE-3: static check method
    private static GetArg check(GetArg args) throws IOException, ClassNotFoundException {
        Remote server = (Remote) args.get("server", null);  // RULE-4: type-checked
        Uuid   uuid   = (Uuid)   args.get("uuid",   null);  // RULE-4: type-checked
        if (server == null) throw new InvalidObjectException("server is null");
        if (uuid   == null) throw new InvalidObjectException("uuid is null");
        return args;
    }

    // RULE-6: static serialize method
    public static void serialize(PutArg args, AbstractProxy proxy) throws IOException {
        args.put("server", proxy.server);
        args.put("uuid",   proxy.uuid);
        args.writeObject();
    }

    // RULE-5: serialForm()
    public static ObjectStreamField[] serialForm() {
        return serialPersistentFields;
    }

    // Existing constructor for local construction
    protected AbstractProxy(Remote server, Uuid uuid) {
        if (server == null) throw new IllegalArgumentException("server cannot be null");
        if (uuid   == null) throw new IllegalArgumentException("uuid cannot be null");
        this.server = server;
        this.uuid   = uuid;
    }
    // ... rest unchanged
}
```

**Note:** Without `@AtomicSerial` compliance, the JGDMS BAE will verdict all Rio proxy
JARs `DANGEROUS`, and JGDMS clients with `ProxyCodebaseSpi` integration will refuse to
load them.

---

### Area 5 — Policy Stack: Flat → Three-Layer + `VerifyingProxyPreparer`

**Current state:**
- `ServiceBeanLoader.java` uses `DynamicPolicyProvider(PolicyFileProvider)` + `LoaderSplitPolicyProvider` — Apache River two-layer stack only.
- `ServiceBeanLoader.java` line 370 uses `BasicProxyPreparer` — no advisory grants.
- `rio.policy` grants `RuntimePermission("*")` to `$RIO_HOME/-` and
  `SocketPermission("*:*","connect,accept")` to all code — unrestricted network access
  is a DoS and exfiltration vector.
- `rio-test.policy` grants `AllPermission` to all of `$RIO_HOME/-`, Maven local
  repo, and the HTTP codebase server.

**Required changes:**

1. **Service startup** (`ServiceBeanLoader.java`): Replace the two-layer policy with
   the three-layer stack:
   ```
   DynamicPolicyProvider
     └── RemotePolicyProvider     (pulls grants from InMemoryPolicyService)
           └── SpiffePolicyFile   (bootstrap: SPIRE socket + InMemoryPolicyService endpoint only)
   ```

2. **Proxy preparation** (`ServiceBeanLoader.java`): Replace `BasicProxyPreparer` with
   `VerifyingProxyPreparer`.  Pass `null` for explicit permissions (advisory path) so
   that `META-INF/PERMISSIONS.LIST` from each service JAR's ClassLoader is the grant
   source.  This enforces the three-way intersection:
   > declared permissions ∩ `GrantPermission` ceiling ∩ SPIFFE principal scope

3. **Add `META-INF/PERMISSIONS.LIST`** to Rio service JARs (Cybernode,
   ProvisionMonitor, EventCollector): declare the minimum required permissions.
   Each entry will be validated by the BAE — avoid `SocketPermission` (DoS risk),
   `RuntimePermission("*")` (too broad), `AllPermission` (never), or
   `PolicyPermission("Remote")` (administrative path — must never be delegatable).

4. **Tighten `distribution/src/main/policy/rio.policy`:**
   - Remove `grant { permission SocketPermission "*:*", "connect,accept"; }` — replace
     with named-host grants scoped to actual peers.
   - Remove `RuntimePermission("*")` from the `$RIO_HOME/-` codebase grant — enumerate
     specific runtime permissions.
   - Add principal-scoped grants (requiring SPIFFE + user principal) for administrative
     operations.

5. **Fix `distribution/src/main/policy/rio-test.policy`:**
   - Remove `AllPermission` from all codebase grants.
   - Replace with the minimum set of permissions required by each test codebase.
   - The HTTP codebase server grant (`http://${hostAddress}:9010/-`) must not have
     `AllPermission`.

6. **`SpiffePolicyFile` configuration:** Each Rio service's bootstrap policy grants
   access to the SPIRE socket and the `InMemoryPolicyService` endpoint only.  All other
   permissions come through `RemotePolicyProvider`.

---

### Area 6 — DoS Hardening: Bounded Thread Pools

**Current state:** At least 9 `Executors.newCachedThreadPool()` calls exist in
production service code:

| File | Pool name / purpose | DoS risk |
|---|---|---|
| `ServiceBeanLoader.java` | Static service-loading pool | New thread per service load |
| `ComputeResourcePolicyHandler.java` | Threshold event handler pool | New thread per SLA breach event |
| `CybernodeImpl.java` | `thresholdTaskPool` | New thread per threshold event |
| `ServiceProvisioner.java` | `provisioningPool` | New thread per service provision request |
| `ServiceProvisioner.java` | `provisionFailurePool` | New thread per provision failure |
| `ProvisionMonitorEventProcessor.java` | `monitorEventPool` | New thread per monitor event |
| `AbstractEventManager.java` | Event dispatch pool | New thread per event |
| `BasicEventConsumer.java` | Consumer dispatch pool | New thread per consumed event |
| `PooledFaultDetectionHandler.java` | Verify pool | New thread per FDH check |
| `DefaultAssociation.java` | Futures executor | New thread per association future |
| `QueuedReplicator.java` | Replication pool | New thread per replication task |
| `AetherResolver.java` | Resolver pool | New thread per resolution request |

An attacker who can trigger RMI calls or discovery events faster than they drain can
exhaust the JVM's thread budget.  With `newCachedThreadPool()`, each request creates a
new OS thread if no idle thread is available, with no upper bound.

Additionally, `ProvisionMonitorPeer` creates raw daemon threads (lines 132, 200, 442)
with `new Thread(...).start()` and no pool or bound.

**Required changes:**

1. Replace every `Executors.newCachedThreadPool()` with a bounded `ThreadPoolExecutor`.
   Use named `ThreadFactory` instances (e.g. `"Rio-Cybernode-ThresholdPool-%d"`) to aid
   diagnostics.

2. Recommended bounds per pool (configurable via Rio's `Configuration` API):

   | Pool | Default bound | Queue type | Reject policy |
   |---|---|---|---|
   | `ServiceBeanLoader` service pool | `serviceLimit` (default 500) | `LinkedBlockingQueue(serviceLimit)` | Caller-runs |
   | `ServiceProvisioner` provisioning pool | 10–50 (configurable) | `LinkedBlockingQueue(200)` | Caller-runs |
   | `ServiceProvisioner` failure pool | 10 | `LinkedBlockingQueue(100)` | Discard oldest + log |
   | `ProvisionMonitorEventProcessor` | 10 | `LinkedBlockingQueue(500)` | Caller-runs |
   | `AbstractEventManager` / `BasicEventConsumer` | 5 | `LinkedBlockingQueue(100)` | Discard + log WARNING |
   | `ComputeResourcePolicyHandler` / `CybernodeImpl` threshold pool | number of configured SLAs | `LinkedBlockingQueue(50)` | Discard oldest |
   | `PooledFaultDetectionHandler` | number of monitored services | `LinkedBlockingQueue(50)` | Caller-runs |
   | `DefaultAssociation` futures | 5 | `LinkedBlockingQueue(100)` | Caller-runs |
   | `QueuedReplicator` | 5 | `LinkedBlockingQueue(200)` | Caller-runs |
   | `AetherResolver` | 20 | `LinkedBlockingQueue(100)` | Caller-runs |

3. Replace the three `new Thread(...).start()` calls in `ProvisionMonitorPeer` with
   tasks submitted to the bounded provisioning pool or a single-threaded scheduled
   executor.

4. **Virtual thread readiness:** Under DirtyChai, `RuntimePermission("createVirtualThread")`
   is guarded.  Rio must not declare this permission in any `PERMISSIONS.LIST` — the BAE
   will flag the JAR `DANGEROUS` if it also detects a `<clinit>` path to a blocking sink
   (e.g. blocking socket read inside class initialization).

---

### Area 7 — BAE / VerdictRegistry Pipeline Integration (SCAP)

**Current state:** `ServiceBeanLoader` and `ResolvingLoader` create `PreferredClassLoader`
directly without consulting a `VerdictRegistry`.  Any JAR from any codebase is loaded
unconditionally.

**Required changes:**

1. Add a `VerdictRegistryHolder` (package-private `volatile` reference) to
   `ServiceBeanLoader`.  The registry is injected at service startup via a setter; the
   holder is null-safe at boot (boot-time permissive).

2. Before creating a `PreferredClassLoader`, hash each resolved JAR (SHA-256) and call
   `VerdictRegistry.getVerdictByHash(hash)`:
   - `DANGEROUS` or `null` (not yet audited): throw `IOException`, refuse to load.
   - `INCONCLUSIVE`: log `WARNING`, proceed.
   - `SAFE`: proceed silently.

3. Apply the same verdict check in `ResolvingLoader` for smart proxy JARs.

4. Document the boot-time permissive period: during service startup before a
   `VerdictRegistry` has been injected, the check is skipped.  Operators should inject
   the registry as early as possible.

---

### Area 8 — JERI Wire Limits (Auto-applied via Area 2)

**Current state:** Apache River's `BasicInvocationDispatcher` has no wire-level limits
on principal count or string length.  A malicious client can send a wire message with
an unbounded principal list or class-name string.

**Required changes:**

After upgrading to JGDMS JERI (Area 2), `BasicInvocationDispatcher` automatically
enforces:
- `MAX_USER_PRINCIPALS = 64`
- `MAX_STRING_BYTES = 8192`

**No separate Rio code change is needed for this.**  However:

- Export configuration in `CybernodeImpl` and `ProvisionMonitorImpl` should be updated
  to require `ClientAuthentication.YES` and `Integrity.YES` `MethodConstraints` on all
  service exports so that the JERI wire is not plain-text.
- Administrative methods (e.g. `deploy()`, `undeploy()`, `release()`, `enlist()`)
  should require `ServerAuthentication.YES` as well.

---

### Area 9 — Caller Identity in Service Methods

**Current state:** Rio service methods run without any knowledge of the authenticated
caller.  No authorization check is performed on administrative RPC calls.

**Required changes:**

1. In security-sensitive service methods of `CybernodeImpl`, `ProvisionMonitorImpl`,
   and `EventCollectorImpl`, retrieve caller identity:

   ```java
   // TLS-verified SPIFFE workload identity of the remote caller
   ClientSubject cs = (ClientSubject)
       ServerContext.getServerContextElement(ClientSubject.class);
   Subject workerSubject = cs != null ? cs.getClientSubject() : null;

   // Wire-asserted human identity (available for v0x02 JERI connections only)
   ClientUserSubject cus = (ClientUserSubject)
       ServerContext.getServerContextElement(ClientUserSubject.class);
   Subject userSubject = cus != null ? cus.getUserSubject() : null;
   ```

2. Authorize administrative operations by checking that the caller's
   `SpiffePrincipal` (in `workerSubject`) is in an allowed set.  Wire-asserted
   `userSubject` may be used for audit logging but must not be trusted for
   authorization without corresponding SPIFFE-level verification.

3. Reject requests whose worker SPIFFE identity is not in the trusted set for the
   operation (e.g. only `spiffe://…/monitor/admin` may call `deploy()`).

---

## 4. Implementation Sequencing

The areas above must be addressed in dependency order:

```
Area 1  (Startable + this-escape fix)      ← no dependencies; blocks Areas 3-9
Area 6  (Bounded thread pools)             ← independent; do in parallel with Area 1
Area 5  (Policy tightening)                ← independent; do in parallel with Area 1
Area 2  (JGDMS dependency upgrade)         ← after Area 1; blocks Areas 3-9
Area 3  (@AtomicSerial compliance)         ← after Area 2; blocks Area 7
Area 4  (callAs migration)                 ← after Area 2; requires DirtyChai JDK
Area 8  (Wire limits)                      ← automatically applied after Area 2
Area 7  (BAE/VerdictRegistry integration)  ← after Area 3 (proxies must be SAFE)
Area 9  (Caller identity)                  ← after Areas 2 and 4
```

---

## 5. Files Changed / To Be Changed — Master List

### Already changed (pre-migration)
*(none — this document defines the plan; no code has been changed yet)*

### To be changed

| File | Area(s) | Nature of change |
|---|---|---|
| `rio-start/.../RioServiceDescriptor.java` | 1 | Call `Startable.start()` after `newInstance()` |
| `rio-core/rio-lib/.../ServiceBeanAdapter.java` | 1, 3 | Implement `Startable`; move export to `start()`; `callAs` migration; `ReadyState` guard |
| `rio-services/cybernode/.../CybernodeImpl.java` | 1, 6, 9 | Constructor stores args only; `start()` calls `bootstrap()`; bound pool; caller-auth |
| `rio-services/monitor/.../ProvisionMonitorImpl.java` | 1, 6, 9 | Same pattern as CybernodeImpl; replace raw `new Thread()` in peer |
| `rio-services/event-collector/.../EventCollectorImpl.java` | 1, 6, 9 | Same pattern as CybernodeImpl |
| `rio-services/monitor/.../peer/ProvisionMonitorPeer.java` | 6 | Replace 3 `new Thread().start()` with bounded pool |
| `rio-services/monitor/.../ServiceProvisioner.java` | 6 | Replace 2 `newCachedThreadPool()` with bounded `ThreadPoolExecutor` |
| `rio-services/monitor/.../ProvisionMonitorEventProcessor.java` | 6 | Replace `newCachedThreadPool()` |
| `rio-services/event-collector/.../AbstractEventManager.java` | 6 | Replace `newCachedThreadPool()` |
| `rio-services/cybernode/.../ComputeResourcePolicyHandler.java` | 6 | Replace `newCachedThreadPool()` |
| `rio-core/rio-lib/.../impl/container/ServiceBeanLoader.java` | 5, 6, 7 | Three-layer policy; `VerifyingProxyPreparer`; bounded pool; `VerdictRegistry` check |
| `rio-core/rio-lib/.../impl/event/BasicEventConsumer.java` | 6 | Replace `newCachedThreadPool()` |
| `rio-core/rio-lib/.../impl/fdh/PooledFaultDetectionHandler.java` | 6 | Replace `newCachedThreadPool()` |
| `rio-core/rio-lib/.../impl/associations/DefaultAssociation.java` | 6 | Replace `newCachedThreadPool()` |
| `rio-core/rio-lib/.../impl/watch/QueuedReplicator.java` | 6 | Replace `newCachedThreadPool()` |
| `rio-core/rio-proxy/.../proxy/service/AbstractProxy.java` | 4 | `@AtomicSerial` compliance |
| `rio-core/rio-proxy/.../proxy/admin/ServiceAdminProxy.java` | 4 | `@AtomicSerial` compliance |
| `rio-core/rio-proxy/.../proxy/admin/ConstrainableServiceAdminProxy.java` | 4 | `@AtomicSerial` compliance |
| `rio-services/cybernode/.../proxy/CybernodeProxy.java` | 4 | `@AtomicSerial` compliance (incl. inner classes) |
| `rio-services/monitor/.../proxy/ProvisionMonitorProxy.java` | 4 | `@AtomicSerial` compliance |
| `rio-services/monitor/.../proxy/ProvisionMonitorAdminProxy.java` | 4 | `@AtomicSerial` compliance |
| `rio-services/event-collector/.../proxy/EventCollectorBackend.java` | 4 | `@AtomicSerial` compliance |
| `rio-core/rio-proxy/.../proxy/bean/BeanDelegator.java` | 4 | `@AtomicSerial` compliance |
| `rio-core/rio-proxy/.../proxy/bean/PackagedMethod.java` | 4 | `@AtomicSerial` compliance |
| `distribution/src/main/policy/rio.policy` | 5 | Remove `SocketPermission("*:*")`; remove `RuntimePermission("*")`; add principal-scoped grants |
| `distribution/src/main/policy/rio-test.policy` | 5 | Remove `AllPermission`; minimum required permissions per codebase |
| `pom.xml` (root) | 2 | Replace `river.version=2.2.2` with JGDMS coordinates |
| `rio-resolver/.../aether/AetherResolver.java` | 6 | Replace `newCachedThreadPool()` |

---

## 6. DoS Vector Summary

| Vector | Location | Mitigation |
|---|---|---|
| Unbounded thread creation | 12 `newCachedThreadPool()` sites; 3 `new Thread().start()` in `ProvisionMonitorPeer` | Area 6: bounded `ThreadPoolExecutor` |
| Unlimited wire principal count | `BasicInvocationDispatcher` (River 2.2.2) | Area 2: JGDMS auto-limits to 64 |
| Unlimited wire string length | `BasicInvocationDispatcher` (River 2.2.2) | Area 2: JGDMS auto-limits to 8 KB |
| `AllPermission` test grants | `rio-test.policy` | Area 5: replace with minimum set |
| `SocketPermission("*:*")` production grant | `rio.policy` | Area 5: named-host grants |
| `RuntimePermission("*")` production grant | `rio.policy` | Area 5: enumerate specific permissions |
| Unvetted JAR loading (no BAE check) | `ServiceBeanLoader`, `ResolvingLoader` | Area 7: `VerdictRegistry` gate |
| `this` escaping during construction | All three service impls | Area 1: `Startable` pattern |
| No authorization on administrative methods | All three service impls | Area 9: SPIFFE-based authorization |

---

## 7. Key JGDMS API / Design Decisions Relevant to Rio

| Decision | Rationale | Implication for Rio |
|---|---|---|
| `Startable.start()` called after construction | JMM compliance; no `this` escape | Two-arg constructors must not export or start threads |
| `doAs` accepts only vanilla `Subject`/`null` | Strict routing; `WorkerSubject` is ambient | Replace `doAsPrivileged(loginContext.getSubject(),…)` with `callAs` |
| `WorkerSubject` is ambient in every `ProtectionDomain` | Baked in by `SecureClassLoader` at class load | No per-request `doAs(workerSubject,…)` wrapper |
| `@AtomicSerial` on all serialized wire objects | BAE rejects non-compliant proxies | All proxy classes need `@AtomicSerial` migration |
| `VerifyingProxyPreparer` enforces three-way intersection | Code + authority + principal | Replace `BasicProxyPreparer` |
| `PolicyPermission("Remote")` and `GrantPermission` must not be delegatable | Proxies must not enter policy machinery | Must not appear in `PERMISSIONS.LIST` |
| `SocketPermission` in `PERMISSIONS.LIST` → `DANGEROUS` | BAE flags as DoS risk | Must not appear in Rio service `PERMISSIONS.LIST` |
| `RuntimePermission("createVirtualThread")` requires care | Grants make blocking `<clinit>` paths reachable | Must not appear in Rio service `PERMISSIONS.LIST` |
| `MAX_USER_PRINCIPALS = 64`, `MAX_STRING_BYTES = 8192` | Wire DoS limits in `BasicInvocationDispatcher` | Auto-applied after JGDMS upgrade |
| Three-layer policy stack | Clean separation of grant lifetimes | `ServiceBeanLoader` must construct the stack |

---

## 8. References

- `pfirmstone/JGDMS` trunk, `JGDMS/docs/Big picture security architecture/AI_Agent_JGDMS-GrantPermission-RoleManagement-context_8.md` (v19)
- `pfirmstone/JGDMS` trunk, `JGDMS/jgdms-collections/src/main/java/org/apache/river/api/util/Startable.java`
- `pfirmstone/JGDMS` trunk, `JGDMS/services/jgdms-service-support/src/main/java/au/net/zeus/jgdms/service/support/AbstractJiniService.java`
- `pfirmstone/JGDMS` trunk, `JGDMS/jgdms-platform/src/main/java/org/apache/river/api/security/AdvisoryDynamicPermissions.java`
- **JGDMS-STD-001**: `@AtomicSerial` compliance rules
- **JGDMS-STD-002**: Five-host SCAP pipeline architecture
- **JGDMS-STD-003 v3.1**: Multi-Subject Identity Architecture
