# DRP-Lang compiler (experimental v0.1)

This is the first compiler slice for DRP. It is a deliberately restricted language prototype, not a general-purpose smart-contract language and not a production execution engine.

## Build and run

```sh
go test ./...
go run ./cmd/drpc check examples/education.drp
go run ./cmd/drpc compile examples/education.drp -o education.ir.json
```

## Supported grammar

- One `protocol Name { ... }` declaration.
- `identity name;` declarations.
- Rights with one `requires PoST(identity, "status");` clause.
- Activities with one `requires PoAT(identity);` clause and an integer `reward N RIGHTS;`.
- One optional `verify { quorum elders >= N; }` declaration.

The semantic pass rejects duplicate declarations and proof references to identities that were not declared. The compiler emits deterministic JSON-shaped DRP-IR v0.1.

## Important limitations

- PoAT and PoST are represented as requirements only. The compiler does not create, inspect, or validate real proofs.
- Elder quorum is parsed as a positive integer. It is not checked against a live validator set, consensus configuration, or a supermajority formula.
- Rewards are descriptive IR fields; no token transfer or ledger mutation occurs.
- No WASM, bytecode, optimizer, VM, deployment, or network submission is implemented.
- The generated IR is not yet a stable protocol ABI. Changes may occur before v1.0.

The next integration step is to define a versioned IR contract with Dr-Protocol and add a separately audited runtime adapter. Never treat successful compilation as proof that a rights claim is true or that a transaction is authorized.
