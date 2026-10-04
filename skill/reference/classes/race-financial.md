# Financial Race Conditions & Concurrency Checklist

Deep-dive audit checklist for state mutations, financial balances, inventory reservations, and rate/quota exhaustion. Load when reviewing or verifying checkout workflows, credit transfers, voucher redemption, or concurrent resource allocation.

## Core Invariant

**Any balance check, inventory allocation, or coupon redemption must be atomic with the mutation that decrements the balance, commits the inventory, or marks the coupon used. Read-then-write in application memory without pessimistic locks or atomic database operations is broken under concurrency.**

## 1. Time-of-Check to Time-of-Use (TOCTOU) on Balances

The classic balance race condition pattern:
```
Thread 1: Read balance ($100). Check if balance >= $100 -> OK.
Thread 2: Read balance ($100). Check if balance >= $100 -> OK.
Thread 1: Write balance ($100 - $100 = $0). Ship order.
Thread 2: Write balance ($100 - $100 = $0). Ship order.
Result: $200 worth of goods purchased for $100.
```

- [ ] **Atomic decrement**: Does the update execute as a single atomic query with a guard condition?
  - Correct: `UPDATE accounts SET balance = balance - 100 WHERE id = ? AND balance >= 100` (check rows affected: if 0, insufficient funds).
- [ ] **Pessimistic row locking**: If multiple tables must be updated in a transaction, does the read use `SELECT ... FOR UPDATE`?
- [ ] **Database check constraints**: Does the database schema enforce non-negative balances (`CHECK (balance >= 0)`)?

## 2. Double-Spend, Double-Refund, & Idempotency

- [ ] **Idempotency keys on mutations**: Does the payment/transfer endpoint require and enforce a unique `Idempotency-Key` header or token?
- [ ] **Idempotency table semantics**:
  - Does the server record the idempotency key in an atomic database transaction *before* initiating external calls?
  - Does a duplicate request with the same idempotency key return the cached original response without re-executing payment capture or transfer logic?
- [ ] **Refund state transitions**: Does processing a refund verify that the transaction is in state `SETTLED` and transition it to `REFUNDING` or `REFUNDED` atomically?
  - Can sending 5 concurrent `POST /api/orders/:id/refund` requests result in multiple external gateway refunds before the local database status is updated?

## 3. Inventory Allocation & Flash Sale Exhaustion

- [ ] **Over-allocation under concurrency**: In ticketing, seat reservation, or limited-stock flash sales:
  - Is inventory checked in one query and decremented in another without row locks?
  - Correct pattern:
    ```sql
    UPDATE inventory
    SET available_stock = available_stock - 1, reserved_stock = reserved_stock + 1
    WHERE product_id = ? AND available_stock >= 1;
    ```
- [ ] **Reservation TTL & Abandonment**: When stock is temporarily reserved during checkout:
  - Is the reservation expiry handled safely?
  - Can an attacker refresh or extend their reservation indefinitely to deny inventory to other customers (inventory denial-of-service)?

## 4. Single-Use Vouchers, Coupons, & Promo Codes

- [ ] **Atomic voucher redemption**:
  - Is the coupon redemption count updated atomically with the order creation?
  - Anti-pattern: `coupon = getCoupon(code); if (coupon.used) return error; createOrder(); coupon.markUsed();`
  - Attack: Sending 10 concurrent checkout requests with a single-use $50 discount code applies $500 in discounts because all 10 threads check `coupon.used == false` before any thread marks it used.
- [ ] **Unique database constraint on redemptions**: Is there a database-enforced unique constraint `UNIQUE(coupon_id, user_id)` on the redemption ledger?

## 5. Distributed Locking & Transaction Isolation Levels

- [ ] **Isolation level adequacy**:
  - Is the application relying on the default isolation level?
  - In PostgreSQL, MySQL, and Oracle, the default `READ COMMITTED` allows non-repeatable reads and race conditions unless explicit `FOR UPDATE` locks or atomic updates are used.
  - `SERIALIZABLE` prevents serialization anomalies, but requires retry loops to handle serialization failure errors (`40001: could not serialize access`). Does the application implement automatic retry on retryable transaction errors?
- [ ] **Distributed lock pitfalls (Redis, Consul, etcd)**:
  - If using Redis distributed locks (e.g. Redlock), is the lock released via a safe Lua script that compares the lock token? (Releasing another thread's lock after timeout is a critical vulnerability).
  - Is the lock TTL longer than the worst-case execution time of the protected operation (including network timeouts)?

## Verification Strategy for Verifier

1. Search for code that reads a counter, balance, or flag, evaluates a condition in application logic, and then performs an update in a separate statement.
2. Check whether the database operation uses an atomic update (`balance = balance - amount WHERE balance >= amount`) or `SELECT ... FOR UPDATE`.
3. Check whether the endpoint processes financial mutations without an idempotency key mechanism or unique database constraint.
4. Verify what happens if two identical requests arrive simultaneously with sub-millisecond delta.
