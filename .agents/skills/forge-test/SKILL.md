---
name: forge-test
description: Run Solidity smart contract tests with Foundry forge including unit tests, fuzz tests, and invariant tests. Use when the user wants to test contracts, run fuzzing, check coverage, or debug failing tests.
---

# Forge Test — Test Smart Contracts

## When to use
- User wants to run tests
- User needs fuzz testing or invariant testing
- User wants gas reports or coverage
- User needs to debug a failing test

## Commands

### Run all tests
```bash
forge test
```

### Run specific test file
```bash
forge test --match-path test/Escrow.t.sol
```

### Run specific test function
```bash
forge test --match-test testDeposit
```

### Verbosity levels
```bash
forge test -vv     # print logs for all tests
forge test -vvv    # print execution traces for failing tests
forge test -vvvv   # print traces for all tests
forge test -vvvvv  # include storage changes
```

### Gas report
```bash
forge test --gas-report
```

### Gas snapshot
```bash
forge snapshot
```

### Coverage
```bash
forge coverage
forge coverage --report lcov  # for IDE integration
```

## Test file conventions

Test files must:
- End with `.t.sol`
- Import `forge-std/Test.sol`
- Contract must inherit `Test`
- Test functions must start with `test`
- Functions starting with `testFail` expect reverts

### Basic test structure
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {MyContract} from "../src/MyContract.sol";

contract MyContractTest is Test {
    MyContract public target;

    function setUp() public {
        target = new MyContract();
    }

    function test_BasicFunction() public {
        // arrange, act, assert
        assertEq(target.value(), 0);
    }
}
```

## Fuzz testing

Forge automatically fuzzes any test with parameters:

```solidity
function testFuzz_Deposit(uint256 amount) public {
    vm.assume(amount > 0 && amount <= 100 ether);
    // test with random amounts
}
```

Configure in foundry.toml:
```toml
[fuzz]
runs = 1000        # number of fuzz runs (default 256)
seed = "0x1"       # reproducible results
```

## Invariant testing

For stateful fuzz testing across random call sequences:

```solidity
function invariant_totalSupplyMatchesBalances() public {
    assertEq(token.totalSupply(), sumOfAllBalances());
}
```

Configure in foundry.toml:
```toml
[invariant]
runs = 256
depth = 15
```

## Useful cheatcodes
- `vm.prank(address)` — next call comes from address
- `vm.deal(address, amount)` — set ETH balance
- `vm.warp(timestamp)` — set block.timestamp
- `vm.roll(blockNumber)` — set block.number
- `vm.expectRevert()` — expect next call to revert
- `vm.expectEmit()` — expect event emission

## Fork testing (against Base Sepolia)
```bash
forge test --fork-url https://sepolia.base.org
```

```solidity
function setUp() public {
    // Fork Base Sepolia at specific block
    vm.createSelectFork("https://sepolia.base.org", 38000000);
}
```
