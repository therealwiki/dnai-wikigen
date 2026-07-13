---
name: phala-cvms
description: Manage Phala Cloud CVM lifecycle — list, inspect, start, stop, restart, resize, replicate, and delete Confidential VMs. Use when the user wants to manage running CVMs or check CVM status and attestation.
---

# Phala CVMs — Manage Confidential VMs

## When to use
- User wants to list, inspect, or search their CVMs
- User needs to start, stop, restart, or delete a CVM
- User wants to resize resources or replicate a CVM
- User needs to check attestation or node availability

## Commands

### List all CVMs
```bash
phala cvms list
phala cvms ls  # alias
```

### List with filters
```bash
# Filter by status
phala cvms list --status running
phala cvms list --status stopped
phala cvms list --status error

# Search by name
phala cvms list --search my-app

# Filter by instance type
phala cvms list --instance-type tdx.medium

# Filter by KMS type
phala cvms list --kms-type phala

# Pagination
phala cvms list --page 1 --page-size 10

# JSON output for scripting
phala cvms list --json
```

### Get CVM details
```bash
phala cvms get <CVM_ID>
phala cvms get  # uses linked CVM from phala.toml
```

### Start a stopped CVM
```bash
phala cvms start <CVM_ID>
```

### Stop a running CVM
```bash
phala cvms stop <CVM_ID>
```

### Restart a CVM
```bash
phala cvms restart <CVM_ID>
```

### Delete a CVM
```bash
phala cvms delete <CVM_ID>
phala cvms delete <CVM_ID> --force --yes  # skip confirmation
```

### Resize a CVM
```bash
phala cvms resize <CVM_ID> \
  --vcpu 4 \
  --memory 8192 \
  --disk-size 80 \
  --allow-restart
```
Note: Resize may require a restart depending on the change.

### Replicate a CVM
```bash
phala cvms replicate <CVM_ID>
phala cvms replicate <CVM_ID> --env-file .env.replica
```

### Get attestation info
```bash
phala cvms attestation <CVM_ID>
```
Returns TDX quote and measurement data. Verify at https://proof.t16z.com/.

### List available worker nodes
```bash
phala cvms list-nodes
phala nodes  # alias
```

## CVM statuses
| Status | Meaning |
|--------|---------|
| `pending` | Queued for deployment |
| `starting` | Booting up |
| `running` | Active and healthy |
| `stopping` | Shutting down |
| `stopped` | Halted (can restart) |
| `error` | Failed (check logs) |

## Common workflows

### Check health of all CVMs
```bash
phala cvms list --status running --json | jq '.[] | {name, status, instance_type}'
```

### Find and restart a stuck CVM
```bash
phala cvms list --search my-app
phala cvms restart <CVM_ID>
phala logs --cvm-id <CVM_ID> --tail 50
```

### Scale up before a demo
```bash
phala cvms resize <CVM_ID> --vcpu 4 --memory 8192 --allow-restart
```

### Clean up old CVMs
```bash
phala cvms list --status stopped --json
phala cvms delete <CVM_ID> --yes
```
