def require($condition; $message):
  if $condition then . else error($message) end;

def is_address:
  type == "string" and test("^0x[0-9a-fA-F]{40}$");

def is_bytes32:
  type == "string" and test("^0x[0-9a-fA-F]{64}$");

def is_tx_hash:
  is_bytes32 and (ascii_downcase != ("0x" + ("0" * 64)));

def is_topic_address:
  type == "string" and test("^0x0{24}[0-9a-fA-F]{40}$");

. as $evidence
| require(type == "object"
    and (.transaction | type) == "object"
    and (.receipt | type) == "object";
    "governance acceptance evidence must contain one transaction and receipt")
| require($mode == "eoa_direct_call" or $mode == "contract_event_and_state";
    "governance acceptance mode is invalid")
| require(($txHash | is_tx_hash); "governance acceptance transaction hash is invalid")
| require(($room | is_address); "DiligenceRoom address is invalid")
| require(($operator | is_address); "deployment operator is invalid")
| require(($controller | is_address); "governance controller is invalid")
| require(($developerTransferredTopic | is_bytes32);
    "DeveloperTransferred event topic is invalid")
| require(($operatorTopic | is_topic_address)
    and ($controllerTopic | is_topic_address);
    "DeveloperTransferred indexed address topics are invalid")
| require(($acceptDeveloperSelector | type) == "string"
    and ($acceptDeveloperSelector | test("^0x[0-9a-fA-F]{8}$"));
    "acceptDeveloper selector is invalid")
| require((.transaction.hash | type) == "string"
    and (.transaction.hash | ascii_downcase) == ($txHash | ascii_downcase);
    "transaction object hash does not match the reviewed acceptance hash")
| require((.receipt.transactionHash | type) == "string"
    and (.receipt.transactionHash | ascii_downcase) == ($txHash | ascii_downcase);
    "receipt hash does not match the reviewed acceptance hash")
| require((.transaction.blockNumber | type) == "string"
    and (.receipt.blockNumber | type) == "string"
    and (.transaction.blockNumber | ascii_downcase)
      == (.receipt.blockNumber | ascii_downcase);
    "transaction and receipt block numbers do not match")
| require(.transaction.chainId == "0x14a34";
    "governance acceptance transaction is not Base Sepolia")
| require(.receipt.status == "0x1";
    "governance acceptance receipt is not successful")
| require((.receipt.logs | type) == "array";
    "governance acceptance receipt logs are missing")
| [
    .receipt.logs[]
    | select(
        (.address | type) == "string"
        and (.address | ascii_downcase) == ($room | ascii_downcase)
      )
  ] as $roomLogs
| require(($roomLogs | length) == 1;
    "acceptance receipt must contain exactly one DiligenceRoom log")
| $roomLogs[0] as $transferLog
| require(($transferLog.topics | type) == "array"
    and ($transferLog.topics | length) == 3
    and (($transferLog.topics[0] // "") | ascii_downcase)
      == ($developerTransferredTopic | ascii_downcase)
    and (($transferLog.topics[1] // "") | ascii_downcase)
      == ($operatorTopic | ascii_downcase)
    and (($transferLog.topics[2] // "") | ascii_downcase)
      == ($controllerTopic | ascii_downcase)
    and (($transferLog.data // "") | ascii_downcase) == "0x";
    "acceptance receipt is missing the exact operator-to-controller DeveloperTransferred event")
| if $mode == "eoa_direct_call" then
    require((.transaction.from | type) == "string"
        and (.transaction.from | ascii_downcase) == ($controller | ascii_downcase);
        "EOA acceptance transaction sender is not the governance controller")
    | require((.transaction.to | type) == "string"
        and (.transaction.to | ascii_downcase) == ($room | ascii_downcase);
        "EOA acceptance transaction does not directly target DiligenceRoom")
    | require((.transaction.input | type) == "string"
        and (.transaction.input | ascii_downcase) == ($acceptDeveloperSelector | ascii_downcase);
        "EOA acceptance calldata is not exactly acceptDeveloper()")
  else
    .
  end
| {
    schema: "dnai.diligence-governance-acceptance-evidence.v1",
    mode: $mode,
    claim: (
      if $mode == "eoa_direct_call" then
        "finalized_direct_eoa_call_event_and_state"
      else
        "finalized_contract_controller_event_and_state_no_trace_claim"
      end
    ),
    transactionHash: ($txHash | ascii_downcase),
    diligenceRoom: ($room | ascii_downcase),
    previousDeveloper: ($operator | ascii_downcase),
    newDeveloper: ($controller | ascii_downcase)
  }
