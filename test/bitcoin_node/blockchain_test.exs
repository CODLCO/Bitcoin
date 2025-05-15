# test/bitcoin_node/blockchain_test.exs
defmodule BitcoinNode.BlockchainTest do
  use ExUnit.Case
  alias BitcoinNode.{Blockchain, Storage, Utils, Mempool, RPC, Protocol.Messages, Script}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(BitcoinNode.Repo)
    Blockchain.init_genesis_block()
    :ok
  end

  test "stores and processes orphan block" do
    parent_hash = BitcoinNode.Config.genesis_block().hash
    orphan = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: parent_hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 0
      },
      transactions: [%{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<>>}], locktime: 0}]
    }
    block_hash = Utils.double_sha256(orphan.header)

    assert {:error, :orphan_block} = Blockchain.insert_block(%{header: orphan.header, transactions: orphan.transactions, hash: block_hash})
    assert %BitcoinNode.Schema.Orphan{} = Storage.get_orphan_by_hash(block_hash)

    parent_block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: parent_hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 1
      },
      transactions: [%{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<>>}], locktime: 0}]
    }
    parent_hash = Utils.double_sha256(parent_block.header)
    {:ok, _} = Blockchain.insert_block(%{header: parent_block.header, transactions: parent_block.transactions, hash: parent_hash})

    assert Storage.get_orphan_by_hash(block_hash) == nil
    assert %BitcoinNode.Schema.Block{} = Storage.get_block_by_hash(block_hash)
  end

  test "handles RBF transaction replacement" do
    tx1 = %{
      version: 1,
      inputs: [%{prev_txid: <<0::256>>, prev_vout: 0, script_sig: <<>>, sequence: 0xFFFFFFFD}],
      outputs: [%{value: 49_000_000, script_pubkey: <<>>}],
      locktime: 0
    }
    {:ok, txid1} = Mempool.add_transaction(tx1)

    tx2 = %{
      version: 1,
      inputs: [%{prev_txid: <<0::256>>, prev_vout: 0, script_sig: <<>>, sequence: 0xFFFFFFFD}],
      outputs: [%{value: 48_000_000, script_pubkey: <<>>}],
      locktime: 0
    }
    {:ok, txid2} = Mempool.add_transaction(tx2)

    assert Mempool.lookup(txid1) == {:error, :not_found}
    assert {:ok, _} = Mempool.lookup(txid2)
  end

  test "processes SegWit P2WPKH transaction" do
    privkey = :crypto.strong_rand_bytes(32)
    {:ok, pubkey} = :crypto.generate_key(:ecdh, :secp256k1, privkey)
    pubkey_hash = Utils.hash160(pubkey)
    script_pubkey = <<0x00, 0x14>> <> pubkey_hash

    utxo = %BitcoinNode.Schema.Utxo{
      txid: <<0::256>>,
      vout: 0,
      value: 50_000_000,
      script_pubkey: script_pubkey,
      height: 0,
      is_coinbase: false
    }
    {:ok, _} = Storage.put_utxo(utxo)

    tx = %{
      version: 1,
      inputs: [%{prev_txid: <<0::256>>, prev_vout: 0, script_sig: <<>>, sequence: 0xFFFFFFFF}],
      outputs: [%{value: 49_000_000, script_pubkey: <<>>}],
      witnesses: [[]],
      locktime: 0,
      has_witness: true
    }
    sig_hash = Script.calculate_sighash(tx, 0, script_pubkey, utxo.value)
    signature = :crypto.sign(:ecdsa, :sha256, sig_hash, [privkey, :secp256k1]) <> <<0x01>>
    tx = %{tx | witnesses: [[signature, pubkey]]}

    block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: BitcoinNode.Config.genesis_block().hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 0
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0x00::256>>}], locktime: 0},
        tx
      ]
    }
    block_hash = Utils.double_sha256(block.header)
    {:ok, _} = Blockchain.insert_block(%{header: block.header, transactions: block.transactions, hash: block_hash})

    assert %BitcoinNode.Schema.Block{} = Storage.get_block_by_hash(block_hash)
    assert [_, tx_rec] = Storage.get_transactions_by_block_id(block_hash)
    assert tx_rec.has_witness
  end

  test "processes SegWit P2WSH multisig transaction" do
    privkeys = for _ <- 1..3, do: :crypto.strong_rand_bytes(32)
    pubkeys = for priv <- privkeys, do: elem(:crypto.generate_key(:ecdh, :secp256k1, priv), 1)
    witness_script = <<0x52>> <> Enum.reduce(pubkeys, <<>>, fn pubkey, acc -> acc <> <<0x21, pubkey::binary>> end) <> <<0x53, 0xae>>
    script_hash = :crypto.hash(:sha256, witness_script)
    script_pubkey = <<0x00, 0x20>> <> script_hash

    utxo = %BitcoinNode.Schema.Utxo{
      txid: <<0::256>>,
      vout: 0,
      value: 50_000_000,
      script_pubkey: script_pubkey,
      height: 0,
      is_coinbase: false
    }
    {:ok, _} = Storage.put_utxo(utxo)

    tx = %{
      version: 1,
      inputs: [%{prev_txid: <<0::256>>, prev_vout: 0, script_sig: <<>>, sequence: 0xFFFFFFFF}],
      outputs: [%{value: 49_000_000, script_pubkey: <<>>}],
      witnesses: [[]],
      locktime: 0,
      has_witness: true
    }
    sig_hash = Script.calculate_sighash(tx, 0, witness_script, utxo.value)
    signatures = for priv <- Enum.take(privkeys, 2) do
      :crypto.sign(:ecdsa, :sha256, sig_hash, [priv, :secp256k1]) <> <<0x01>>
    end
    witness_items = [<<>>, signatures, 2, 3, witness_script] |> List.flatten()
    tx = %{tx | witnesses: [witness_items]}

    block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: BitcoinNode.Config.genesis_block().hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 0
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0x00::256>>}], locktime: 0},
        tx
      ]
    }
    block_hash = Utils.double_sha256(block.header)
    {:ok, _} = Blockchain.insert_block(%{header: block.header, transactions: block.transactions, hash: block_hash})

    assert %BitcoinNode.Schema.Block{} = Storage.get_block_by_hash(block_hash)
    assert [_, tx_rec] = Storage.get_transactions_by_block_id(block_hash)
    assert tx_rec.has_witness
  end

  test "processes Taproot P2TR key path transaction" do
    privkey = :crypto.strong_rand_bytes(32)
    {:ok, pubkey} = ExSecp256k1.public_key_create(privkey)
    x_only_pubkey = binary_part(pubkey, 1, 32)
    script_pubkey = <<0x51, 0x20>> <> x_only_pubkey

    utxo = %BitcoinNode.Schema.Utxo{
      txid: <<0::256>>,
      vout: 0,
      value: 50_000_000,
      script_pubkey: script_pubkey,
      height: 0,
      is_coinbase: false
    }
    {:ok, _} = Storage.put_utxo(utxo)

    tx = %{
      version: 1,
      inputs: [%{prev_txid: <<0::256>>, prev_vout: 0, script_sig: <<>>, sequence: 0xFFFFFFFF}],
      outputs: [%{value: 49_000_000, script_pubkey: <<>>}],
      witnesses: [[]],
      locktime: 0,
      has_witness: true
    }
    sig_hash = Script.calculate_taproot_sighash(tx, 0, script_pubkey, utxo.value, :key_spend, nil)
    {:ok, signature} = ExSecp256k1.schnorr_sign(sig_hash, privkey)
    tx = %{tx | witnesses: [[signature]]}

    block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: BitcoinNode.Config.genesis_block().hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 0
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0x00::256>>}], locktime: 0},
        tx
      ]
    }
    block_hash = Utils.double_sha256(block.header)
    {:ok, _} = Blockchain.insert_block(%{header: block.header, transactions: block.transactions, hash: block_hash})

    assert %BitcoinNode.Schema.Block{} = Storage.get_block_by_hash(block_hash)
    assert [_, tx_rec] = Storage.get_transactions_by_block_id(block_hash)
    assert tx_rec.has_witness
  end

  test "processes Taproot P2TR script path transaction with varied prevouts" do
    privkey = :crypto.strong_rand_bytes(32)
    {:ok, pubkey} = ExSecp256k1.public_key_create(privkey)
    x_only_pubkey = binary_part(pubkey, 1, 32)
    tapscript = <<0x51>> # OP_1
    control_block = <<0x00>> <> x_only_pubkey
    script_pubkey = <<0x51, 0x20>> <> x_only_pubkey
    annex = <<0x50, 0x01>>

    # Create two UTXOs with different amounts and scriptPubKeys
    utxo1 = %BitcoinNode.Schema.Utxo{
      txid: <<0::256>>,
      vout: 0,
      value: 50_000_000,
      script_pubkey: <<0x00, 0x14>> <> :crypto.strong_rand_bytes(20),
      height: 0,
      is_coinbase: false
    }
    utxo2 = %BitcoinNode.Schema.Utxo{
      txid: <<1::256>>,
      vout: 1,
      value: 25_000_000,
      script_pubkey: <<0x00, 0x20>> <> :crypto.strong_rand_bytes(32),
      height: 0,
      is_coinbase: false
    }
    {:ok, _} = Storage.put_utxo(utxo1)
    {:ok, _} = Storage.put_utxo(utxo2)

    tx = %{
      version: 1,
      inputs: [
        %{prev_txid: <<0::256>>, prev_vout: 0, script_sig: <<>>, sequence: 0xFFFFFFFF},
        %{prev_txid: <<1::256>>, prev_vout: 1, script_sig: <<>>, sequence: 0xFFFFFFFE}
      ],
      outputs: [%{value: 74_000_000, script_pubkey: <<>>}],
      witnesses: [[<<0x01>>, tapscript, control_block, annex], []],
      locktime: 0,
      has_witness: true
    }
    sig_hash = Script.calculate_taproot_sighash(tx, 0, tapscript, utxo1.value, :script_spend, annex)
    {:ok, signature} = ExSecp256k1.schnorr_sign(sig_hash, privkey)
    tx = %{tx | witnesses: [[signature, tapscript, control_block, annex], []]}

    block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: BitcoinNode.Config.genesis_block().hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 0
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0x00::256>>}], locktime: 0},
        tx
      ]
    }
    block_hash = Utils.double_sha256(block.header)
    {:ok, _} = Blockchain.insert_block(%{header: block.header, transactions: block.transactions, hash: block_hash})

    assert %BitcoinNode.Schema.Block{} = Storage.get_block_by_hash(block_hash)
    assert [_, tx_rec] = Storage.get_transactions_by_block_id(block_hash)
    assert tx_rec.has_witness
  end

  test "processes transaction with OP_CHECKLOCKTIMEVERIFY" do
    locktime = 100
    witness_script = <<locktime::little-32, 0xb1, 0x51>>
    script_hash = :crypto.hash(:sha256, witness_script)
    script_pubkey = <<0x00, 0x20>> <> script_hash

    utxo = %BitcoinNode.Schema.Utxo{
      txid: <<0::256>>,
      vout: 0,
      value: 50_000_000,
      script_pubkey: script_pubkey,
      height: 0,
      is_coinbase: false
    }
    {:ok, _} = Storage.put_utxo(utxo)

    parent_block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: BitcoinNode.Config.genesis_block().hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 1
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<>>}], locktime: 0}
      ]
    }
    parent_hash = Utils.double_sha256(parent_block.header)
    {:ok, _} = Blockchain.insert_block(%{header: parent_block.header, transactions: parent_block.transactions, hash: parent_hash})

    tx = %{
      version: 1,
      inputs: [%{prev_txid: <<0::256>>, prev_vout: 0, script_sig: <<>>, sequence: 0xFFFFFFFE}],
      outputs: [%{value: 49_000_000, script_pubkey: <<>>}],
      witnesses: [[<<locktime::little-32>>, witness_script]],
      locktime: locktime,
      has_witness: true
    }

    block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: parent_hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 0
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0x00::256>>}], locktime: 0},
        tx
      ]
    }
    block_hash = Utils.double_sha256(block.header)
    {:ok, _} = Blockchain.insert_block(%{header: block.header, transactions: block.transactions, hash: block_hash})

    assert %BitcoinNode.Schema.Block{} = Storage.get_block_by_hash(block_hash)
    assert [_, tx_rec] = Storage.get_transactions_by_block_id(block_hash)
    assert tx_rec.has_witness
  end

  test "processes transaction with OP_CHECKSEQUENCEVERIFY" do
    sequence = 10
    witness_script = <<sequence::little-32, 0xb2, 0x51>>
    script_hash = :crypto.hash(:sha256, witness_script)
    script_pubkey = <<0x00, 0x20>> <> script_hash

    utxo = %BitcoinNode.Schema.Utxo{
      txid: <<0::256>>,
      vout: 0,
      value: 50_000_000,
      script_pubkey: script_pubkey,
      height: 0,
      is_coinbase: false
    }
    {:ok, _} = Storage.put_utxo(utxo)

    parent_block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: BitcoinNode.Config.genesis_block().hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 1
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<>>}], locktime: 0}
      ]
    }
    parent_hash = Utils.double_sha256(parent_block.header)
    {:ok, _} = Blockchain.insert_block(%{header: parent_block.header, transactions: parent_block.transactions, hash: parent_hash})

    tx = %{
      version: 1,
      inputs: [%{prev_txid: <<0::256>>, prev_vout: 0, script_sig: <<>>, sequence: sequence}],
      outputs: [%{value: 49_000_000, script_pubkey: <<>>}],
      witnesses: [[<<sequence::little-32>>, witness_script]],
      locktime: 0,
      has_witness: true
    }

    block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: parent_hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 0
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0x00::256>>}], locktime: 0},
        tx
      ]
    }
    block_hash = Utils.double_sha256(block.header)
    {:ok, _} = Blockchain.insert_block(%{header: block.header, transactions: block.transactions, hash: block_hash})

    assert %BitcoinNode.Schema.Block{} = Storage.get_block_by_hash(block_hash)
    assert [_, tx_rec] = Storage.get_transactions_by_block_id(block_hash)
    assert tx_rec.has_witness
  end

  test "rejects oversized script to prevent DoS" do
    script_pubkey = <<0x00, 0x14>> <> :crypto.strong_rand_bytes(20)
    oversized_script_sig = String.duplicate("a", 11_000)

    tx = %{
      version: 1,
      inputs: [%{prev_txid: <<0::256>>, prev_vout: 0, script_sig: oversized_script_sig, sequence: 0xFFFFFFFF}],
      outputs: [%{value: 49_000_000, script_pubkey: <<>>}],
      locktime: 0
    }
    utxo = %BitcoinNode.Schema.Utxo{
      txid: <<0::256>>,
      vout: 0,
      value: 50_000_000,
      script_pubkey: script_pubkey,
      height: 0,
      is_coinbase: false
    }
    {:ok, _} = Storage.put_utxo(utxo)

    assert {:error, :invalid_inputs} = Blockchain.validate_transaction(tx, :mempool)
  end

  test "handles RPC getblock request" do
    block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: BitcoinNode.Config.genesis_block().hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 0
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<0x01>>}], locktime: 0}
      ]
    }
    block_hash = Utils.double_sha256(block.header)
    {:ok, _} = Blockchain.insert_block(%{header: block.header, transactions: block.transactions, hash: block_hash})

    request = %{"jsonrpc" => "2.0", "method" => "getblock", "params" => [Base.encode16(block_hash, case: :lower)], "id" => 1}
    response = RPC.handle_request(request)
    assert %{"result" => %{"hash" => hash, "height" => 1, "tx_count" => 1}} = response
    assert hash == Base.encode16(block_hash, case: :lower)
  end

  test "handles RPC getmempoolinfo request" do
    tx = %{
      version: 1,
      inputs: [%{prev_txid: <<0::256>>, prev_vout: 0, script_sig: <<>>, sequence: 0xFFFFFFFF}],
      outputs: [%{value: 49_000_000, script_pubkey: <<>>}],
      locktime: 0
    }
    {:ok, _} = Mempool.add_transaction(tx)

    request = %{"jsonrpc" => "2.0", "method" => "getmempoolinfo", "params" => [], "id" => 1}
    response = RPC.handle_request(request)
    assert %{"result" => %{"size" => 1, "bytes" => bytes, "maxmempool" => 300_000_000}} = response
    assert bytes > 0
  end

  test "handles RPC getblockchaininfo request" do
    block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: BitcoinNode.Config.genesis_block().hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 0
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<0x01>>}], locktime: 0}
      ]
    }
    block_hash = Utils.double_sha256(block.header)
    {:ok, _} = Blockchain.insert_block(%{header: block.header, transactions: block.transactions, hash: block_hash})

    request = %{"jsonrpc" => "2.0", "method" => "getblockchaininfo", "params" => [], "id" => 1}
    response = RPC.handle_request(request)
    assert %{"result" => %{"chain" => "main", "blocks" => 1, "bestblockhash" => hash, "difficulty" => _, "headers" => 1}} = response
    assert hash == Base.encode16(block_hash, case: :lower)
  end

  test "handles RPC sendrawtransaction request" do
    tx = %{
      version: 1,
      inputs: [%{prev_txid: <<0::256>>, prev_vout: 0, script_sig: <<>>, sequence: 0xFFFFFFFF}],
      outputs: [%{value: 49_000_000, script_pubkey: <<>>}],
      locktime: 0
    }
    {:ok, raw} = Messages.encode(%Messages.Tx{transaction: tx})

    request = %{"jsonrpc" => "2.0", "method" => "sendrawtransaction", "params" => [Base.encode16(raw, case: :lower)], "id" => 1}
    response = RPC.handle_request(request)
    assert %{"result" => txid} = response
    assert byte_size(txid) == 64
    assert {:ok, _} = Mempool.lookup(Base.decode16!(txid, case: :lower))
  end

  test "handles RPC getblockfilter request" do
    block = %BitcoinNode.Protocol.Messages.Block{
      header: %{
        version: 1,
        prev_block_hash: BitcoinNode.Config.genesis_block().hash,
        merkle_root: <<0::256>>,
        timestamp: DateTime.utc_now(),
        bits: 0x1d00ffff,
        nonce: 0
      },
      transactions: [
        %{version: 1, inputs: [], outputs: [%{value: 50_000_000, script_pubkey: <<0x01>>}], locktime: 0}
      ]
    }
    block_hash = Utils.double_sha256(block.header)
    {:ok, _} = Blockchain.insert_block(%{header: block.header, transactions: block.transactions, hash: block_hash})

    request = %{"jsonrpc" => "2.0", "method" => "getblockfilter", "params" => [Base.encode16(block_hash, case: :lower)], "id" => 1}
    response = RPC.handle_request(request)
    assert %{"result" => %{"filter" => filter, "type" => 0}} = response
    assert byte_size(Base.decode16!(filter, case: :lower)) > 0
  end
end
