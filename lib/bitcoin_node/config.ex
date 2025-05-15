defmodule BitcoinNode.Config do
  @moduledoc """
  Configuration utilities for BitcoinNode, including genesis block definition.
  """

  require Logger

  def network_name, do: "mainnet"

  @doc """
  Returns the mainnet magic bytes.
  """
  @spec magic_bytes() :: binary()
  def magic_bytes, do: <<0xF9, 0xBE, 0xB4, 0xD9>>

  @doc """
  Returns the Bitcoin mainnet genesis block.

  ## Returns
  - A map representing the genesis block with header and transactions.
  """
  @spec genesis_block() :: map()
  def genesis_block do
    block = %{
      header: %{
        version: 1,
        prev_block_hash: <<0::256>>,
        merkle_root:
          <<0x4A, 0x5E, 0x1E, 0x4B, 0xAA, 0xB8, 0x9F, 0x3A, 0x32, 0x51, 0x8A, 0x88, 0xC3, 0x1B,
            0xC8, 0x7F, 0x61, 0x8F, 0x76, 0x67, 0x3E, 0x2C, 0xC7, 0x7A, 0xB2, 0x12, 0x7B, 0x7A,
            0xFD, 0xED, 0xA3, 0x3B>>,
        timestamp: DateTime.from_unix!(1_231_006_505),
        bits: 0x1D00FFFF,
        nonce: 2_083_236_893
      },
      transactions: [
        %{
          version: 1,
          locktime: 0,
          has_witness: false,
          inputs: [
            %{
              prev_txid: <<0::256>>,
              prev_vout: 0xFFFFFFFF,
              script_sig:
                Base.decode16!(
                  "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73",
                  case: :lower
                ),
              sequence: 0xFFFFFFFF
            }
          ],
          outputs: [
            %{
              value: 5_000_000_000,
              script_pubkey:
                Base.decode16!(
                  "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
                  case: :lower
                )
            }
          ]
        }
      ]
    }

    Logger.debug("Generated genesis block: header=#{inspect(block.header, limit: 50)}, tx_count=#{length(block.transactions)}")
    :ok = :telemetry.execute(
      [:bitcoin_node, :config, :genesis_block],
      %{tx_count: length(block.transactions)},
      %{
        version: block.header.version,
        prev_block_hash: Base.encode16(block.header.prev_block_hash, case: :lower),
        merkle_root: Base.encode16(block.header.merkle_root, case: :lower),
        timestamp: block.header.timestamp,
        bits: block.header.bits,
        nonce: block.header.nonce,
        coinbase_value: block.transactions |> List.first() |> Map.get(:outputs) |> List.first() |> Map.get(:value)
      }
    )

    block
  rescue
    e ->
      Logger.error("Failed to generate genesis block: #{inspect(e)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :config, :genesis_block_failed],
        %{},
        %{reason: inspect(e)}
      )
      raise e
  end



end
