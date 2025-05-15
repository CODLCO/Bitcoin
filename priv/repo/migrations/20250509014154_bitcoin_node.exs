defmodule BitcoinNode.Repo.Migrations.BitcoinNode do
  use Ecto.Migration

  def change do
    create table(:blocks) do
      add :hash, :binary, null: false
      add :prev_block_hash, :binary
      add :merkle_root, :binary, null: false
      add :version, :integer, null: false
      add :timestamp, :utc_datetime_usec, null: false
      add :bits, :integer, null: false
      add :nonce, :bigint, null: false
      add :height, :bigint, null: false
      add :chain_work, :numeric, null: false, default: 0
      add :size, :integer, null: false
      add :raw, :binary, null: false
      timestamps()
    end

    create unique_index(:blocks, [:hash])
    create index(:blocks, [:height])
    create index(:blocks, [:prev_block_hash])

    create table(:block_headers, primary_key: false) do
      add :hash, :binary, primary_key: true
      add :prev_block_hash, :binary
      add :merkle_root, :binary, null: false
      add :version, :integer, null: false
      add :timestamp, :utc_datetime_usec, null: false
      add :bits, :integer, null: false
      add :nonce, :bigint, null: false
      add :height, :bigint, null: false
      add :chain_work, :numeric, null: false, default: 0
      add :valid, :boolean, default: false, null: false
    end

    create index(:block_headers, [:prev_block_hash])
    create index(:block_headers, [:height])

    create table(:transactions) do
      add :txid, :binary, null: false
      add :block_id, references(:blocks, column: :hash, type: :binary, on_delete: :delete_all), null: false
      add :position, :integer, null: false
      add :version, :integer, null: false
      add :locktime, :bigint, null: false
      add :is_coinbase, :boolean, default: false, null: false
      add :has_witness, :boolean, default: false, null: false
      add :raw, :binary, null: false
      timestamps()
    end

    create unique_index(:transactions, [:txid])
    create index(:transactions, [:block_id])
    create index(:transactions, [:block_id, :position])

    create table(:transaction_inputs) do
      add :tx_id, references(:transactions, column: :txid, type: :binary, on_delete: :delete_all), null: false
      add :prev_txid, :binary, null: false
      add :prev_vout, :bigint, null: false
      add :script_sig, :binary, null: false
      add :sequence, :bigint, null: false
      add :input_index, :integer, null: false
    end

    create index(:transaction_inputs, [:tx_id])
    create index(:transaction_inputs, [:prev_txid, :prev_vout])

    create table(:transaction_outputs) do
      add :tx_id, references(:transactions, column: :txid, type: :binary, on_delete: :delete_all), null: false
      add :vout, :bigint, null: false
      add :value, :bigint, null: false
      add :script_pubkey, :binary, null: false
      add :spent, :boolean, default: false, null: false
      add :spent_by_txid, :binary
      add :output_index, :integer, null: false
    end

    create index(:transaction_outputs, [:tx_id])
    create index(:transaction_outputs, [:spent_by_txid])
    create index(:transaction_outputs, [:tx_id, :vout])

    create table(:transaction_witnesses) do
      add :input_id, references(:transaction_inputs, on_delete: :delete_all), null: false
      add :witness_data, {:array, :binary}, null: false
      add :witness_index, :integer, null: false
    end

    create index(:transaction_witnesses, [:input_id])

    create table(:utxos, primary_key: false) do
      add :txid, :binary, null: false, primary_key: true
      add :vout, :bigint, null: false, primary_key: true
      add :value, :bigint, null: false
      add :script_pubkey, :binary, null: false
      add :height, :bigint, null: false
      add :is_coinbase, :boolean, default: false, null: false
      timestamps()
    end

    create index(:utxos, [:height])
    create index(:utxos, [:txid, :vout])

    create table(:orphans) do
      add :hash, :binary, primary_key: true
      add :raw, :binary, null: false
      add :prev_block_hash, :binary
      add :received_at, :utc_datetime_usec, default: fragment("NOW()"), null: false
      timestamps()
    end

    create index(:orphans, [:prev_block_hash])
    create index(:orphans, [:received_at])

    create table(:peers) do
      add :address, :string, null: false
      add :port, :integer, default: 8333, null: false
      add :services, :bigint
      add :last_seen, :utc_datetime_usec
      add :user_agent, :string
      add :start_height, :bigint
      add :misbehavior_score, :integer, default: 0, null: false
      add :is_banned, :boolean, default: false, null: false
      add :banned_until, :utc_datetime_usec
      timestamps()
    end

    create unique_index(:peers, [:address, :port], name: :peers_address_port_index)
    create index(:peers, [:last_seen])

    create table(:mempool) do
      add :txid, :binary, primary_key: true
      add :raw, :binary, null: false
      add :fee, :bigint
      add :size, :integer
      add :received_at, :utc_datetime_usec, default: fragment("NOW()"), null: false
      add :depends_on, {:array, :binary}, default: [], null: false
      add :short_id, :binary, null: false
      timestamps()
    end

    execute """
    ALTER TABLE mempool
    ADD CONSTRAINT short_id_length CHECK (LENGTH(short_id) = 6)
    """

    create unique_index(:mempool, [:short_id])
    create index(:mempool, [:depends_on])

    create table(:settings) do
      add :key, :string, primary_key: true
      add :value, :string, null: false
    end

    create table(:reorg_journal) do
      add :block_hash, :binary, null: false
      add :height, :bigint, null: false
      add :applied, :boolean, default: true, null: false
      add :reverted_at, :utc_datetime_usec
      timestamps()
    end

    create index(:reorg_journal, [:block_hash])

    create table(:inv_cache) do
      add :txid, :binary, primary_key: true
      add :seen_at, :utc_datetime_usec, default: fragment("NOW()"), null: false
      timestamps()
    end

    create index(:inv_cache, [:seen_at])

    create table(:block_filters, primary_key: false) do
      add :block_hash, :binary, primary_key: true
      add :filter_type, :integer, null: false
      add :filter_data, :binary, null: false
    end

    create index(:block_filters, [:block_hash])
  end
end
