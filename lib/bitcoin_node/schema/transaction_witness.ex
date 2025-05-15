defmodule BitcoinNode.Schema.TransactionWitness do
  @moduledoc """
  Ecto schema for transaction witnesses, storing SegWit data for transaction inputs.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "transaction_witnesses" do
    belongs_to :transaction_input, BitcoinNode.Schema.TransactionInput,
      foreign_key: :input_id,
      references: :id,
      type: :integer
    field :witness_data, {:array, :binary}
    field :witness_index, :integer
  end

  def changeset(witness, attrs) do
    witness
    |> cast(attrs, [:input_id, :witness_data, :witness_index])
    |> validate_required([:input_id, :witness_data, :witness_index])
    |> assoc_constraint(:transaction_input)
  end
end
