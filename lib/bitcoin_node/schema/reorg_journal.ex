defmodule BitcoinNode.Schema.ReorgJournal do
  @moduledoc """
  Ecto schema for the reorg_journal table, tracking blockchain reorganizations.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{
          block_hash: binary(),
          height: integer(),
          applied: boolean(),
          reverted_at: DateTime.t() | nil,
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  schema "reorg_journal" do
    field :block_hash, :binary
    field :height, :integer
    field :applied, :boolean
    field :reverted_at, :utc_datetime_usec
    timestamps()
  end

  @doc """
  Creates a changeset for a reorg journal entry with validation for Bitcoin-specific constraints.

  ## Parameters
  - `journal`: The reorg journal struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - `Ecto.Changeset.t()`
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(journal, attrs) do
    journal
    |> cast(attrs, [:block_hash, :height, :applied, :reverted_at])
    |> validate_required([:block_hash, :height, :applied])
    |> validate_length(:block_hash, is: 32)
    |> validate_number(:height, greater_than_or_equal_to: 0)
  end
end
