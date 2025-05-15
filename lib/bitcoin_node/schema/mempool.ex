defmodule BitcoinNode.Schema.Mempool do
  @moduledoc """
  Ecto schema for the mempool table, representing unconfirmed Bitcoin transactions.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{
          txid: binary(),
          raw: binary(),
          fee: integer() | nil,
          size: integer() | nil,
          received_at: DateTime.t(),
          depends_on: [binary()],
          short_id: binary(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @primary_key {:txid, :binary, autogenerate: false}
  schema "mempool" do
    field :raw, :binary
    field :fee, :integer
    field :size, :integer
    field :received_at, :utc_datetime_usec
    field :depends_on, {:array, :binary}
    field :short_id, :binary
    timestamps()
  end

  @doc """
  Creates a changeset for a mempool transaction with validation for Bitcoin-specific constraints.

  ## Parameters
  - `mempool`: The mempool transaction struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - `Ecto.Changeset.t()`
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(mempool, attrs) do
    mempool
    |> cast(attrs, [:txid, :raw, :fee, :size, :received_at, :depends_on, :short_id])
    |> validate_required([:txid, :raw, :received_at, :short_id])
    |> validate_length(:txid, is: 32)
    |> validate_length(:short_id, is: 6)
    |> validate_number(:fee, greater_than_or_equal_to: 0, allow_nil: true)
    |> validate_number(:size, greater_than: 0, allow_nil: true)
    |> validate_depends_on()
    |> unique_constraint(:txid)
    |> unique_constraint(:short_id)
  end

  defp validate_depends_on(changeset) do
    validate_change(changeset, :depends_on, fn :depends_on, depends_on ->
      if is_list(depends_on) and Enum.all?(depends_on, &(is_binary(&1) and byte_size(&1) == 32)) do
        []
      else
        [depends_on: "must be an array of 32-byte binaries"]
      end
    end)
  end
end
