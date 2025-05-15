defmodule BitcoinNode.Schema.Setting do
  @moduledoc """
  Ecto schema for the settings table, representing key-value configuration settings.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{
          key: String.t(),
          value: String.t()
        }

  @primary_key {:key, :string, autogenerate: false}
  schema "settings" do
    field :value, :string
  end

  @doc """
  Creates a changeset for a setting with validation.

  ## Parameters
  - `setting`: The setting struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - `Ecto.Changeset.t()`
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(setting, attrs) do
    setting
    |> cast(attrs, [:key, :value])
    |> validate_required([:key, :value])
  end
end
