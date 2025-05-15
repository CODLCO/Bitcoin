defmodule BitcoinNode.Blockchain.Supervisor do
  @moduledoc """
  Supervisor for blockchain-related processes in the BitcoinNode application.

  Manages workers and other supervisors related to blockchain operations, such as
  block validation and storage.
  """

  use Supervisor
  require Logger

  def start_link(arg) do
    Logger.debug("Starting BitcoinNode.Blockchain.Supervisor with arg: #{inspect(arg)}")
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    Logger.debug("Initializing BitcoinNode.Blockchain.Supervisor")

    children = [
      # Add blockchain-related workers or supervisors here
      # Example: {BitcoinNode.Blockchain.Worker, []}
    ]

    Logger.debug("Blockchain.Supervisor children: #{inspect(children, limit: 50)}")
    Supervisor.init(children, strategy: :one_for_one)
  end
end
