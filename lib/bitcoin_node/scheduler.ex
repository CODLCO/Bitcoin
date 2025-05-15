# lib/bitcoin_node/scheduler.ex
defmodule BitcoinNode.Scheduler do
  use GenServer
  alias BitcoinNode.{Mempool}
  require Logger

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    schedule_tasks()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:rebroadcast_txs, state) do
    import Ecto.Query
    txs = from(m in BitcoinNode.Schema.Mempool, select: m.txid)
          |> BitcoinNode.Repo.all()

    if txs != [] do
      inv = %BitcoinNode.Protocol.Messages.Inv{inventory: Enum.map(txs, &{:tx, &1})}
      case Process.whereis(BitcoinNode.Peer) do
        pid when is_pid(pid) ->
          GenServer.cast(pid, {:send_message, inv})
        _ ->
          :ok
      end
    end

    schedule_tasks()
    {:noreply, state}
  end

  @impl true
  def handle_info(:evict_txs, state) do
    Mempool.evict_low_fee_txns()
    schedule_tasks()
    {:noreply, state}
  end

  @impl true
  def handle_info(:clean_orphans, state) do
    import Ecto.Query
    threshold = DateTime.add(DateTime.utc_now(), -24 * 3600, :second)
    from(o in BitcoinNode.Schema.Orphan, where: o.received_at < ^threshold)
    |> BitcoinNode.Repo.delete_all()
    |> case do
      {count, _} ->
        Logger.info("Cleaned #{count} stale orphan blocks")
        :ok
    end

    schedule_tasks()
    {:noreply, state}
  end

  defp schedule_tasks do
    Process.send_after(self(), :rebroadcast_txs, 5 * 60 * 1000) # Every 5 minutes
    Process.send_after(self(), :evict_txs, 60 * 60 * 1000) # Every hour
    Process.send_after(self(), :clean_orphans, 24 * 60 * 60 * 1000) # Every 24 hours
  end
end
