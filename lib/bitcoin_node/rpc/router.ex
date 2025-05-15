# lib/bitcoin_node/rpc/router.ex
defmodule BitcoinNode.RPC.Router do
  use Plug.Router
  require Logger

  plug :match
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason
  plug :dispatch

  post "/" do
    case BitcoinNode.RPC.handle_request(conn.body_params) do
      {:error, code, message} ->
        send_resp(conn, 400, Jason.encode!(%{"jsonrpc" => "2.0", "error" => %{"code" => code, "message" => message}, "id" => conn.body_params["id"]}))
      response ->
        send_resp(conn, 200, Jason.encode!(response))
    end
  end

  match _ do
    send_resp(conn, 404, Jason.encode!(%{"jsonrpc" => "2.0", "error" => %{"code" => -32601, "message" => "Method not found"}, "id" => nil}))
  end
end
