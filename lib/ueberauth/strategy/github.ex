defmodule Ueberauth.Strategy.Github do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with Github.

  ### Setup

  Create an application in Github for you to use.

  Register a new application at: [your github developer page](https://github.com/settings/developers) and get the `client_id` and `client_secret`.

  Include the provider in your configuration for Ueberauth

      config :ueberauth, Ueberauth,
        providers: [
          github: { Ueberauth.Strategy.Github, [] }
        ]

  Then include the configuration for github.

      config :ueberauth, Ueberauth.Strategy.Github.OAuth,
        client_id: System.get_env("GITHUB_CLIENT_ID"),
        client_secret: System.get_env("GITHUB_CLIENT_SECRET")

  If you haven't already, create a pipeline and setup routes for your callback handler

      pipeline :auth do
        Ueberauth.plug "/auth"
      end

      scope "/auth" do
        pipe_through [:browser, :auth]

        get "/:provider/callback", AuthController, :callback
      end


  Create an endpoint for the callback where you will handle the `Ueberauth.Auth` struct

      defmodule MyApp.AuthController do
        use MyApp.Web, :controller

        def callback_phase(%{ assigns: %{ ueberauth_failure: fails } } = conn, _params) do
          # do things with the failure
        end

        def callback_phase(%{ assigns: %{ ueberauth_auth: auth } } = conn, params) do
          # do things with the auth
        end
      end

  You can edit the behaviour of the Strategy by including some options when you register your provider.

  To set the `uid_field`

      config :ueberauth, Ueberauth,
        providers: [
          github: { Ueberauth.Strategy.Github, [uid_field: :email] }
        ]

  Default is `:id`

  To set the default 'scopes' (permissions):

      config :ueberauth, Ueberauth,
        providers: [
          github: { Ueberauth.Strategy.Github, [default_scope: "user,public_repo"] }
        ]

  Default is empty ("") which "Grants read-only access to public information (includes public user profile info, public repository info, and gists)"
  """
  use Ueberauth.Strategy,
    uid_field: :id,
    default_scope: "user,public_repo",
    oauth2_module: Ueberauth.Strategy.Github.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  def oauth2_module, do: Ueberauth.Strategy.Github.OAuth

  def secure_random_hex(n \\ 16) do
    n
    |> :crypto.strong_rand_bytes()
    |> Base.encode16(case: :lower)
  end

  @doc """
  Handles the initial redirect to the github authentication page.

  To customize the scope (permissions) that are requested by github include them as part of your url:

      "/auth/github?scope=user,public_repo,gist"

  You can also include a `state` param that github will return to you.
  """
  def handle_request!(conn) do
    conn = conn |> Plug.Conn.fetch_session()
    module = option(conn, :oauth2_module)
    scopes = conn.params["scope"] || option(conn, :default_scope)
    send_redirect_uri = Keyword.get(options(conn), :send_redirect_uri, true)
    config = conn.private[:ueberauth_request_options] |> Map.get(:options, [])
    redirect_uri = config[:redirect_uri] || callback_url(conn)
    state = secure_random_hex()

    params =
      if send_redirect_uri do
        [redirect_uri: redirect_uri, scope: scopes, state: state]
      else
        [scope: scopes, state: state]
      end

    conn
    |> Plug.Conn.put_session(:ueberauth_state, state)
    |> redirect!(apply(module, :authorize_url!, [params, [config: config]]))
  end

  @doc """
  Handles the callback from Github. When there is a failure from Github the failure is included in the
  `ueberauth_failure` struct. Otherwise the information returned from Github is returned in the `Ueberauth.Auth` struct.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code, "state" => state}} = conn) do
    conn = conn |> Plug.Conn.fetch_session()
    module = option(conn, :oauth2_module)

    client_options =
      conn.private
      |> Map.get(:ueberauth_request_options, %{})
      |> Map.get(:options, [])

    options = [client_options: [config: client_options]]
    token = apply(module, :get_token!, [[code: code], [options: options]])
    session_state = conn |> Plug.Conn.get_session(:ueberauth_state)

    conn = conn |> Plug.Conn.delete_session(:ueberauth_state)

    cond do
      state != session_state ->
        set_errors!(conn, [
          error("StateMistake", "state mistake")
        ])

      token.access_token |> to_string |> String.length() == 0 ->
        set_errors!(conn, [
          error(token.other_params["error"], token.other_params["error_description"])
        ])

      true ->
        fetch_user(conn, token)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw Github response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:github_user, nil)
    |> put_private(:github_token, nil)
  end

  @doc """
  Fetches the uid field from the Github response. This defaults to the option `uid_field` which in-turn defaults to `id`
  """
  def uid(conn) do
    conn |> option(:uid_field) |> to_string() |> fetch_uid(conn)
  end

  defp fetch_uid(field, conn) do
    conn.private.github_user[field]
  end

  @doc """
  Includes the credentials from the Github response.
  """
  def credentials(conn) do
    token = conn.private.github_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",", trim: true)

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes
    }
  end

  def present?(str), do: str |> to_string() |> String.length() > 0

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.github_user

    %Info{
      name: user["name"],
      description: user["bio"],
      nickname: user["login"],
      location: user["location"],
      image: user["avatar_url"],
      urls: %{
        followers_url: user["followers_url"],
        avatar_url: user["avatar_url"],
        events_url: user["events_url"],
        starred_url: user["starred_url"],
        blog: user["blog"],
        subscriptions_url: user["subscriptions_url"],
        organizations_url: user["organizations_url"],
        gists_url: user["gists_url"],
        following_url: user["following_url"],
        api_url: user["url"],
        html_url: user["html_url"],
        received_events_url: user["received_events_url"],
        repos_url: user["repos_url"]
      }
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the Github callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.github_token,
        user: conn.private.github_user
      }
    }
  end

  def fetch_user(conn, token) do
    conn = put_private(conn, :github_token, token)
    config = conn.private[:ueberauth_request_options] |> Map.get(:options, [])

    # Will be better with Elixir 1.3 with/else
    token
    |> Ueberauth.Strategy.Github.OAuth.get(
      "/user?access_token=#{token.access_token}",
      [],
      config: config
    )
    |> case do
      {_, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: user}}
      when status_code in 200..399 ->
        put_private(conn, :github_user, user)

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn) || [], key, Keyword.get(default_options(), key))
  end
end
