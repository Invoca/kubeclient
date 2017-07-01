require 'test_helper'

class OidcTokenTest < MiniTest::Test
  def build_jwt(payload)
    header = { alg: 'none' }.to_json
    signature = "\x00" * 256
    [header, payload.to_json, signature].map { |e| Base64.urlsafe_encode64(e) }.join('.')
  end

  def stub_provider(idp:)
    discovery_endpoint = "#{idp}/.well-known/openid-configuration"
    token_endpoint = "#{idp}/token"
    discovery_response_body = { issuer: idp, token_endpoint: token_endpoint }.to_json

    stub_request(:get, discovery_endpoint).to_return(body: discovery_response_body, status: 200)
  end

  def test_token_needs_refresh
    payload = { exp: Time.now.to_i - 3600 }
    id_token = build_jwt(payload)

    client_id = 'client-id'
    client_secret = 'client-secret'
    refresh_token = 'refresh-token'

    idp = 'https://domain.tld'
    discovery_endpoint = "#{idp}/.well-known/openid-configuration"
    token_endpoint = "#{idp}/token"

    discovery_response_body = { issuer: idp, token_endpoint: token_endpoint }.to_json
    refreshed_payload = { exp: Time.now.to_i + 3600 }
    refreshed_token_value = build_jwt(refreshed_payload)
    refresh_response_body = { token_type: 'Bearer', expires_in: 3600, id_token: refreshed_token_value }.to_json

    stub_request(:get, discovery_endpoint).to_return(body: discovery_response_body, status: 200)
    stub_request(:post, token_endpoint).to_return(body: refresh_response_body, status: 200)

    oidc_token = Kubeclient::OidcToken.new(
      client_id: client_id,
      client_secret: client_secret,
      idp_issuer_url: idp,
      id_token: id_token,
      refresh_token: refresh_token
    )

    assert_equal(refreshed_token_value, oidc_token.id_token)
    assert_requested(:get, discovery_endpoint, times: 1)
    assert_requested(:post, token_endpoint, times: 1,
      body: {
        client_id: client_id,
        client_secret: client_secret,
        refresh_token: refresh_token,
        grant_type: 'refresh_token'
      }
    )
  end

  def test_token_no_refresh_needed
    payload = { exp: Time.now.to_i + 3600 }
    jwt = build_jwt(payload)

    idp = 'https://domain.tld'
    token_endpoint = "#{idp}/token"
    client_id = 'client-id'
    client_secret = 'client-secret'
    refresh_token = 'refresh-token'

    stub_provider(idp: idp)

    oidc_token = Kubeclient::OidcToken.new(
      client_id: client_id,
      client_secret: client_secret,
      idp_issuer_url: idp,
      id_token: jwt,
      refresh_token: refresh_token
    )

    assert_equal(jwt, oidc_token.id_token)
    assert_not_requested(:post, token_endpoint)
  end
end
