require 'test_helper'

class OidcTokenTest < MiniTest::Test
  def build_jwt_jwk_pair(payload, private_key)
    jwk = private_key.to_jwk
    id_token = JSON::JWT.new(payload)
    id_token.kid = jwk.thumbprint
    id_token = id_token.sign(private_key, :RS256)
    Struct.new(:id_token, :jwk).new(id_token.to_s, jwk)
  end

  def stub_provider(idp:, jwk_response:)
    discovery_endpoint = "#{idp}/.well-known/openid-configuration"
    token_endpoint = "#{idp}/token"
    jwks_endpoint = "#{idp}/certs"
    discovery_response_body = { issuer: idp, token_endpoint: token_endpoint, jwks_uri: jwks_endpoint }.to_json

    stub_request(:get, discovery_endpoint).to_return(body: discovery_response_body, status: 200)
    stub_request(:get, jwks_endpoint).to_return(body: jwk_response.to_json, status: 200)
  end

  def test_unexpired_token_fails_verify
    idp = 'https://domain.tld'
    payload = { exp: Time.now.to_i + 3600 }
    private_key = OpenSSL::PKey::RSA.new(2048)
    jwt = build_jwt_jwk_pair(payload, private_key)

    client_id = 'client-id'
    client_secret = 'client-secret'
    refresh_token = 'refresh-token'

    stub_provider(idp: idp, jwk_response: { keys: [] })

    assert_raises JSON::JWK::Set::KidNotFound do
      Kubeclient::OidcToken.new(
        client_id: client_id,
        client_secret: client_secret,
        idp_issuer_url: idp,
        id_token: jwt.id_token,
        refresh_token: refresh_token
      )
    end
  end

  def test_token_needs_refresh
    payload = { exp: Time.now.to_i - 3600 }
    private_key = OpenSSL::PKey::RSA.new(2048)
    jwt = build_jwt_jwk_pair(payload, private_key)
    id_token = jwt.id_token

    client_id = 'client-id'
    client_secret = 'client-secret'
    refresh_token = 'refresh-token'

    idp = 'https://domain.tld'
    discovery_endpoint = "#{idp}/.well-known/openid-configuration"
    token_endpoint = "#{idp}/token"
    jwks_endpoint = "#{idp}/certs"

    discovery_response_body = { issuer: idp, token_endpoint: token_endpoint, jwks_uri: jwks_endpoint }.to_json
    refreshed_payload = { exp: Time.now.to_i + 3600 }
    refreshed_token_value = build_jwt_jwk_pair(refreshed_payload, private_key).id_token
    refresh_response_body = { token_type: 'Bearer', expires_in: 3600, id_token: refreshed_token_value }.to_json

    stub_request(:get, discovery_endpoint).to_return(body: discovery_response_body, status: 200)
    stub_request(:get, jwks_endpoint).to_return(body: { keys: [jwt.jwk] }.to_json, status: 200)
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
    assert_requested(:get, jwks_endpoint, times: 2)
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
    private_key = OpenSSL::PKey::RSA.new(2048)
    jwt = build_jwt_jwk_pair(payload, private_key)

    idp = 'https://domain.tld'
    token_endpoint = "#{idp}/token"
    client_id = 'client-id'
    client_secret = 'client-secret'
    refresh_token = 'refresh-token'

    stub_provider(idp: idp, jwk_response: { keys: [jwt.jwk] })

    oidc_token = Kubeclient::OidcToken.new(
      client_id: client_id,
      client_secret: client_secret,
      idp_issuer_url: idp,
      id_token: jwt.id_token,
      refresh_token: refresh_token
    )

    assert_equal(jwt.id_token, oidc_token.id_token)
    assert_not_requested(:post, token_endpoint)
  end
end
