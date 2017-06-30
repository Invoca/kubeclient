require 'json/jwt'

module Kubeclient
  OidcException = Class.new(StandardError)

  class OidcToken
    attr_reader :client_id, :refresh_token, :client_secret, :idp

    DISCOVERY_PATH = '.well-known/openid-configuration'.freeze
    JWKS_FIELD = 'jwks_uri'.freeze
    TOKEN_ENDPOINT_FIELD = 'token_endpoint'.freeze

    REFRESH_WITHIN = 300
    ID_TOKEN = 'id_token'.freeze
    TOKEN_EXPIRY = 'exp'.freeze
    GRANT_TYPE = 'refresh_token'.freeze

    def initialize(client_id:, client_secret:, idp:, id_token:, refresh_token:)
      @client_id = client_id
      @client_secret = client_secret
      @idp = idp
      @id_token = id_token
      @refresh_token = refresh_token

      decode_token_payload(ignore_kid_not_found: true)
    end

    def id_token
      refresh if refresh?
      @id_token
    end

    private

    def refresh?
      @token_payload[TOKEN_EXPIRY] - REFRESH_WITHIN < Time.now.to_i
    end

    def refresh
      response = RestClient.post(token_endpoint, refresh_payload)
      @id_token = JSON.parse(response)[ID_TOKEN]
      decode_token_payload
    end

    def refresh_payload
      {
        client_id: client_id,
        client_secret: client_secret,
        refresh_token: refresh_token,
        grant_type: GRANT_TYPE
      }
    end

    # If the token has been expired for some time, the JWK signing key may have been rotated out
    # Ignore KidNotFound errors IIF the token is expired and ignore_kid_not_found == true
    def decode_token_payload(ignore_kid_not_found: false)
      @token_payload = JSON::JWT.decode(@id_token, jwks)
    rescue JSON::JWK::Set::KidNotFound => e
      if ignore_kid_not_found
        @token_payload = JSON::JWT.decode(@id_token, :skip_verification)
        raise e unless refresh?
      else
        raise e
      end
    end

    def jwks
      JSON::JWK::Set.new(JSON.parse(RestClient.get(jwks_endpoint)))
    end

    def token_endpoint
      @token_endpoint ||= oidc_discovery_field(TOKEN_ENDPOINT_FIELD)
    end

    def jwks_endpoint
      @jwks_endpoint ||= oidc_discovery_field(JWKS_FIELD)
    end

    def oidc_discovery
      @oidc_discovery ||= JSON.parse(RestClient.get(oidc_discovery_url))
    end

    def oidc_discovery_field(field)
      oidc_discovery.key?(field) && oidc_discovery[field] or raise OidcException,
        "OIDC discovery URL #{oidc_discovery_url} did not return a JSON document containing a '#{field}' field"
    end

    def oidc_discovery_url
      @idp_discovery_url ||= "#{idp.chomp('/')}/#{DISCOVERY_PATH}"
    end
  end
end
