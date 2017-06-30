require 'json/jwt'
require 'delegate'

module Kubeclient
  OidcException = Class.new(StandardError)

  class OidcDiscovery
    attr_reader :idp

    DISCOVERY_PATH = '.well-known/openid-configuration'.freeze

    FIELD_MAP = {
      token_endpoint: 'token_endpoint',
      jwks_endpoint: 'jwks_uri'
    }

    class << self
      def fields
        FIELD_MAP.keys
      end
    end

    FIELD_MAP.each do |method, field|
      define_method method do
        validate_and_retrieve_field(field)
      end
    end

    def initialize(idp)
      @idp = idp
    end

    private

    def discovered
      @discovered ||= JSON.parse(RestClient.get(discovery_url))
    end

    def discovery_url
      "#{idp.chomp('/')}/#{DISCOVERY_PATH}"
    end

    def validate_and_retrieve_field(field)
      discovered.key?(field) && discovered[field] or raise OidcException,
        "OIDC discovery URL #{discovery_url} did not return a JSON document containing a '#{field}' field"
    end
  end

  class OidcToken
    attr_reader :client_id, :refresh_token, :client_secret, :idp_issuer_url, :oidc_discovery
    delegate *OidcDiscovery.fields, to: :oidc_discovery

    REFRESH_WITHIN = 300
    ID_TOKEN = 'id_token'.freeze
    TOKEN_EXPIRY = 'exp'.freeze
    REFRESH_GRANT_TYPE = 'refresh_token'.freeze

    def initialize(client_id:, client_secret:, idp_issuer_url:, id_token:, refresh_token:)
      @client_id = client_id
      @client_secret = client_secret
      @idp_issuer_url = idp_issuer_url
      @id_token = id_token
      @refresh_token = refresh_token
      @oidc_discovery = OidcDiscovery.new(idp_issuer_url)

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
        grant_type: REFRESH_GRANT_TYPE
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
  end
end
