
require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Pinterest < OmniAuth::Strategies::OAuth2
      option :client_options, {
        :site => 'https://api.pinterest.com/',
        :authorize_url => 'https://www.pinterest.com/oauth/',
        :token_url => 'https://api.pinterest.com/v5/oauth/token',
        :redirect_uri_remove_query => true,
        :token_method => :post, # important
        :auth_scheme => :basic_auth # important
      }

      def request_phase
        options[:scope] ||= 'scope=boards:read,pins:read,user_accounts:read'
        options[:response_type] ||= 'code'
        super
      end

      uid { raw_info['uid'] }

      info { raw_info }

      def authorize_params
        super.tap do |params|
          %w[redirect_uri].each do |v|
            params[:redirect_uri] = request.params[v] if request.params[v]
          end
        end
      end

      def raw_info
        response = access_token.get("/v5/user_account")
        @raw_info ||= JSON.parse(response.body)
      end

      def ssl?
        true
      end
    end
  end
end
