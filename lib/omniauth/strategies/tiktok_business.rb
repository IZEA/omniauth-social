# frozen_string_literal: true

require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class TiktokBusiness < OmniAuth::Strategies::OAuth2
      class NoAuthorizationCodeError < StandardError; end
      DEFAULT_SCOPE = 'video.list,video.insights,user.info.basic,biz.creator.info,biz.creator.insights,tcm.order.update,user.info.username,user.info.stats,user.account.type,user.insights,comment.list'
      USER_INFO_URL = 'https://business-api.tiktok.com/open_api/v1.3/business/get/'
      DEFAULT_TOKEN_FIELDS = ['username', 'display_name', 'profile_image', 'audience_countries', 'audience_genders', 'likes', 'comments', 'shares', 'followers_count', 'profile_views', 'video_views', 'is_business_account', 'audience_activity']

      option :name, 'tiktok_business'
      option :client_options, {
        site: 'https://business-api.tiktok.com',
        authorize_url: 'https://www.tiktok.com/v2/auth/authorize',
        token_url: 'https://business-api.tiktok.com/open_api/v1.3/tt_user/oauth2/token/',
        stratergy_name: 'tiktok_business',
        extract_access_token: proc do |client, hash|
          hash = hash['data']
          token = hash.delete('access_token') || hash.delete(:access_token)
          token && ::OAuth2::AccessToken.new(client, token, hash)
        end
      }

      option :authorize_options, %i[scope display auth_type]

      uid { access_token.params['open_id'] }

      info do
        prune!('nickname' => raw_info['data']['display_name'])
      end

      extra do
        hash = {}
        hash['raw_info'] = raw_info unless skip_info?
        prune! hash
      end

      credentials do
        hash = {}
        hash['token'] = access_token.token
        hash['refresh_token'] = access_token.refresh_token if access_token.expires? && access_token.refresh_token
        hash['expires_at'] = access_token.expires_at if access_token.expires?
        hash['expires'] = access_token.expires?
        refresh_token_expires_at = Time.now.to_i + access_token.params['refresh_expires_in'].to_i
        hash['refresh_token_expires_at'] = refresh_token_expires_at
        hash
      end

      def raw_info
        opts = { headers: { 'Access-Token': access_token.token },
                params: { business_id: access_token.params["open_id"],
                          fields: DEFAULT_TOKEN_FIELDS } }
        @raw_info ||= access_token
                      .get("#{USER_INFO_URL}", opts)
                      .parsed || {}
      end

      def callback_url
        options[:callback_url] || (full_host + script_name + callback_path)
      end

      def authorize_params
        super.tap do |params|
          params[:scope] ||= DEFAULT_SCOPE
          params[:response_type] = 'code'
          params.delete(:client_id)
          params[:client_key] = options.client_id
        end
      end

      def token_params
        super.tap do |params|
          params[:client_id] = options.client_id
          params[:client_secret] = options.client_secret
        end
      end

      private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end
    end
  end
end
