# frozen_string_literal: true

require 'rack/session/dalli'

class RapidConnectMemcacheSession < Rack::Session::Dalli
  attr_reader :memcache_session_expiry

  DEFAULT_OPTIONS = Rack::Session::Dalli::DEFAULT_OPTIONS.merge \
    memcache_session_expiry: nil

  def initialize(app, options = {})
    super

    @memcache_session_expiry = @default_options[:memcache_session_expiry]
  end

  def set_session(env, session_id, new_session, options)
    expire_after_old = options[:expire_after]
    options[:expire_after] = @memcache_session_expiry
    result = super
    options[:expire_after] = expire_after_old
    result
  end
end
