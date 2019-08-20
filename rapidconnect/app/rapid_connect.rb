# frozen_string_literal: true

require 'sinatra'
require 'sinatra/reloader' if development?
require 'sinatra/config_file'
require 'erubis'
require 'json'
require 'json/jwt'
require 'securerandom'
require 'rack-flash'
require 'redis-rack'
require 'mail'
require 'rdiscount'
require 'json'
require 'uri'

require_relative 'rcmcsession'
require_relative 'models/rapid_connect_service'
require_relative 'models/claims_set'
require_relative 'models/attributes_claim'

# The RapidConnect application
class RapidConnect < Sinatra::Base
  configure :production, :development do
    # :nocov: Doesn't run in test environment
    use RapidConnectMemcacheSession, memcache_session_expiry: 3600, secure: Sinatra::Base.production?
    # :nocov:
  end

  configure :test do
    use Rack::Session::Pool, expire_in: 3600
  end

  use Rack::UTF8Sanitizer
  use Rack::MethodOverride
  use Rack::Flash, sweep: true

  configure :development do
    # :nocov: Doesn't run in test environment
    register Sinatra::Reloader
    # :nocov:
  end

  configure :production, :development do
    # :nocov: Doesn't run in test environment
    enable :logging
    register Sinatra::ConfigFile

    set :app_root, File.expand_path(File.join(File.dirname(__FILE__), '..'))
    config_file File.join(settings.app_root, 'config', 'app_config.yml')
    set :app_logfile, File.join(settings.app_root, 'logs', 'app.log')
    set :audit_logfile, File.join(settings.app_root, 'logs', 'audit.log')

    set :erb, escape_html: true

    mail_settings = settings.mail
    Mail.defaults do
      delivery_method :smtp,
                      address: 'localhost',
                      port: '25',
                      user_name: mail_settings[:user_name],
                      password: mail_settings[:password],
                      authentication: :plain,
                      enable_starttls_auto: true
    end

    unless settings.respond_to? :hostname
      set :hostname, ::URI.parse(settings.issuer).hostname
    end
    # :nocov:
  end

  attr_reader :current_version
  AUTHORIZE_REGEX = /^AAF-RAPID-EXPORT service="([^"]+)", key="([^"]*)?"$/

  def initialize
    super
    check_reopen

    @current_version = '1.9.1-tuakiri5'
  end

  def check_reopen
    return if @pid == Process.pid

    @redis = Redis.new

    @app_logger = Logger.new(settings.app_logfile)
    @app_logger.level = Logger::INFO
    @app_logger.formatter = Logger::Formatter.new

    @audit_logger = Logger.new(settings.audit_logfile)
    @audit_logger.level = Logger::INFO

    @pid = Process.pid
  end

  def call(env)
    check_reopen
    super(env)
  end

  ##
  # Marketing Site
  ##
  get '/' do
    erb :welcome, layout: nil
  end

  ## Status for load balancer
  get '/status' do
    if settings.status_disabled_file && File.exists?(settings.status_disabled_file)
        404
    end
    ## else return a blank 200 page
  end

  before %r{\A/(login|jwt)/.+}, mustermann_opts: { check_anchors: false } do
    cache_control :no_cache
  end

  ###
  # Session Management
  ###
  get '/login/:id' do |id|
    shibboleth_login_url = "/Shibboleth.sso/Login?target=/login/shibboleth/#{id}"
    if params[:entityID]
      shibboleth_login_url = "#{shibboleth_login_url}&entityID=#{params[:entityID]}"
    end
    redirect shibboleth_login_url
  end

  get '/login/shibboleth/:id' do |id|
    # Process Shibboleth provided login details
    if env['HTTP_SHIB_SESSION_ID'] && !env['HTTP_SHIB_SESSION_ID'].empty?
      targets = session[:target] || {}
      target = targets[id.to_s]
      if target
        session[:target].delete id.to_s

        # As we support more attributes in the future the subject should be extended to hold all of them
        subject = {
          principal: env['HTTP_PERSISTENT_ID'],
          cn: env['HTTP_CN'],
          display_name: env['HTTP_DISPLAYNAME'],
          given_name: env['HTTP_GIVENNAME'],
          surname: env['HTTP_SN'],
          mail: env['HTTP_MAIL'],
          principal_name: env['HTTP_EPPN'],
          scoped_affiliation: env['HTTP_AFFILIATION'],
          o: env['HTTP_O'],
          orcid: env['HTTP_EDUPERSONORCID'],
          shared_token: env['HTTP_AUEDUPERSONSHAREDTOKEN']
        }

        session[:subject] = subject
        if valid_subject?(subject)
          @app_logger.info "Established session for #{subject[:cn]}(#{subject[:principal]})"
          redirect target
        else
          session.clear
          session[:invalid_target] = target
          session[:invalid_subject] = subject
          redirect '/invalidsession'
        end
      else
        session.clear
        redirect '/serviceunknown'
      end
    else
      403
    end
  end

  get '/logout' do
    if session[:subject]
      @app_logger.info "Terminated session for #{session[:subject][:cn]}(#{session[:subject][:principal]})"
    end
    session.clear
    if params[:return] 
        target = params[:return]
    else
        target = '/'
    end
    redirect target
  end

  get '/serviceunknown' do
    erb :serviceunknown
  end

  get '/invalidsession' do
    erb :invalidsession
  end

  def valid_subject?(subject)
    subject[:principal].present? &&
      subject[:cn].present? &&
      subject[:mail].present? &&
      subject[:display_name].present?
  end

  ###
  # Service Registration
  ###
  before '/registration*' do
    authenticated?
  end

  get '/registration' do
    @organisations = load_organisations
    erb :'registration/index'
  end

  def load_service(identifier)
    json = @redis.hget('serviceproviders', identifier)
    return nil if json.nil?

    RapidConnectService.new.from_json(json).tap do |service|
      service.identifier = identifier
    end
  end

  def load_all_services
    @redis.hgetall('serviceproviders').sort.reduce({}) do |hash, (id, json)|
      service = RapidConnectService.new.from_json(json).tap do |s|
        s.identifier = id
      end
      hash.merge(id => service)
    end
  end

  def service_attrs
    %i[organisation name audience endpoint secret].reduce({}) do |map, sym|
      param = if RapidConnectService::URI_FIELDS.include?(sym)
                params[sym].strip
              else
                params[sym]
              end

      map.merge(sym => param)
    end
  end

  def registrant_attrs
    subject = session[:subject]
    { registrant_name: subject[:cn], registrant_mail: subject[:mail] }
  end

  def admin_supplied_attrs
    base = { enabled: !params[:enabled].nil? }

    %i[type registrant_name registrant_mail].reduce(base) do |map, sym|
      map.merge(sym => params[sym])
    end
  end

  post '/registration/save' do
    service = RapidConnectService.new
    service.attributes = service_attrs.merge(registrant_attrs)

    if service.valid?
      identifier = service.identifier!
      if @redis.hexists('serviceproviders', identifier)
        @organisations = load_organisations
        flash[:error] = 'Invalid identifier generated. Please re-submit registration.'
        erb :'registration/index'
      else
        service.enabled = settings.auto_approve_in_test && (settings.federation == 'test')
        service.created_at = Time.now.utc.to_i
        @redis.hset('serviceproviders', identifier, service.to_json)

        send_registration_email(service)
        if service.enabled
          session[:registration_identifier] = identifier
        end

        @app_logger.info "New service #{service}, endpoint: #{service.endpoint}, contact email: #{service.registrant_mail}, organisation: #{service.organisation}"
        redirect to('/registration/complete')
      end
    else
      @organisations = load_organisations
      flash[:error] = "Invalid data supplied: #{service.errors.full_messages.join(', ')}"
      erb :'registration/index'
    end
  end

  get '/registration/complete' do
    @identifier = nil
    @approved = settings.auto_approve_in_test && settings.federation == 'test'
    if @approved
      @identifier = session[:registration_identifier]
    end
    erb :'registration/complete'
  end

  ###
  # Administration
  ###
  before '/administration*' do
    authenticated?
    administrator?
  end

  get '/administration' do
    erb :'administration/index'
  end

  # Administration - Services
  get '/administration/services' do
    @services = load_all_services
    erb :'administration/services/list'
  end

  get '/administration/services/:identifier' do |identifier|
    @identifier = identifier
    @service = load_service(identifier)
    halt 404 if @service.nil?

    erb :'administration/services/show'
  end

  get '/administration/services/edit/:identifier' do |identifier|
    @identifier = identifier
    @service = load_service(identifier)
    halt 404 if @service.nil?

    @organisations = load_organisations
    erb :'administration/services/edit'
  end

  put '/administration/services/update' do
    identifier = params[:identifier]
    service = load_service(identifier)

    if service.nil?
      flash[:error] = 'Invalid data supplied'
      halt redirect to('/administration/services')
    end

    service.attributes = service_attrs.merge(admin_supplied_attrs)

    if service.valid?
      @redis.hset('serviceproviders', identifier, service.to_json)
      @app_logger.info "Service #{identifier} updated by #{session[:subject][:principal]} #{session[:subject][:cn]}"
      redirect to('/administration/services/' + identifier)
    else
      flash[:error] = 'Invalid data supplied'
      redirect to('/administration/services')
    end
  end

  patch '/administration/services/toggle/:identifier' do |identifier|
    service = load_service(identifier)
    halt 404 if service.nil?

    service.enabled = !service.enabled

    @redis.hset('serviceproviders', identifier, service.to_json)
    @app_logger.info "Service #{identifier} toggled by #{session[:subject][:principal]} #{session[:subject][:cn]}"

    flash[:success] = 'Service modified successfully'
    redirect to('/administration/services/' + identifier)
  end

  delete '/administration/services/delete/:identifier' do |identifier|
    service = load_service(identifier)
    halt 404 if service.nil?

    @redis.hdel('serviceproviders', identifier)
    @app_logger.info "Service #{identifier} deleted by #{session[:subject][:principal]} #{session[:subject][:cn]}"
    flash[:success] = 'Service deleted successfully'
    redirect '/administration/services'
  end

  # Administration - Administrators
  get '/administration/administrators' do
    administrators_raw = @redis.hgetall('administrators')
    @administrators = administrators_raw.reduce({}) { |map, (k, v)| map.merge(k => JSON.parse(v)) }
    erb :'administration/administrators/list'
  end

  get '/administration/administrators/create' do
    erb :'administration/administrators/create'
  end

  post '/administration/administrators/save' do
    identifier = params[:identifier]
    if identifier.nil? || identifier.empty?
      flash[:error] = 'Invalid form data'
      erb :'administration/administrators/create'
    elsif @redis.hexists('administrators', identifier)
      flash[:error] = 'Administrator already exists'
      redirect '/administration/administrators'
    else
      name = params[:name]
      mail = params[:mail]

      if name && !name.empty? && mail && !mail.empty?
        @redis.hset('administrators', identifier, { 'name' => name, 'mail' => mail }.to_json)
        @app_logger.info "current administrator #{session[:subject][:principal]} #{session[:subject][:cn]} added new administrator #{name}, #{mail}"
        flash[:success] = 'Administrator added'
        redirect '/administration/administrators'
      else
        flash[:error] = 'Invalid form data'
        erb :'administration/administrators/create'
      end
    end
  end

  delete '/administration/administrators/delete' do
    identifier = params[:identifier]
    if identifier.nil? || identifier.empty?
      flash[:error] = 'Invalid form data'
    elsif identifier == session[:subject][:principal]
      flash[:error] = 'Removing your own access is not supported'
    elsif @redis.hexists('administrators', identifier)
      @redis.hdel('administrators', identifier)
      @app_logger.info "Current administrator #{session[:subject][:principal]} #{session[:subject][:cn]} deleted administrator #{identifier}"
      flash[:success] = 'Administrator deleted successfully'
    else
      flash[:error] = 'No such administrator'
    end
    redirect '/administration/administrators'
  end

  ###
  # JWT
  ###
  before '/jwt/*' do
    authenticated?
  end

  def binding(*parts)
    ['urn:mace:aaf.edu.au:rapid.aaf.edu.au', *parts].join(':')
  end

  # To enable raptor and other tools to report on rapid like we would any other
  # IdP we create a shibboleth styled audit.log file for each service access.
  # Fields are on a single line, separated by pipes:
  #
  # auditEventTime|requestBinding|requestId|relyingPartyId|messageProfileId|
  # assertingPartyId|responseBinding|responseId|principalName|authNMethod|
  # releasedAttributeId1,releasedAttributeId2,|nameIdentifier|
  # assertion1ID,assertion2ID,|
  def audit_log(service, subject, claims, attrs)
    fields = [
      Time.now.utc.strftime('%Y%m%dT%H%M%SZ'), binding(service.type, 'get'),
      service.identifier, claims[:aud], binding('jwt', service.type, 'sso'),
      claims[:iss], binding('jwt', service.type, 'post'), claims[:jti],
      subject[:principal], 'urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig',
      attrs.sort.join(','), '', '', ''
    ]

    @audit_logger.info(fields.join('|'))
  end

  before '/jwt/authnrequest/:type/:identifier' do |type, identifier|
    @service = load_service(identifier)
    if @service.nil? || @service.type != type
      halt 404, 'There is no such endpoint defined please validate the request.'
    end

    unless @service.enabled
      halt 403, "The service \"#{@service.name}\" is unable to process requests at this time."
    end

    iss = settings.issuer
    aud = @service.audience

    claim = AttributesClaim.new(iss, aud, session[:subject])
    @app_logger.info("Retargeted principal #{session[:subject][:principal]} " \
                     "for #{aud} as #{claim.attributes[:edupersontargetedid]}")
    @claims_set = ClaimsSet.send(type, iss, aud, claim)
    @jws = @claims_set.to_jws(@service.secret)

    @endpoint = @service.endpoint

    @app_logger.info "Provided details for #{session[:subject][:cn]}(#{session[:subject][:mail]}) to service #{@service.name} (#{@service.endpoint})"
    @app_logger.debug @claims_set.claims
  end

  get '/jwt/authnrequest/research/:identifier' do
    attrs = @claims_set.claims[:'https://aaf.edu.au/attributes']
    audit_log(@service, session['subject'], @claims_set.claims, attrs.keys)

    erb :post, layout: :post
  end

  get '/jwt/authnrequest/auresearch/:identifier' do
    attrs = @claims_set.claims[:'https://aaf.edu.au/attributes']
    audit_log(@service, session['subject'], @claims_set.claims, attrs.keys)

    erb :post, layout: :post
  end

  get '/jwt/authnrequest/zendesk/:identifier' do
    attrs = %w[cn mail edupersontargetedid o]
    audit_log(@service, session['subject'], @claims_set.claims, attrs)

    redirect "#{@endpoint}?jwt=#{@jws}&return_to=#{params[:return_to]}"
  end

  get '/jwt/authnrequest/freshdesk/:identifier' do
    attrs = %w[cn mail o]
    audit_log(@service, session['subject'], @claims_set.claims, attrs)

    redirect freshdesk_redirect(@claims_set.claims)
  end

  def freshdesk_redirect(claims)
    name = claims[:name]
    email = claims[:email]
    company = claims[:o]
    timestamp = Time.now.utc.to_i.to_s
    secret = @service.secret
    digest = OpenSSL::Digest::MD5.new
    message = name + secret + email + timestamp
    hash = OpenSSL::HMAC.hexdigest(digest, secret, message)

    "#{@endpoint}?name=#{name}&email=#{email}&company=#{company}" \
    "&timestamp=#{timestamp}&hash=#{hash}"
  end

  get '/developers' do
    erb :developers, locals: { text: markdown(:'documentation/developers') }
  end

  def flash_types
    %i[success warning error]
  end

  def authenticated?
    return if session[:subject]

    id = SecureRandom.urlsafe_base64(24, false)
    session[:target] ||= {}
    session[:target][id] = request.url

    login_url = "/login/#{id}"
    if params[:entityID]
      login_url = "#{login_url}?entityID=#{params[:entityID]}"
    end
    redirect login_url
  end

  def administrator?
    return if @redis.hexists('administrators', session[:subject][:principal])

    @app_logger.warn "Denied access to administrative area to #{session[:subject][:principal]} #{session[:subject][:cn]}"
    status 403
    halt erb :'administration/administrators/denied'
  end

  ##
  # New Service Registration Notification
  ##
  def send_registration_email(service)
    mail_settings = settings.mail
    settings_hostname = settings.hostname
    service_url_research = "https://#{settings.hostname}/jwt/authnrequest/research/#{service.identifier}"
    if service.enabled
         admin_action = "There is a new registration within Tuakiri Rapid Connect that has been automatically approved - but we are letting you know anyway."
    else
         admin_action = "There is a new registration within Tuakiri Rapid Connect that needs to be enabled."
    end
    Mail.deliver do
      from mail_settings[:from]
      to mail_settings[:to]
      subject 'New service registration for Tuakiri Rapid Connect'
      html_part do
        content_type 'text/html; charset=UTF-8'
        body "
          #{admin_action}
          <br><br>
          <strong>Details</strong>
          <br>
          <ul>
            <li>Service Name: #{service.name}</li>
            <li>Endpoint: #{service.endpoint}</li>
            <li>Creator: #{service.registrant_name} (#{service.registrant_mail})</li>
          </ul>
          <br><br>
          Please ensure <strong>all endpoints utilise HTTPS</strong> before enabling.
          <br><br>
          For more information and to enable this service please view the <a href='https://#{settings_hostname}/administration/services/#{service.identifier}'>full service record</a> in Tuakiri Rapid Connect.
          <br><br>
          After reviewing and approving the service, please notify the user.  We suggest the following template:
          <br><hr><br>
          To: \"#{service.registrant_name}\" &lt;#{service.registrant_mail}&gt;<br>
          Subject: service registration on #{settings_hostname}<br>
          <br>
          Dear #{service.registrant_name}<br>
          <br>
          Your service #{service.name} has been accepted into the Tuakiri Rapid Connect at #{settings_hostname}<br>
          <br>
          You can now configure your service to use this login URL :<br>
          <a href=\"#{service_url_research}\">#{service_url_research}</a><br>
          <br>
          Or, if your service needs custom JWT structure (Freshdesk, Zendesk),<br>
          or the service needs additional Research and Education attributes (auEduPersonSharedToken),<br>
          please contact Tuakiri support at tuakiri@reannz.co.nz - and after your<br>
          service registration is adjusted, you will be provided with a different URL to use.<br>
          <br>
          Please contact Tuakiri support at tuakiri@reannz.co.nz if you have any questions or need any assistance with connecting your service to Tuakiri RapidConnect.
        "
      end
    end
  end

  ##
  # Export Data
  ##
  before '/export*' do
    api_authenticated?
  end

  get '/export/service/:identifier' do |identifier|
    content_type :json

    service = load_service(identifier)
    halt 404 if service.nil?

    { service: service_as_json(identifier, service) }.to_json
  end

  get '/export/services' do
    content_type :json

    services = load_all_services.sort.map do |(id, service)|
      service_as_json(id, service)
    end

    { services: services }.to_json
  end

  get '/export/basic' do
    content_type :json

    services = load_all_services.map do |(id, service)|
      service_as_json(id, service).tap do |s|
        s[:rapidconnect].delete(:secret)
      end
    end

    { services: services }.to_json
  end

  def service_as_json(id, service)
    { id: id,
      name: service.name,
      created_at: Time.at(service.created_at).utc.xmlschema,
      contact: {
        name: service.registrant_name,
        email: service.registrant_mail,
        type: 'technical'
      },
      rapidconnect: {
        audience: service.audience,
        callback: service.endpoint,
        secret: service.secret,
        endpoints: {
          scholarly: "https://#{settings.hostname}/jwt/authnrequest/research/#{id}"
        }
      },
      enabled: service.enabled,
      organization: service.organisation }
  end

  def api_authenticated?
    if settings.export[:enabled]
      authorization = request.env['HTTP_AUTHORIZATION']
      unless authorization && authorization =~ AUTHORIZE_REGEX
        halt 403, 'Invalid authorization token'
      end

      service, secret = authorization.match(AUTHORIZE_REGEX).captures
      unless secret == settings.export[:secret]
        halt 403, 'Invalid authorization header'
      end

      @app_logger.info "Established API session for service #{service}"
    else
      halt 404
    end
  end

  ##
  # Organisation names via FR
  ##
  def load_organisations
    JSON.parse(IO.read(settings.organisations)).sort_by(&:downcase)
  end
end
